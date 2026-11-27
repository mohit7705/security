from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

from security_analyzer.authentication.session_storage_bridge import SessionStorageBridge
from security_analyzer.browser.browser_manager import (
    ScopedBrowserManager,
    is_playwright_installed,
)
from security_analyzer.browser.console_monitor import ConsoleMonitor
from security_analyzer.browser.har_recorder import HarRecorder
from security_analyzer.browser.network_capture import NetworkCapture, redact_url_query
from security_analyzer.browser.route_discovery import RouteDiscovery
from security_analyzer.browser.screenshot_capture import ScreenshotCapture
from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.egress import resolve_browser_egress
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.utils.redaction import scrub_text


def _identity_artifact_key(identity_id: str) -> str:
    """Produce a stable, path-safe artifact component without exposing arbitrary IDs."""
    raw = str(identity_id or "anonymous")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")[:40] or "identity"
    suffix = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]
    return f"{slug}-{suffix}"


def _origin(url: str) -> str:
    parsed = urlsplit(str(url or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    rendered_host = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except ValueError:
        return ""
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    netloc = rendered_host if port in (None, default_port) else f"{rendered_host}:{port}"
    return f"{parsed.scheme.lower()}://{netloc}"


def _run_katana(
    ctx: ExecutionContext,
    stage_id: str,
    seed_urls: list[str],
    browser_cfg: dict[str, Any],
    *,
    max_depth: int,
    max_pages: int,
    check_dns: bool,
) -> tuple[str, list[dict[str, Any]], str]:
    """Run Katana over the browser seeds and retain only validated in-scope URLs."""
    binary = shutil.which("katana")
    if not binary:
        return "failed", [], "Katana executable was not found"

    seed_file_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix="security-analyzer-katana-",
            suffix=".txt", delete=False,
        ) as seed_file:
            seed_file_path = seed_file.name
            seed_file.write("\n".join(seed_urls))
            seed_file.write("\n")

        scope_hosts = sorted({
            parsed.hostname.lower().rstrip(".")
            for parsed in (urlsplit(url) for url in seed_urls)
            if parsed.hostname
        })
        command = [
            binary, "-list", seed_file_path, "-jsonl", "-silent",
            "-duc", "-or", "-ob", "-depth", str(max_depth),
            "-c", str(max(1, int(browser_cfg.get("katana_concurrency", 3)))),
            "-rl", str(max(1, int(browser_cfg.get("katana_rate_limit", 3)))),
            "-timeout", str(max(1, int(browser_cfg.get("katana_request_timeout_sec", 10)))),
            "-max-response-size", str(max(1, int(browser_cfg.get("katana_max_response_bytes", 1048576)))),
        ]
        if scope_hosts:
            command.extend(["-cs", ",".join(scope_hosts)])
        result = ctx.resource_governor.run_process(
            command,
            timeout_sec=max(1, int(browser_cfg.get("katana_timeout_sec", 300))),
            cwd=ctx.workspace.project_root,
        )
        if result.timed_out:
            return "failed", [], "Katana exceeded its configured timeout"
        if result.output_truncated:
            return "failed", [], "Katana output exceeded the configured process-output limit"
        if result.returncode != 0:
            detail = (result.stderr or "").strip()[:300] or f"exit code {result.returncode}"
            return "failed", [], f"Katana exited unsuccessfully: {detail}"

        records: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            request_data = record.get("request", {})
            raw_url = request_data.get("endpoint", "") if isinstance(request_data, dict) else ""
            if not raw_url:
                raw_url = record.get("url", "")
            decision = ctx.scope_engine.evaluate_url(str(raw_url), check_dns=True)
            if decision.allowed:
                ctx.coverage.record_target_tested(stage_id, decision.normalized_url)
                records.append(record)
            elif raw_url:
                ctx.coverage.record_out_of_scope(
                    stage_id, str(raw_url), getattr(decision, "reason", "URL rejected by scope policy")
                )
        return "success", records[:max_pages], ""
    except ResourceLimitExceeded as exc:
        return "failed", [], f"ResourceGovernor blocked Katana: {str(exc)[:200]}"
    except OSError as exc:
        return "failed", [], f"Katana execution error: {type(exc).__name__}"
    finally:
        if seed_file_path:
            try:
                os.unlink(seed_file_path)
            except OSError:
                pass


def _browser_identity_contexts(ctx: ExecutionContext) -> list[tuple[str, Any, Any]]:
    """Return (identity_id, context, profile) in deterministic configured order."""
    manager = ctx.auth_manager
    if manager is None:
        return [("anonymous", None, None)]

    identities = manager.list_identities()
    if not identities:
        identities = ["anonymous"]

    results: list[tuple[str, Any, Any]] = []
    for identity_id in identities:
        identity_context = manager.get_context(identity_id)
        profile = manager.profiles.get(identity_id)
        results.append((identity_id, identity_context, profile))
    return results


def _identity_browser_settings(
    ctx: ExecutionContext,
    identity_id: str,
    identity_context: Any,
    profile: Any,
    *,
    check_dns: bool,
) -> tuple[dict[str, str], set[str], dict[str, dict[str, str]], dict[str, Any] | None]:
    """Build origin-restricted browser credentials and storage for one identity."""
    if identity_context is None or identity_id == "anonymous":
        return {}, set(), {}, None

    if not identity_context.authenticated or not identity_context.session_valid:
        return {}, set(), {}, None

    raw_origins = (
        list(getattr(profile, "browser_auth_origins", []) or [])
        if profile is not None
        else []
    )
    if not raw_origins:
        raw_origins = [ctx.target]

    allowed_origins: set[str] = set()
    for raw_origin in raw_origins:
        normalized_origin = _origin(raw_origin)
        if not normalized_origin:
            continue
        decision = ctx.scope_engine.evaluate_url(
            normalized_origin + "/",
            check_dns=check_dns,
        )
        if decision.allowed:
            allowed_origins.add(_origin(decision.normalized_url))

    # A profile with no in-scope browser origin must not load credentials or
    # browser storage into any page.
    if not allowed_origins:
        return {}, set(), {}, None

    headers = dict(identity_context.headers)

    session_storage: dict[str, dict[str, str]] = {}
    for raw_origin, values in (
        getattr(identity_context, "session_storage_by_origin", {}) or {}
    ).items():
        normalized_origin = _origin(raw_origin)
        if normalized_origin not in allowed_origins:
            continue
        session_storage[normalized_origin] = {
            str(key): str(value)
            for key, value in (values or {}).items()
        }

    storage_state: dict[str, Any] | None = None
    to_storage_state = getattr(
        identity_context,
        "to_playwright_storage_state",
        None,
    )
    if callable(to_storage_state):
        raw_state = to_storage_state(ctx.target)
        allowed_hosts = {
            urlsplit(origin).hostname.lower().rstrip(".")
            for origin in allowed_origins
        }
        safe_cookies = []
        for cookie in raw_state.get("cookies", []):
            domain = str(cookie.get("domain", "")).lower().lstrip(".").rstrip(".")
            if not domain:
                continue
            if any(
                host == domain or host.endswith("." + domain)
                for host in allowed_hosts
            ):
                safe_cookies.append(cookie)

        safe_origins = []
        for origin_entry in raw_state.get("origins", []):
            origin = _origin(str(origin_entry.get("origin", "")))
            if origin in allowed_origins:
                safe_origins.append(
                    {
                        "origin": origin,
                        "localStorage": list(
                            origin_entry.get("localStorage", [])
                        ),
                    }
                )

        storage_state = {
            "cookies": safe_cookies,
            "origins": safe_origins,
        }

    return headers, allowed_origins, session_storage, storage_state


def run_browser_capture(ctx: ExecutionContext, stage_def: StageDefinition) -> StageResult:
    """Capture in-scope application routes independently for each configured identity."""
    if not is_playwright_installed():
        reason = (
            "Playwright Python package is not installed; browser discovery skipped "
            "without synthetic routes"
        )
        ctx.coverage.record_skipped_check(stage_def.stage_id, "playwright", reason)
        return StageResult(
            stage_id=stage_def.stage_id,
            status=StageStatus.SKIPPED,
            summary=reason,
            metrics={"targets_total": 0, "targets_tested": 0, "targets_skipped": 0},
        )

    browser_cfg = ctx.config.get("browser", {})
    egress = resolve_browser_egress(ctx.config, ctx.scope_engine.policy)
    if not egress.allowed:
        reason = egress.reason
        ctx.coverage.record_skipped_check(stage_def.stage_id, "browser_egress", reason)
        return StageResult(
            stage_id=stage_def.stage_id,
            status=StageStatus.SKIPPED,
            summary=reason,
            metrics={"targets_total": 0, "targets_tested": 0, "targets_skipped": 0},
        )

    headless = bool(browser_cfg.get("headless", True))
    max_pages = int(browser_cfg.get("max_pages", 25))
    max_depth = int(browser_cfg.get("max_depth", 2))
    nav_timeout_ms = int(browser_cfg.get("navigation_timeout_ms", 15000))
    settle_wait_ms = int(browser_cfg.get("settle_wait_ms", 1200))
    capture_screenshots = bool(browser_cfg.get("capture_screenshots", True))
    max_screenshots = int(browser_cfg.get("max_screenshots", 15))
    record_har = bool(browser_cfg.get("record_har", True))
    har_mode = str(browser_cfg.get("har_mode", "minimal"))
    max_console_events = int(browser_cfg.get("max_console_events", 500))
    user_agent = str(ctx.config.get("limits", {}).get("user_agent", "SecurityAnalyzer/0.1.0"))
    check_dns = bool(ctx.config.get("scope", {}).get("check_dns", True))
    if egress.mode == "lab":
        # Lab mode still pins and validates every browser destination against DNS.
        check_dns = True
    viewport = browser_cfg.get("viewport", {})
    # Crawl budgets: failed navigations also count, so a slow/blocking site can't loop for hours.
    max_attempts = int(browser_cfg.get("max_attempts", max_pages * 2))
    max_crawl_sec = int(browser_cfg.get("max_crawl_sec_per_identity", 600))
    max_stage_sec = int(browser_cfg.get("max_stage_sec", 1800))
    max_consecutive_failures = int(browser_cfg.get("max_consecutive_failures", 5))
    max_query_variants = int(browser_cfg.get("max_query_variants_per_path", 3))
    max_seed_hosts = int(browser_cfg.get("max_seed_hosts", 10))
    block_resource_types = list(browser_cfg.get("block_resource_types", ["media", "font"]))
    stage_deadline = time.monotonic() + max(60, max_stage_sec)

    if max_pages < 1 or max_depth < 0 or nav_timeout_ms < 1000 or settle_wait_ms < 0:
        raise ValueError("Invalid browser limits: max_pages, max_depth, navigation_timeout_ms or settle_wait_ms")

    subdomains_art = ctx.upstream_artifacts["domain_enumeration"]["discovery/subdomains.json"]
    seed_urls: list[str] = [ctx.target]
    seed_scheme = urlsplit(ctx.target).scheme.lower() or "https"
    for host_entry in subdomains_art.get("hosts", []):
        raw_url = str(host_entry.get("url", "")).strip()
        if not raw_url:
            # Step 1 assets carry "hostname"/"ports", never "url".
            hostname = str(host_entry.get("hostname", "")).strip()
            if hostname:
                ports = host_entry.get("ports") or []
                port = ports[0] if ports else None
                port_part = f":{port}" if port and int(port) not in (80, 443) else ""
                raw_url = f"{seed_scheme}://{hostname}{port_part}/"
        if raw_url and raw_url not in seed_urls and len(seed_urls) < max_seed_hosts:
            seed_urls.append(raw_url)

    inventory = UnifiedEndpointInventory(ctx.workspace)
    normalizer = EndpointNormalizer(
        ctx.scope_engine,
        ctx.coverage,
        check_dns=check_dns,
    )
    route_discovery = RouteDiscovery()

    all_visited_pages: list[dict[str, Any]] = []
    all_navigation_errors: list[dict[str, str]] = []
    all_network_exchanges: list[dict[str, Any]] = []
    all_screenshots: list[dict[str, Any]] = []
    identity_results: list[dict[str, Any]] = []
    har_summaries: dict[str, dict[str, Any]] = {}
    total_blocked = 0
    total_budget_blocked = 0
    total_console_events = 0
    successful_identities = 0
    failed_identities = 0
    skipped_identities = 0

    all_identity_contexts = _browser_identity_contexts(ctx)
    if not all_identity_contexts:
        all_identity_contexts = [("anonymous", None, None)]

    max_identities = int(browser_cfg.get("max_identities", 5))
    identity_contexts = all_identity_contexts[:max_identities]
    omitted_identity_contexts = all_identity_contexts[max_identities:]
    for omitted_id, omitted_context, _ in omitted_identity_contexts:
        skipped_identities += 1
        reason = "Browser identity limit reached; this identity was not launched"
        ctx.coverage.record_skipped_check(
            stage_def.stage_id,
            f"identity:{omitted_id}",
            reason,
        )
        identity_results.append(
            {
                "identity_id": omitted_id,
                "role": str(getattr(omitted_context, "role", "")),
                "authenticated": bool(getattr(omitted_context, "authenticated", False)),
                "status": StageStatus.SKIPPED.value,
                "reason": reason,
                "visited_pages": 0,
                "navigation_errors": 0,
            }
        )

    for identity_id, identity_context, profile in identity_contexts:
        if time.monotonic() >= stage_deadline:
            skipped_identities += 1
            reason = "Browser stage time budget (browser.max_stage_sec) exhausted before this identity ran"
            ctx.coverage.record_skipped_check(stage_def.stage_id, f"identity:{identity_id}", reason)
            identity_results.append(
                {
                    "identity_id": identity_id,
                    "role": str(getattr(identity_context, "role", "")),
                    "authenticated": bool(getattr(identity_context, "authenticated", False)),
                    "status": StageStatus.SKIPPED.value,
                    "reason": reason,
                    "visited_pages": 0,
                    "navigation_errors": 0,
                }
            )
            continue
        is_anonymous = identity_id == "anonymous"
        authenticated = bool(
            identity_context is not None
            and identity_context.authenticated
            and identity_context.session_valid
            and not is_anonymous
        )

        if (
            identity_context is not None
            and not is_anonymous
            and not authenticated
        ):
            skipped_identities += 1
            reason = "Identity session is not authenticated or not valid; browser context was not started"
            ctx.coverage.record_skipped_check(
                stage_def.stage_id,
                f"identity:{identity_id}",
                reason,
            )
            identity_results.append(
                {
                    "identity_id": identity_id,
                    "role": str(getattr(identity_context, "role", "")),
                    "authenticated": False,
                    "status": StageStatus.SKIPPED.value,
                    "reason": reason,
                    "visited_pages": 0,
                    "navigation_errors": 0,
                }
            )
            continue

        identity_key = _identity_artifact_key(identity_id)
        identity_dir = f"browser/identities/{identity_key}"
        har_path = f"{identity_dir}/traffic.har"
        console_path = f"{identity_dir}/console_events.json"
        screenshot_dir = f"{identity_dir}/screenshots"

        har_recorder = HarRecorder(ctx.workspace, har_path)
        har_target_path = har_recorder.prepare_path() if record_har else None
        net_capture = NetworkCapture()
        console_monitor = ConsoleMonitor(
            ctx.workspace,
            max_events=max_console_events,
            relative_path=console_path,
        )
        screenshot_capture = ScreenshotCapture(
            ctx.workspace,
            max_screenshots=max_screenshots if capture_screenshots else 0,
            relative_dir=screenshot_dir,
        )

        auth_headers, auth_origins, session_storage, storage_state = (
            _identity_browser_settings(
                ctx,
                identity_id,
                identity_context,
                profile,
                check_dns=check_dns,
            )
        )

        queue: deque[tuple[str, int]] = deque()
        enqueued: set[str] = set()
        for raw_seed in seed_urls:
            decision = ctx.scope_engine.evaluate_url(
                raw_seed,
                check_dns=check_dns,
            )
            if decision.allowed and decision.normalized_url not in enqueued:
                enqueued.add(decision.normalized_url)
                queue.append((decision.normalized_url, 0))

        visited_pages: list[dict[str, Any]] = []
        navigation_errors: list[dict[str, str]] = []
        skipped_mutating_total = 0
        blocked_count = 0
        budget_blocked_count = 0
        browser_error = ""
        captured_session_storage: dict[str, dict[str, str]] = {}
        attempts = 0
        consecutive_failures = 0
        stop_reason = "queue_empty"
        path_variants: dict[tuple[str, str], int] = {}

        try:
            with ScopedBrowserManager(
                ctx.scope_engine,
                coverage=ctx.coverage,
                stage_id=stage_def.stage_id,
                headless=headless,
                har_path=har_target_path,
                har_mode=har_mode,
                storage_state=storage_state,
                session_storage_by_origin=session_storage,
                auth_headers=auth_headers,
                auth_origins=auth_origins,
                resource_governor=ctx.resource_governor,
                user_agent=user_agent,
                lab_mode=egress.mode == "lab",
                check_dns=check_dns,
                block_resource_types=block_resource_types,
                viewport_width=int(viewport.get("width", 1366)),
                viewport_height=int(viewport.get("height", 768)),
            ) as manager:
                page = manager.new_page(timeout_ms=nav_timeout_ms)
                net_capture.attach(page)
                console_monitor.attach(page)
                crawl_deadline = min(
                    time.monotonic() + max(30, max_crawl_sec), stage_deadline
                )

                while queue and len(visited_pages) < max_pages:
                    if attempts >= max_attempts:
                        stop_reason = "attempt_limit"
                        break
                    if time.monotonic() >= crawl_deadline:
                        stop_reason = "time_limit"
                        break
                    if consecutive_failures >= max_consecutive_failures:
                        stop_reason = "consecutive_failures"
                        break
                    target_url, depth = queue.popleft()
                    decision = ctx.scope_engine.evaluate_url(
                        target_url,
                        check_dns=check_dns,
                    )
                    if not decision.allowed:
                        ctx.coverage.record_out_of_scope(
                            stage_def.stage_id,
                            target_url,
                            decision.reason,
                        )
                        continue

                    attempts += 1
                    try:
                        response = page.goto(
                            decision.normalized_url,
                            wait_until="domcontentloaded",
                            timeout=nav_timeout_ms,
                        )
                        page.wait_for_timeout(settle_wait_ms)
                    except Exception as exc:
                        consecutive_failures += 1
                        err_msg = f"{type(exc).__name__}: {exc}"
                        navigation_errors.append(
                            {
                                "url": redact_url_query(decision.normalized_url)[0],
                                "error": err_msg[:300],
                            }
                        )
                        ctx.coverage.record_request_failure(
                            stage_def.stage_id,
                            decision.normalized_url,
                            err_msg[:300],
                        )
                        continue

                    consecutive_failures = 0
                    final_url = str(page.url or decision.normalized_url)
                    final_decision = ctx.scope_engine.evaluate_url(
                        final_url,
                        check_dns=check_dns,
                    )
                    if not final_decision.allowed:
                        ctx.coverage.record_out_of_scope(
                            stage_def.stage_id,
                            final_url,
                            final_decision.reason,
                        )
                        continue

                    if not is_anonymous:
                        try:
                            session_origin, session_entries = SessionStorageBridge.capture_from_page(page)
                            origin_decision = ctx.scope_engine.evaluate_url(
                                f"{session_origin}/", check_dns=check_dns
                            )
                            if session_entries and origin_decision.allowed:
                                safe_origin = _origin(origin_decision.normalized_url)
                                captured_session_storage.setdefault(safe_origin, {}).update(session_entries)
                        except Exception:
                            # Session storage is optional evidence; never fail route capture on it.
                            pass

                    status_code = int(response.status) if response is not None else None
                    try:
                        page_title = str(page.title() or "")[:200]
                    except Exception:
                        page_title = ""

                    # Extract links/forms BEFORE the screenshot: the PII-masking script rewrites
                    # attributes (e.g. hrefs containing long numbers) and would corrupt them.
                    extracted = None
                    extract_error = ""
                    try:
                        extracted = route_discovery.extract_from_page(
                            page,
                            final_decision.normalized_url,
                        )
                    except Exception as exc:
                        extract_error = f"dom_extract:{type(exc).__name__}"

                    screenshot_ref = ""
                    if capture_screenshots:
                        try:
                            screenshot = screenshot_capture.capture(
                                page,
                                final_decision.normalized_url,
                            )
                            if screenshot is not None:
                                screenshot_ref = str(screenshot["relative_path"])
                                all_screenshots.append(
                                    {
                                        **screenshot,
                                        "identity_id": identity_id,
                                    }
                                )
                        except Exception as exc:
                            # Evidence capture failure must not silently produce
                            # an unmasked screenshot or fail route discovery.
                            navigation_errors.append(
                                {
                                    "url": redact_url_query(final_decision.normalized_url)[0],
                                    "error": f"screenshot_capture:{type(exc).__name__}",
                                }
                            )

                    visited_entry = {
                        "identity_id": identity_id,
                        "authenticated": authenticated,
                        "url": redact_url_query(final_decision.normalized_url)[0],
                        "depth": depth,
                        "status_code": status_code,
                        "title": page_title,
                        "screenshot": screenshot_ref,
                    }
                    visited_pages.append(visited_entry)
                    all_visited_pages.append(visited_entry)

                    nav_endpoint = normalizer.normalize(
                        final_decision.normalized_url,
                        method="GET",
                        source="playwright_navigation",
                        stage_id=stage_def.stage_id,
                        status_code=status_code,
                        title=page_title,
                        reachable=True,
                        evidence_ref=screenshot_ref or f"{identity_dir}/crawl_routes.json",
                        auth_context=identity_id,
                        tags=[f"identity:{identity_id}"],
                        check_dns=check_dns,
                    )
                    if nav_endpoint is not None:
                        inventory.upsert_endpoint(nav_endpoint)

                    if extracted is None:
                        navigation_errors.append(
                            {
                                "url": redact_url_query(final_decision.normalized_url)[0],
                                "error": extract_error or "dom_extract:unknown",
                            }
                        )
                        continue

                    skipped_mutating_total += len(
                        extracted.get("skipped_mutating_links", [])
                    )

                    for form in extracted.get("forms", []):
                        form_url = form.action_url
                        if form.input_names:
                            separator = "&" if "?" in form_url else "?"
                            form_url = (
                                f"{form_url}{separator}"
                                + urlencode([(name, "") for name in form.input_names])
                            )
                        form_endpoint = normalizer.normalize(
                            form_url,
                            method=form.method,
                            source="playwright_form",
                            stage_id=stage_def.stage_id,
                            evidence_ref=f"{identity_dir}/crawl_routes.json",
                            auth_context=identity_id,
                            tags=["html_form", f"identity:{identity_id}"],
                            check_dns=check_dns,
                        )
                        if form_endpoint is not None:
                            inventory.upsert_endpoint(form_endpoint)

                    for spa_route in extracted.get("spa_routes", []):
                        spa_endpoint = normalizer.normalize(
                            spa_route,
                            method="GET",
                            source="playwright_spa_route",
                            stage_id=stage_def.stage_id,
                            evidence_ref=f"{identity_dir}/crawl_routes.json",
                            auth_context=identity_id,
                            tags=["spa_route", f"identity:{identity_id}"],
                            check_dns=check_dns,
                        )
                        if spa_endpoint is not None:
                            inventory.upsert_endpoint(spa_endpoint)

                    if depth < max_depth:
                        for link in extracted.get("links", []):
                            link_decision = ctx.scope_engine.evaluate_url(
                                link,
                                check_dns=check_dns,
                            )
                            if (
                                link_decision.allowed
                                and link_decision.normalized_url not in enqueued
                            ):
                                link_parts = urlsplit(link_decision.normalized_url)
                                variant_key = (link_parts.netloc, link_parts.path)
                                # Crawl-trap guard: faceted/paginated URLs differing only by query.
                                if path_variants.get(variant_key, 0) >= max_query_variants:
                                    continue
                                path_variants[variant_key] = path_variants.get(variant_key, 0) + 1
                                enqueued.add(link_decision.normalized_url)
                                queue.append(
                                    (link_decision.normalized_url, depth + 1)
                                )

                if queue and stop_reason == "queue_empty":
                    stop_reason = "page_limit"
                blocked_count = len(manager.blocked_requests)
                budget_blocked_count = manager.budget_blocked_requests

        except Exception as exc:
            browser_error = (
                f"{type(exc).__name__}: {scrub_text(str(exc)[:300])}"
            )
            ctx.coverage.record_skipped_check(
                stage_def.stage_id,
                f"browser_identity:{identity_id}",
                browser_error,
            )
        finally:
            # Playwright flushes HAR when its context closes. Sanitize even when
            # navigation or browser shutdown failed so secrets are not left raw.
            if record_har:
                try:
                    har_summaries[identity_id] = har_recorder.summarize()
                except Exception as exc:
                    har_summaries[identity_id] = {
                        "recorded": False,
                        "relative_path": har_path,
                        "error": type(exc).__name__,
                    }
            try:
                console_payload = console_monitor.save(stage_id=stage_def.stage_id)
                total_console_events += int(console_payload["total_events"])
            except Exception:
                console_payload = {"total_events": 0}

        auth_store = getattr(ctx.auth_manager, "store", None)
        if captured_session_storage and auth_store is not None:
            try:
                SessionStorageBridge(auth_store).save_for_identity(
                    identity_key, captured_session_storage
                )
            except Exception as exc:
                ctx.coverage.record_skipped_check(
                    stage_def.stage_id,
                    f"session_storage:{identity_id}",
                    f"Could not persist browser session storage: {type(exc).__name__}",
                )

        all_navigation_errors.extend(navigation_errors)
        exchanges = net_capture.exchanges()
        exchange_dicts = [exchange.to_dict() for exchange in exchanges]
        for exchange in exchange_dicts:
            exchange["identity_id"] = identity_id
        all_network_exchanges.extend(exchange_dicts)

        api_endpoints_discovered = 0
        for exchange in exchanges:
            tags = (
                ["browser_network", f"resource:{exchange.resource_type}"]
                if exchange.resource_type
                else ["browser_network"]
            )
            if exchange.is_api_candidate:
                tags.append("api_candidate")
                api_endpoints_discovered += 1
            tags.append(f"identity:{identity_id}")

            network_endpoint = normalizer.normalize(
                exchange.sanitized_url,
                method=exchange.method,
                source="playwright_network",
                stage_id=stage_def.stage_id,
                status_code=exchange.status_code,
                content_type=exchange.response_content_type,
                request_content_type=exchange.request_content_type,
                request_headers=exchange.request_headers,
                request_body_schema=exchange.request_body_schema,
                reachable=exchange.status_code is not None,
                evidence_ref=(
                    har_path
                    if record_har
                    else f"{identity_dir}/console_events.json"
                ),
                auth_context=identity_id,
                tags=tags,
                check_dns=check_dns,
            )
            if network_endpoint is not None:
                inventory.upsert_endpoint(network_endpoint)

        total_blocked += blocked_count
        total_budget_blocked += budget_blocked_count

        if browser_error:
            if not visited_pages:
                identity_status = StageStatus.SKIPPED
                skipped_identities += 1
            else:
                identity_status = StageStatus.PARTIAL
                failed_identities += 1
        elif not visited_pages and navigation_errors:
            identity_status = StageStatus.FAILED
            failed_identities += 1
        elif navigation_errors or queue or budget_blocked_count:
            identity_status = StageStatus.PARTIAL
            successful_identities += 1
        else:
            identity_status = StageStatus.SUCCESS
            successful_identities += 1

        identity_results.append(
            {
                "identity_id": identity_id,
                "role": str(getattr(identity_context, "role", "anonymous")),
                "authenticated": authenticated,
                "session_valid": bool(
                    getattr(identity_context, "session_valid", True)
                ),
                "status": identity_status.value,
                "reason": browser_error,
                "visited_pages": len(visited_pages),
                "navigation_errors": len(navigation_errors),
                "crawl_attempts": attempts,
                "stop_reason": stop_reason,
                "skipped_mutating_links": skipped_mutating_total,
                "api_candidates": api_endpoints_discovered,
                "blocked_out_of_scope_requests": blocked_count,
                "budget_blocked_requests": budget_blocked_count,
                "artifacts": {
                    "har": har_path if record_har else None,
                    "console": console_path,
                    "screenshots": screenshot_dir,
                },
            }
        )

    if successful_identities == 0 and failed_identities == 0:
        status = StageStatus.SKIPPED
    elif failed_identities and successful_identities == 0:
        status = StageStatus.FAILED
    elif failed_identities or skipped_identities or any(
        item["status"] == StageStatus.PARTIAL.value
        for item in identity_results
    ):
        status = StageStatus.PARTIAL
    else:
        status = StageStatus.SUCCESS

    if successful_identities == 0 and failed_identities == 0:
        return StageResult(
            stage_id=stage_def.stage_id,
            status=status,
            summary="No eligible identity browser context was available",
            metrics={
                "targets_total": len(seed_urls) * len(all_identity_contexts),
                "targets_tested": 0,
                "targets_skipped": len(seed_urls) * len(all_identity_contexts),
            },
        )

    # ------------------------------------------------------------
    # Katana supplemental crawling
    # ------------------------------------------------------------
    katana_enabled = bool(browser_cfg.get("katana_enabled", False))
    katana_status = "disabled"
    katana_message = ""
    katana_records: list[dict[str, Any]] = []
    katana_endpoints_added = 0
    if katana_enabled:
        katana_status, katana_records, katana_message = _run_katana(
            ctx,
            stage_def.stage_id,
            seed_urls,
            browser_cfg,
            max_depth=max_depth,
            max_pages=max_pages,
            check_dns=check_dns,
        )
        if katana_status == "success":
            for record in katana_records:
                request_data = record.get("request", {})
                response_data = record.get("response", {})
                if not isinstance(request_data, dict):
                    continue
                raw_url = str(request_data.get("endpoint", "") or record.get("url", ""))
                if not raw_url:
                    continue
                status_code = response_data.get("status_code") if isinstance(response_data, dict) else None
                endpoint = normalizer.normalize(
                    raw_url,
                    method=str(request_data.get("method", "GET")),
                    source="katana_crawl",
                    stage_id=stage_def.stage_id,
                    status_code=status_code if isinstance(status_code, int) else None,
                    content_type=str(response_data.get("header", {}).get("content-type", ""))
                    if isinstance(response_data, dict) and isinstance(response_data.get("header"), dict)
                    else "",
                    reachable=True,
                    check_dns=True,
                )
                if endpoint is not None:
                    inventory.upsert_endpoint(endpoint)
                    katana_endpoints_added += 1

    inventory.save(stage_id=stage_def.stage_id)

    crawl_payload: dict[str, Any] = {
        "schema_version": "1.1",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "identity_captures": identity_results,
        "katana": {
            "enabled": katana_enabled,
            "status": katana_status,
            "message": katana_message,
            "records_received": len(katana_records),
            "endpoints_added": katana_endpoints_added,
        },
        "visited_pages": all_visited_pages,
        "navigation_errors": all_navigation_errors,
        "skipped_mutating_links_count": sum(
            int(item.get("skipped_mutating_links", 0))
            for item in identity_results
        ),
        "blocked_out_of_scope_requests_count": total_blocked,
        "budget_blocked_requests_count": total_budget_blocked,
        "har": har_summaries,
        "console_events_count": total_console_events,
        "screenshots": all_screenshots,
        "network_exchanges": all_network_exchanges,
        "endpoints": [
            endpoint.to_dict()
            for endpoint in inventory.all_endpoints()
            if (
                any(source.startswith("playwright_") for source in endpoint.discovery_sources)
                or "katana_crawl" in endpoint.discovery_sources
            )
        ],
    }
    ctx.workspace.write_json_atomic(
        "browser/crawl_routes.json",
        crawl_payload,
    )

    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Captured {len(all_visited_pages)} Playwright page(s) across "
            f"{len(identity_results)} identity context(s), "
            f"{len(all_network_exchanges)} network exchange(s); "
            f"Katana status: {katana_status}, "
            f"{katana_endpoints_added} endpoint(s) added; "
            f"{failed_identities} failed and {skipped_identities} skipped"
        ),
        artifacts=[
            "browser/crawl_routes.json",
            "inventory/unified_endpoints.json",
            "inventory/contributions/browser_capture.json",
        ],
        metrics={
            "targets_total": len(seed_urls) * len(all_identity_contexts),
            "targets_tested": len(all_visited_pages),
            "targets_skipped": (
                len(seed_urls) * len(all_identity_contexts)
                - len(all_visited_pages)
            ),
            "identities_total": len(all_identity_contexts),
            "identities_successful": successful_identities,
            "identities_failed": failed_identities,
            "identities_skipped": skipped_identities,
            "network_exchanges": len(all_network_exchanges),
            "budget_blocked_requests": total_budget_blocked,
            "katana_records_received": len(katana_records),
            "katana_endpoints_added": katana_endpoints_added,
        },
    )