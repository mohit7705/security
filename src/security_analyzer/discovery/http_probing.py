from __future__ import annotations

import ipaddress
import json
import math
import threading
from concurrent.futures import ThreadPoolExecutor
import os
import re
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.egress import is_trusted_scope_proxy
from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.utils.http_client import ScopedHttpClient
from security_analyzer.utils.request_safety import is_destructive_request, is_safe_read_method

TITLE_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.strip().lower() == "localhost"


def _is_local_scope_proxy(proxy_url: str) -> bool:
    """Compatibility wrapper for the shared trusted-proxy policy."""
    return is_trusted_scope_proxy(proxy_url)


def _proxy_env(proxy_url: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "ALL_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "all_proxy": proxy_url,
        "NO_PROXY": "localhost,127.0.0.1,::1",
        "no_proxy": "localhost,127.0.0.1,::1",
    })
    return env


def _safe_location(base_url: str, location: str, normalizer: EndpointNormalizer, stage_id: str) -> str:
    if not location:
        return ""
    record = normalizer.normalize(location, base_url=base_url, stage_id=stage_id)
    if record is not None:
        return record.url
    try:
        parsed = urlsplit(urljoin(base_url, location))
        if parsed.scheme and parsed.hostname:
            host = parsed.hostname.lower()
            authority = f"[{host}]" if ":" in host else host
            if parsed.port:
                authority += f":{parsed.port}"
            return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", "", ""))
    except ValueError:
        pass
    return "[BLOCKED_REDIRECT]"


def _extract_title(html_text: str) -> str:
    match = TITLE_PATTERN.search(html_text[:32768])
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


def _detect_technologies(headers: dict[str, str], body_sample: str) -> list[str]:
    tech: set[str] = set()
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    if server:
        tech.add(f"server:{server[:64]}")
    if powered_by:
        tech.add(f"powered_by:{powered_by[:64]}")
    lower_body = body_sample[:16384].lower()
    if "__next_data__" in lower_body or "/_next/" in lower_body:
        tech.add("Next.js")
    if "ng-version" in lower_body:
        tech.add("Angular")
    if "data-reactroot" in lower_body or "react-dom" in lower_body or "__react" in lower_body:
        tech.add("React")
    if "swagger-ui" in lower_body or "/openapi.json" in lower_body or "/swagger.json" in lower_body:
        tech.add("OpenAPI")
    if "/graphql" in lower_body or "graphql-playground" in lower_body:
        tech.add("GraphQL")
    return sorted(tech)


def _is_projectdiscovery_httpx(binary: str, governor) -> bool:
    """`httpx` on PATH is often the Python httpx CLI, which rejects `-l`/`-json`."""
    if Path(binary).name == "httpx-toolkit":
        return True
    try:
        proc = governor.run_process([binary, "-version"], timeout_sec=10)
    except Exception:
        return False
    text = f"{proc.stdout}\n{proc.stderr}".lower()
    return "projectdiscovery" in text or "current version" in text


def _scaled_timeout(base_sec: int, url_count: int, rate: int) -> int:
    needed = math.ceil(url_count / max(1, rate)) * 1.5 + 30
    return int(min(max(base_sec, needed), 900))


def _run_httpx_toolkit(
    urls: list[str],
    *,
    proxy_url: str,
    scope_engine,
    check_dns: bool,
    timeout_sec: int,
    governor,
) -> tuple[dict[str, dict[str, Any]], str]:
    binary = shutil.which("httpx-toolkit") or shutil.which("httpx")
    if not binary:
        return {}, "httpx-toolkit is not installed"
    if not urls:
        return {}, "No URLs available for httpx-toolkit"

    if not _is_projectdiscovery_httpx(binary, governor):
        return {}, "httpx binary on PATH is not ProjectDiscovery httpx (install httpx-toolkit)"

    rate = min(max(1, int(getattr(governor, "requests_per_host_per_sec", 5))), 25)
    timeout_sec = min(
        _scaled_timeout(timeout_sec, len(urls), rate),
        max(1, int(timeout_sec)),
    )
    with tempfile.TemporaryDirectory(prefix="security-analyzer-httpx-") as tmp_dir:
        targets_file = Path(tmp_dir) / "targets.txt"
        targets_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
        cmd = [
            binary,
            "-l", str(targets_file),
            "-http-proxy", proxy_url,
            "-sc",
            "-cl",
            "-title",
            "-td",
            "-location",
            "-rl", str(rate),
            "-json",
            "-silent",
            "-nc",
        ]
        try:
            proc = governor.run_process(
                cmd,
                timeout_sec=timeout_sec,
                env=_proxy_env(proxy_url),
            )
        except ResourceLimitExceeded:
            return {}, f"httpx-toolkit stopped by scan-wide resource budget ({timeout_sec}s)"
        except OSError as exc:
            return {}, f"httpx-toolkit could not run ({type(exc).__name__})"

        note = ""
        if proc.timed_out:
            # Keep whatever was already emitted instead of discarding it.
            note = f"httpx-toolkit exceeded its time budget ({timeout_sec}s); partial results kept"
        elif proc.returncode != 0:
            return {}, f"httpx-toolkit exited with status {proc.returncode}"

        by_url: dict[str, dict[str, Any]] = {}
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            raw_url = str(obj.get("url") or obj.get("input") or "").strip()
            if not raw_url:
                continue
            decision = scope_engine.evaluate_url(raw_url, check_dns=check_dns)
            if not decision.allowed:
                continue
            techs = [str(t)[:64] for t in (obj.get("tech") or []) if isinstance(t, str) and t.strip()]
            by_url[decision.normalized_url] = {
                "status_code": int(obj.get("status_code") or obj.get("status-code") or 0) or None,
                "content_length": int(obj.get("content_length") or obj.get("content-length") or 0),
                "title": str(obj.get("title", ""))[:200],
                "technologies": sorted(set(techs)),
                "location": str(obj.get("location", "")),
            }
        return by_url, note


def _run_whatweb(
    hosts: list[str],
    *,
    proxy_url: str,
    timeout_sec: int,
    governor,
) -> tuple[dict[str, list[str]], str]:
    binary = shutil.which("whatweb")
    if not binary:
        return {}, "whatweb is not installed"
    if not hosts:
        return {}, "No hosts available for whatweb"

    parsed_proxy = urlsplit(proxy_url)
    proxy_host_port = f"{parsed_proxy.hostname}:{parsed_proxy.port}"

    with tempfile.TemporaryDirectory(prefix="security-analyzer-whatweb-") as tmp_dir:
        hosts_file = Path(tmp_dir) / "hosts.txt"
        hosts_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")
        cmd = [
            binary,
            "--no-errors",
            "--color=never",
            "-a", "3",
            "--proxy", proxy_host_port,
            "--log-json=-",
            "-i", str(hosts_file),
        ]
        try:
            proc = governor.run_process(
                cmd,
                timeout_sec=timeout_sec,
                env=_proxy_env(proxy_url),
            )
        except ResourceLimitExceeded:
            return {}, f"whatweb stopped by scan-wide resource budget ({timeout_sec}s)"
        except OSError as exc:
            return {}, f"whatweb could not run ({type(exc).__name__})"

        if proc.timed_out:
            return {}, f"whatweb exceeded its time budget ({timeout_sec}s)"
        if proc.returncode != 0:
            return {}, f"whatweb exited with status {proc.returncode}"

        tech_by_host: dict[str, set[str]] = {}
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line or line in {"[", "]"}:
                continue
            line = line.rstrip(",")
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(entry, dict):
                continue
            target = str(entry.get("target", "")).strip()
            host = (urlsplit(target).hostname or "").lower().rstrip(".")
            plugins = entry.get("plugins")
            if not host or not isinstance(plugins, dict):
                continue
            for plugin_name in plugins:
                if plugin_name not in {"Title", "Country", "IP", "HTTPServer", "Cookies", "UncommonHeaders", "Script", "Email"}:
                    tech_by_host.setdefault(host, set()).add(str(plugin_name)[:64])
        return {h: sorted(t) for h, t in tech_by_host.items()}, ""


def _run_nmap(
    hosts: list[str],
    *,
    timeout_sec: int,
    governor,
) -> tuple[dict[str, list[dict[str, Any]]], str]:
    """Fail closed until a separately scoped TCP scanning transport exists.

    Nmap performs direct TCP connections. The enforced egress transport in
    this project is an HTTP/HTTPS proxy and cannot safely proxy arbitrary TCP
    port scans. Do not launch Nmap from the scanner process under the host or
    Docker egress restrictions.
    """
    if not shutil.which("nmap"):
        return {}, "nmap is not installed"
    if not hosts:
        return {}, "No hosts available for nmap"
    return {}, (
        "nmap skipped: direct TCP scanning is not supported by the scoped HTTP "
        "proxy; direct scanner egress is disabled"
    )


_GLOBAL_STOP = "global_budget"


def _probe_one(client, ep, method: str, stage_id: str, deadline: float, stop: threading.Event):
    """Network-only worker. All inventory/coverage writes stay on the main thread."""
    if stop.is_set():
        return ("budget", None, 0.0)
    if time.monotonic() >= deadline:
        return ("deadline", None, 0.0)
    start = time.monotonic()
    try:
        resp = client.request(method, ep.url, stage_id=stage_id, allow_redirects=False)
    except ResourceLimitExceeded as exc:
        # The same exception type is raised for a single oversized response body
        # and for the scan-wide budget; only the latter must stop the stage.
        if "Response body" in str(exc):
            return ("oversize", exc, 0.0)
        stop.set()
        return ("budget", exc, 0.0)
    except ScopeViolationError as exc:
        return ("scope", exc, 0.0)
    except requests.RequestException as exc:
        return ("error", exc, 0.0)
    return ("ok", resp, round((time.monotonic() - start) * 1000.0, 2))


def run_http_probing(ctx: ExecutionContext, stage_def: StageDefinition) -> StageResult:
    """Stage 05: Probes inventoried endpoints with strict TLS verification and single-pass deduplication."""
    inventory = UnifiedEndpointInventory(ctx.workspace)
    check_dns = bool(ctx.config.get("scope", {}).get("check_dns", False))
    normalizer = EndpointNormalizer(
        ctx.scope_engine,
        ctx.coverage,
        check_dns=check_dns,
    )

    timeouts = ctx.config.get("timeouts", {})
    max_urls = max(0, min(int(ctx.config.get("limits", {}).get("max_urls_per_stage", 2500)), 10000))
    client = ScopedHttpClient(
        ctx.scope_engine,
        coverage=ctx.coverage,
        connect_timeout=float(timeouts.get("http_connect_sec", 10)),
        read_timeout=float(timeouts.get("http_read_sec", 20)),
        max_redirects=0,  # Capture raw hop status here; redirect chains are traced in redirect_analysis
        check_dns=check_dns,
        governor=ctx.resource_governor,
    )

    stage_budget = max(1.0, float(timeouts.get("http_probe_stage_sec", 900)))
    stage_deadline = time.monotonic() + stage_budget

    def emit_progress(completed: int, total: int, message: str) -> None:
        callback = getattr(ctx, "progress_callback", None)
        if callable(callback):
            percent = 100 if total <= 0 else min(99, max(0, int(completed * 100 / total)))
            try:
                callback({
                    "progress_percent": percent,
                    "message": message[:180],
                    "completed": max(0, int(completed)),
                    "total": max(0, int(total)),
                })
            except Exception:
                pass

    raw_candidates = inventory.get_endpoints(include_excluded=False)
    candidates: list[Any] = []
    seen_probe_keys: set[tuple[str, str]] = set()
    dedup_skipped = 0
    unsafe_skipped = 0
    cap_skipped = 0
    for ep in raw_candidates:
        probe_method = str(ep.method or "GET").upper()
        # Never turn a discovered write method into a GET request. That can
        # accidentally invoke state-changing behavior on poorly designed apps.
        if not is_safe_read_method(probe_method):
            unsafe_skipped += 1
            continue
        if is_destructive_request(ep.url, method=probe_method):
            unsafe_skipped += 1
            continue
        canonical_key = (probe_method, ep.canonical_url or ep.url)
        if canonical_key in seen_probe_keys:
            dedup_skipped += 1
            continue
        if len(candidates) >= max_urls:
            cap_skipped += 1
            continue
        seen_probe_keys.add(canonical_key)
        candidates.append(ep)

    if unsafe_skipped:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id,
            "destructive_or_non_read_endpoint",
            f"Skipped {unsafe_skipped} endpoint(s) matching the shared read-only request policy",
        )

    if cap_skipped:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "max_urls_per_stage",
            f"{cap_skipped} endpoint(s) beyond max_urls_per_stage={max_urls} were not probed",
        )

    probe_records: list[dict[str, Any]] = []
    tested = 0
    failed = 0
    oversize = 0
    deadline_skipped = 0
    budget_exhausted = False
    tools_used: set[str] = set()

    proxy_url = os.environ.get("SECURITY_ANALYZER_PROXY", "").strip()
    egress_enforced = (
        os.environ.get("SECURITY_ANALYZER_EGRESS_ENFORCED") == "1"
        and _is_local_scope_proxy(proxy_url)
    )
    non_loopback_urls = [
        ep.url
        for ep in candidates
        if not _is_loopback_host(ep.hostname)
    ]
    non_loopback_hosts = sorted({
        ep.hostname
        for ep in candidates
        if ep.hostname and not _is_loopback_host(ep.hostname)
    })

    httpx_map: dict[str, dict[str, Any]] = {}
    whatweb_map: dict[str, list[str]] = {}
    nmap_map: dict[str, list[dict[str, Any]]] = {}

    if non_loopback_urls and not egress_enforced:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "external_probe_tools",
            "httpx-toolkit/whatweb skipped: scoped egress proxy is not enforced",
        )
    if egress_enforced and ctx.resource_governor is not None and non_loopback_urls and time.monotonic() < stage_deadline:
        remaining_tool_budget = max(1, int(stage_deadline - time.monotonic()))
        httpx_map, httpx_err = _run_httpx_toolkit(
            non_loopback_urls,
            proxy_url=proxy_url,
            scope_engine=ctx.scope_engine,
            check_dns=check_dns,
            timeout_sec=min(int(timeouts.get("httpx_sec", 120)), remaining_tool_budget),
            governor=ctx.resource_governor,
        )
        if httpx_map:
            tools_used.add("httpx-toolkit")
        if httpx_err:
            ctx.coverage.record_skipped_check(stage_def.stage_id, "httpx-toolkit", httpx_err)

        whatweb_map, whatweb_err = _run_whatweb(
            non_loopback_hosts,
            proxy_url=proxy_url,
            timeout_sec=min(int(timeouts.get("whatweb_sec", 120)), max(1, int(stage_deadline - time.monotonic()))),
            governor=ctx.resource_governor,
        )
        if whatweb_map:
            tools_used.add("whatweb")
        elif whatweb_err:
            ctx.coverage.record_skipped_check(stage_def.stage_id, "whatweb", whatweb_err)

        nmap_map, nmap_err = _run_nmap(
            non_loopback_hosts,
            timeout_sec=min(int(timeouts.get("nmap_sec", 180)), max(1, int(stage_deadline - time.monotonic()))),
            governor=ctx.resource_governor,
        )
        if nmap_map:
            tools_used.add("nmap")
            for host, open_ports in nmap_map.items():
                port_nums = [int(p["port"]) for p in open_ports if p.get("port")]
                if port_nums:
                    inventory.upsert_asset(host, ports=port_nums, source="nmap")
        elif nmap_err:
            ctx.coverage.record_skipped_check(stage_def.stage_id, "nmap", nmap_err)

    deadline = stage_deadline
    workers = max(1, min(int(getattr(ctx.resource_governor, "max_concurrent_requests", 4) or 4), 8))
    stop = threading.Event()
    plan = [(ep, ep.method if ep.method in {"GET", "HEAD", "OPTIONS"} else "GET") for ep in candidates]
    emit_progress(0, len(plan), f"HTTP probing starting: {len(plan)} unique safe endpoint(s)")
    outcomes_by_index: dict[int, tuple[str, Any, float]] = {}
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="http-probe") as pool:
        futures = {
            pool.submit(_probe_one, client, ep, method, stage_def.stage_id, deadline, stop): index
            for index, (ep, method) in enumerate(plan)
        }
        completed_futures = 0
        from concurrent.futures import as_completed
        for future in as_completed(futures):
            index = futures[future]
            try:
                outcomes_by_index[index] = future.result()
            except Exception as exc:
                outcomes_by_index[index] = ("error", exc, 0.0)
            completed_futures += 1
            emit_progress(
                completed_futures,
                len(plan),
                f"HTTP probing: completed {completed_futures}/{len(plan)} endpoint checks",
            )

    for index, (ep, method) in enumerate(plan):
        kind, resp, elapsed_ms = outcomes_by_index.get(index, ("deadline", None, 0.0))
        if kind == "budget":
            budget_exhausted = True
            failed += 1
            continue
        if kind == "deadline":
            deadline_skipped += 1
            continue
        if kind == "scope":
            ep.excluded = True
            ep.scope_status = "out_of_scope"
            inventory.upsert_endpoint(ep)
            continue
        if kind in {"error", "oversize"}:
            if kind == "error":
                failed += 1
            else:
                oversize += 1
            ep.reachable = False
            inventory.upsert_endpoint(ep)
            probe_records.append(
                {
                    "endpoint_id": ep.endpoint_id,
                    "url": ep.url,
                    "method": method,
                    "reachable": False,
                    "error": type(resp).__name__ if kind == "error" else "ResponseTooLarge",
                }
            )
            continue

        tested += 1
        ctx.coverage.record_target_tested(stage_def.stage_id, ep.url, status_code=resp.status_code)
        ctype = resp.headers.get("Content-Type", "")
        text_preview = (
            resp.text[:32768]
            if "text" in ctype.lower() or "json" in ctype.lower() or "html" in ctype.lower()
            else ""
        )
        httpx_info = httpx_map.get(ep.url) or httpx_map.get(ep.canonical_url or "") or {}
        title = (_extract_title(text_preview) if "html" in ctype.lower() else "") or httpx_info.get("title", "")
        merged_tech = sorted(
            set(_detect_technologies(dict(resp.headers), text_preview))
            | set(httpx_info.get("technologies", []))
            | set(whatweb_map.get(ep.hostname, []))
        )

        if merged_tech:
            inventory.upsert_asset(ep.hostname, technologies=merged_tech, source="http_probing")

        updated = normalizer.normalize(
            ep.url,
            method=method,
            source="http_probing",
            stage_id=stage_def.stage_id,
            status_code=resp.status_code,
            content_type=ctype,
            reachable=True,
            evidence_ref="discovery/http_probes.json",
        )
        if updated is not None:
            updated.title = title
            updated.tested = True
            inventory.upsert_endpoint(updated)

        probe_records.append(
            {
                "endpoint_id": updated.endpoint_id if updated is not None else ep.endpoint_id,
                "url": updated.url if updated is not None else ep.url,
                "canonical_url": updated.canonical_url if updated is not None else ep.canonical_url,
                "method": method,
                "reachable": True,
                "status_code": resp.status_code,
                "server": str(resp.headers.get("Server", ""))[:120],
                "content_type": ctype,
                "content_length": len(resp.content or b""),
                "title": title,
                "body_preview": re.sub(r"\s+", " ", text_preview[:1024]).strip(),
                "redirect_location": _safe_location(
                    ep.url, resp.headers.get("Location", ""), normalizer, stage_def.stage_id
                ),
                "technologies": merged_tech,
                "open_ports": nmap_map.get(ep.hostname, []),
                "elapsed_ms": elapsed_ms,
            }
        )

    if budget_exhausted:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "http_resource_budget", "Scan-wide resource budget exhausted during probing"
        )
    if deadline_skipped:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "http_probe_stage_budget",
            f"{deadline_skipped} endpoint(s) not probed: stage budget {int(stage_budget)}s reached",
        )

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "external_tools_used": sorted(tools_used),
        "deduplicated_skipped": dedup_skipped,
        "budget_exhausted": budget_exhausted,
        "deadline_skipped": deadline_skipped,
        "oversize_skipped": oversize,
        "probes": probe_records,
    }
    ctx.workspace.write_json_atomic("discovery/http_probes.json", payload)
    inventory.save(stage_id=stage_def.stage_id)

    # Historical/wayback URLs routinely time out; a few dead URLs must not mark the
    # whole stage PARTIAL. Only a high failure ratio or a truncated run does.
    attempted = tested + failed
    fail_ratio = (failed / attempted) if attempted else 0.0
    max_fail_ratio = float(ctx.config.get("limits", {}).get("http_probe_max_failure_ratio", 0.5))
    status = (
        StageStatus.PARTIAL
        if not candidates or tested == 0 or budget_exhausted or deadline_skipped > 0 or fail_ratio > max_fail_ratio
        else StageStatus.SUCCESS
    )

    emit_progress(
        100,
        100,
        f"HTTP probing finished: {tested} tested, {failed} failed, {deadline_skipped} not started",
    )
    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Probed {tested} reachable endpoint(s), {failed} unreachable"
            + (f" ({dedup_skipped} duplicate URL(s) deduplicated)" if dedup_skipped else "")
            + (f"; {deadline_skipped} not probed (stage time budget)" if deadline_skipped else "")
            + (f"; {oversize} oversized response(s) skipped" if oversize else "")
            + (f"; {unsafe_skipped} destructive/non-read endpoint(s) skipped" if unsafe_skipped else "")
            + ("; scan resource budget exhausted" if budget_exhausted else "")
        ),
        artifacts=["discovery/http_probes.json", "inventory/unified_endpoints.json", "inventory/contributions/http_probing.json"],
        metrics={
            "targets_total": len(raw_candidates),
            "targets_tested": tested,
            "targets_skipped": failed + unsafe_skipped + dedup_skipped,
            "destructive_or_non_read_skipped": unsafe_skipped,
            "deadline_skipped": deadline_skipped,
            "oversize_skipped": oversize,
            "failure_ratio": round(fail_ratio, 3),
        },
    )