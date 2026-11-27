from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.egress import is_trusted_scope_proxy
from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.utils.http_client import ScopedHttpClient

BUILTIN_COMMON_PATHS: tuple[str, ...] = (
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    ".well-known/openid-configuration",
    "openapi.json",
    "swagger.json",
    "v2/api-docs",
    "v3/api-docs",
    "swagger-ui.html",
    "graphql",
    "api",
    "api/v1",
    "api/v2",
    "api/health",
    "health",
    "status",
    "metrics",
    "login",
    "auth/login",
    "register",
    "admin",
    "dashboard",
    "config.json",
    "manifest.json",
    ".git/HEAD",
    ".env",
    "actuator",
    "actuator/health",
    "api-docs",
    "swagger/index.html",
    "server-status",
)

STATIC_EXTENSIONS: tuple[str, ...] = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov",
)

INTERESTING_STATUS_CODES: set[int] = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}


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


def _is_static_asset(url: str) -> bool:
    path = (urlsplit(url).path or "").lower()
    return path.endswith(STATIC_EXTENSIONS)


def _load_wordlist(configured_path: str | None, max_entries: int) -> list[str]:
    max_entries = max(0, min(int(max_entries), 10000))
    if configured_path:
        wl_file = Path(configured_path)
        if wl_file.is_file():
            words: list[str] = []
            for raw_line in wl_file.read_text(encoding="utf-8", errors="replace").splitlines():
                item = raw_line.strip().lstrip("/")
                if (
                    item
                    and not item.startswith("#")
                    and "\\" not in item
                    and "\x00" not in item
                    and "://" not in item
                    and "?" not in item
                    and "#" not in item
                    and all(part not in {".", ".."} for part in item.split("/"))
                ):
                    words.append(item)
                if len(words) >= max_entries:
                    break
            if words:
                return list(dict.fromkeys(words))  # drop duplicates, keep order
    return list(BUILTIN_COMMON_PATHS[:max_entries])


def _run_katana(
    base_url: str,
    *,
    proxy_url: str,
    scope_engine,
    coverage,
    stage_id: str,
    check_dns: bool,
    max_threads: int,
    timeout_sec: int,
    governor,
) -> tuple[list[dict[str, Any]], str]:
    binary = shutil.which("katana")
    if not binary:
        return [], "katana is not installed"

    rate = min(max(1, int(getattr(governor, "requests_per_host_per_sec", 5))), 20)
    concurrency = max(1, min(int(max_threads), rate, 10))
    crawl_duration = max(10, min(int(timeout_sec), 180))

    cmd = [
        binary,
        "-u", base_url,
        "-d", "3",
        "-jc",
        "-c", str(concurrency),
        "-rl", str(rate),
        "-ct", f"{crawl_duration}s",
        "-fs", "fqdn",  # stay on this host; otherwise every host re-crawls the whole root domain
        "-proxy", proxy_url,
        "-silent",
        "-nc",
    ]
    hits: list[dict[str, Any]] = []
    try:
        proc = governor.run_process(
            cmd,
            timeout_sec=timeout_sec,
            env=_proxy_env(proxy_url),
        )
        tool_error = ""
        if proc.timed_out:
            tool_error = f"katana exceeded its time budget ({timeout_sec}s); partial results kept"
        elif proc.output_truncated:
            tool_error = "katana output exceeded the configured process-output limit; partial results kept"
        elif proc.returncode != 0:
            return [], f"katana exited with status {proc.returncode}"

        for raw_line in (proc.stdout or "").splitlines():
            candidate = raw_line.strip()
            if not candidate.startswith(("http://", "https://")) or _is_static_asset(candidate):
                continue
            decision = scope_engine.evaluate_url(candidate, check_dns=check_dns)
            if not decision.allowed:
                if coverage is not None:
                    coverage.record_out_of_scope(stage_id, candidate, decision.reason)
                continue
            hits.append({
                "url": decision.normalized_url,
                "status_code": None,  # katana output is URLs only: status is unverified, never assume 200
                "content_length": 0,
                "content_type": "",
                "source": "katana",
            })
    except ResourceLimitExceeded:
        return hits, f"katana stopped by scan-wide resource budget ({timeout_sec}s)"
    except OSError as exc:
        return hits, f"katana could not run ({type(exc).__name__})"
    return hits, tool_error


def _run_gau(
    root_domains: list[str],
    *,
    proxy_url: str,
    scope_engine,
    coverage,
    stage_id: str,
    check_dns: bool,
    max_urls: int,
    timeout_sec: int,
    governor,
) -> tuple[list[dict[str, Any]], str]:
    binary = shutil.which("gau")
    if not binary:
        return [], "gau is not installed"
    if not root_domains:
        return [], "No root domains configured for gau"

    cmd = [
        binary,
        "--subs",
        "--threads", "3",
        "--proxy", proxy_url,
    ]
    hits: list[dict[str, Any]] = []
    try:
        proc = governor.run_process(
            cmd,
            timeout_sec=timeout_sec,
            env=_proxy_env(proxy_url),
            input_text="\n".join(root_domains) + "\n",
        )
        tool_error = ""
        if proc.timed_out:
            tool_error = f"gau exceeded its time budget ({timeout_sec}s); partial results kept"
        elif proc.output_truncated:
            tool_error = "gau output exceeded the configured process-output limit; partial results kept"
        elif proc.returncode != 0:
            return [], f"gau exited with status {proc.returncode}"

        for raw_line in (proc.stdout or "").splitlines():
            if len(hits) >= max_urls:
                break
            candidate = raw_line.strip()
            if not candidate.startswith(("http://", "https://")) or _is_static_asset(candidate):
                continue
            decision = scope_engine.evaluate_url(candidate, check_dns=check_dns)
            if not decision.allowed:
                if coverage is not None:
                    coverage.record_out_of_scope(stage_id, candidate, decision.reason)
                continue
            hits.append({
                "url": decision.normalized_url,
                "status_code": None,
                "content_length": 0,
                "content_type": "",
                "source": "gau",
            })
    except ResourceLimitExceeded:
        return hits, f"gau stopped by scan-wide resource budget ({timeout_sec}s)"
    except OSError as exc:
        return hits, f"gau could not run ({type(exc).__name__})"
    return hits, tool_error


def _run_waybackurls(
    hosts: list[str],
    *,
    proxy_url: str,
    scope_engine,
    coverage,
    stage_id: str,
    check_dns: bool,
    max_urls: int,
    timeout_sec: int,
    governor,
) -> tuple[list[dict[str, Any]], str]:
    binary = shutil.which("waybackurls")
    if not binary:
        return [], "waybackurls is not installed"
    if not hosts:
        return [], "No hosts available for waybackurls"

    cmd = [binary, "-no-subs"] if len(hosts) > 1 else [binary]
    hits: list[dict[str, Any]] = []
    try:
        proc = governor.run_process(
            cmd,
            timeout_sec=timeout_sec,
            env=_proxy_env(proxy_url),
            input_text="\n".join(hosts) + "\n",
        )
        tool_error = ""
        if proc.timed_out:
            tool_error = f"waybackurls exceeded its time budget ({timeout_sec}s); partial results kept"
        elif proc.output_truncated:
            tool_error = "waybackurls output exceeded the configured process-output limit; partial results kept"
        elif proc.returncode != 0:
            return [], f"waybackurls exited with status {proc.returncode}"

        for raw_line in (proc.stdout or "").splitlines():
            if len(hits) >= max_urls:
                break
            candidate = raw_line.strip()
            if not candidate.startswith(("http://", "https://")) or _is_static_asset(candidate):
                continue
            decision = scope_engine.evaluate_url(candidate, check_dns=check_dns)
            if not decision.allowed:
                if coverage is not None:
                    coverage.record_out_of_scope(stage_id, candidate, decision.reason)
                continue
            hits.append({
                "url": decision.normalized_url,
                "status_code": None,
                "content_length": 0,
                "content_type": "",
                "source": "waybackurls",
            })
    except ResourceLimitExceeded:
        return hits, f"waybackurls stopped by scan-wide resource budget ({timeout_sec}s)"
    except OSError as exc:
        return hits, f"waybackurls could not run ({type(exc).__name__})"
    return hits, tool_error


def _run_feroxbuster(
    base_url: str,
    words: list[str],
    *,
    workspace,
    proxy_url: str,
    scope_engine,
    coverage,
    stage_id: str,
    check_dns: bool,
    max_threads: int,
    timeout_sec: int,
    governor,
) -> tuple[list[dict[str, Any]], str]:
    binary = shutil.which("feroxbuster")
    if not binary:
        return [], "feroxbuster is not installed"

    allowed_words = [
        word
        for word in words
        if scope_engine.evaluate_url(urljoin(base_url.rstrip("/") + "/", word), check_dns=check_dns).allowed
    ]
    if not allowed_words:
        return [], "No wordlist candidates remained in scope for feroxbuster"

    host_tag = hashlib.sha256(base_url.encode("utf-8")).hexdigest()[:12]
    wl_path = workspace.resolve_path(f"discovery/_ferox_wordlist_{host_tag}.txt")
    wl_path.write_text("\n".join(allowed_words) + "\n", encoding="utf-8")

    rate = min(max(1, int(getattr(governor, "requests_per_host_per_sec", 5))), 20)
    threads = max(1, min(int(max_threads), rate, 10))
    time_limit = max(15, min(int(timeout_sec), 300))

    cmd = [
        binary,
        "-u", base_url.rstrip("/"),
        "-w", str(wl_path),
        "--proxy", proxy_url,
        "--auto-tune",
        "--no-recursion",
        "--silent",
        "--json",
        "-t", str(threads),
        "--rate-limit", str(rate),
        "--time-limit", f"{time_limit}s",
    ]
    hits: list[dict[str, Any]] = []
    try:
        proc = governor.run_process(
            cmd,
            timeout_sec=timeout_sec,
            cwd=workspace.project_root,
            env=_proxy_env(proxy_url),
        )
        tool_error = ""
        if proc.timed_out:
            tool_error = f"feroxbuster exceeded its time budget ({timeout_sec}s); partial results kept"
        elif proc.output_truncated:
            tool_error = "feroxbuster output exceeded the configured process-output limit; partial results kept"
        elif proc.returncode != 0:
            return [], f"feroxbuster exited with status {proc.returncode}"

        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict) or obj.get("type") != "response":
                continue
            hit_url = str(obj.get("url", "")).strip()
            status = int(obj.get("status", 0))
            if hit_url and status in INTERESTING_STATUS_CODES:
                decision = scope_engine.evaluate_url(hit_url, check_dns=check_dns)
                if not decision.allowed:
                    if coverage is not None:
                        coverage.record_out_of_scope(stage_id, hit_url, decision.reason)
                    continue
                hits.append({
                    "url": decision.normalized_url,
                    "status_code": status,
                    "content_length": int(obj.get("content_length", 0)),
                    "content_type": str(obj.get("content_type", ""))[:256],
                    "source": "feroxbuster",
                })

        # Only claim coverage when the run was complete.
        if coverage is not None and not tool_error:
            for word in allowed_words:
                candidate = urljoin(base_url.rstrip("/") + "/", word)
                decision = scope_engine.evaluate_url(candidate, check_dns=check_dns)
                if decision.allowed:
                    coverage.record_target_tested(stage_id, decision.normalized_url)
    except ResourceLimitExceeded:
        return hits, f"feroxbuster stopped by scan-wide resource budget ({timeout_sec}s)"
    except OSError as exc:
        return hits, f"feroxbuster could not run ({type(exc).__name__})"
    finally:
        wl_path.unlink(missing_ok=True)
    return hits, tool_error


def _run_ffuf(
    base_url: str,
    words: list[str],
    *,
    workspace,
    scope_engine,
    coverage,
    stage_id: str,
    check_dns: bool,
    max_threads: int,
    timeout_sec: int = 180,
    governor=None,
) -> tuple[list[dict[str, Any]], int, str]:
    binary = shutil.which("ffuf")
    if not binary:
        return [], 0, "ffuf is not installed"

    proxy_url = os.environ.get("SECURITY_ANALYZER_PROXY", "").strip()
    enforced = os.environ.get("SECURITY_ANALYZER_EGRESS_ENFORCED") == "1"
    if not enforced or not _is_local_scope_proxy(proxy_url):
        return [], 0, "ffuf skipped: enforced local scope-aware proxy is unavailable"
    if governor is None:
        return [], 0, "ffuf skipped: shared ResourceGovernor is unavailable"

    allowed_words: list[str] = []
    skipped = 0
    for word in words:
        candidate = urljoin(base_url.rstrip("/") + "/", word)
        decision = scope_engine.evaluate_url(candidate, check_dns=check_dns)
        if decision.allowed:
            allowed_words.append(word)
        else:
            skipped += 1
            if coverage is not None:
                coverage.record_out_of_scope(stage_id, candidate, decision.reason)
    if not allowed_words:
        return [], skipped, "No wordlist candidates remained in scope"

    host_tag = hashlib.sha256(base_url.encode("utf-8")).hexdigest()[:12]
    wl_path = workspace.resolve_path(f"discovery/_ffuf_wordlist_{host_tag}.txt")
    wl_path.write_text("\n".join(allowed_words) + "\n", encoding="utf-8")
    fuzz_target = base_url.rstrip("/") + "/FUZZ"

    configured_rate = max(1, int(getattr(governor, "requests_per_host_per_sec", 5)))
    configured_concurrency = max(1, int(getattr(governor, "max_concurrent_requests", 1)))
    rate = min(configured_rate, 20)
    threads = max(1, min(int(max_threads), configured_concurrency, rate, 20))

    cmd = [
        binary,
        "-u", fuzz_target,
        "-w", str(wl_path),
        "-x", proxy_url,
        "-mc", "200,201,202,204,301,302,307,308,401,403,405",
        "-json",
        "-s",
        "-noninteractive",
        "-ac",  # auto-calibrate: filters wildcard / soft-404 responses (SPAs answer 200 to everything)
        "-t", str(threads),
        "-rate", str(rate),
    ]
    hits: list[dict[str, Any]] = []
    try:
        proc = governor.run_process(
            cmd,
            timeout_sec=timeout_sec,
            cwd=workspace.project_root,
        )
        tool_error = ""
        if proc.timed_out:
            tool_error = f"ffuf exceeded its time budget ({timeout_sec}s); partial results kept"
        elif proc.output_truncated:
            tool_error = "ffuf output exceeded the configured process-output limit; partial results kept"
        elif proc.returncode != 0:
            return [], skipped, f"ffuf exited with status {proc.returncode}"

        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    continue
                hit_url = str(obj.get("url", "")).strip()
                status = int(obj.get("status", 0))
                if hit_url and status:
                    decision = scope_engine.evaluate_url(hit_url, check_dns=check_dns)
                    if not decision.allowed:
                        if coverage is not None:
                            coverage.record_out_of_scope(stage_id, hit_url, decision.reason)
                        continue
                    hits.append({
                        "url": decision.normalized_url,
                        "status_code": status,
                        "content_length": int(obj.get("length", 0)),
                        "content_type": str(obj.get("content-type", ""))[:256],
                        "source": "ffuf",
                    })
            except (json.JSONDecodeError, ValueError, TypeError):
                continue

        if coverage is not None and not tool_error:
            for word in allowed_words:
                candidate = urljoin(base_url.rstrip("/") + "/", word)
                decision = scope_engine.evaluate_url(candidate, check_dns=check_dns)
                if decision.allowed:
                    coverage.record_target_tested(stage_id, decision.normalized_url)
    except ResourceLimitExceeded:
        return hits, skipped, f"ffuf stopped by scan-wide resource budget ({timeout_sec}s)"
    except OSError as exc:
        return hits, skipped, f"ffuf could not run ({type(exc).__name__})"
    finally:
        wl_path.unlink(missing_ok=True)

    return hits, skipped, tool_error


def _body_fingerprint(content: bytes | None) -> tuple[int, str]:
    data = content or b""
    return len(data), hashlib.sha1(data).hexdigest()[:16]


def _probe_soft_404_baseline(client, base_url: str, stage_id: str, check_dns_decision) -> dict[str, Any] | None:
    """Request a random, surely-nonexistent path. If it does not return 404/410, the site
    answers every path (SPA / catch-all) and identical-looking hits are false positives."""
    probe = urljoin(base_url.rstrip("/") + "/", f"sa-baseline-{uuid.uuid4().hex[:12]}")
    decision = check_dns_decision(probe)
    if not decision.allowed:
        return None
    try:
        resp = client.get(decision.normalized_url, stage_id=stage_id)
    except (ScopeViolationError, requests.RequestException, ResourceLimitExceeded):
        return None
    if resp.status_code in {404, 410}:
        return None
    length, digest = _body_fingerprint(resp.content)
    return {"status": resp.status_code, "length": length, "digest": digest}


def _is_soft_404(baseline: dict[str, Any] | None, status: int, content: bytes | None) -> bool:
    if baseline is None or status != baseline["status"]:
        return False
    length, digest = _body_fingerprint(content)
    if digest == baseline["digest"]:
        return True
    # Dynamic catch-all pages differ slightly (nonces, timestamps): compare size within 3%.
    base_len = baseline["length"]
    return base_len > 0 and abs(length - base_len) <= max(32, int(base_len * 0.03))


def run_directory_discovery(ctx: ExecutionContext, stage_def: StageDefinition) -> StageResult:
    """Stage 03: Discovers directories and API paths within authorized scope using TLS-verified probing."""
    subdomains_art = ctx.upstream_artifacts["domain_enumeration"]["discovery/subdomains.json"]
    hosts = subdomains_art.get("hosts", [])

    limits = ctx.config.get("limits", {})
    timeouts = ctx.config.get("timeouts", {})
    check_dns = bool(ctx.config.get("scope", {}).get("check_dns", True))
    max_paths = max(0, min(int(limits.get("max_directory_words", 250)), 10000))
    configured_wl = ctx.config.get("wordlists", {}).get("directories")
    words = _load_wordlist(configured_wl, max_paths)
    stage_deadline = time.monotonic() + max(1, int(timeouts.get("directory_stage_sec", 1800)))

    inventory = UnifiedEndpointInventory(ctx.workspace)
    existing_inventory_urls: set[str] = {
        ep.url
        for ep in inventory.get_endpoints(include_excluded=True, include_out_of_scope=True)
        if ep.url
    }
    normalizer = EndpointNormalizer(
        ctx.scope_engine,
        ctx.coverage,
        check_dns=check_dns,
    )
    client = ScopedHttpClient(
        ctx.scope_engine,
        coverage=ctx.coverage,
        connect_timeout=float(timeouts.get("http_connect_sec", 10)),
        read_timeout=float(timeouts.get("http_read_sec", 20)),
        max_redirects=int(timeouts.get("max_redirects", 5)),
        check_dns=check_dns,
        governor=ctx.resource_governor,
    )

    discovered_paths: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    tested_count = 0
    skipped_count = 0
    partial_reasons: list[str] = []
    tools_used: set[str] = set()

    def emit_progress(percent: int, message: str, completed: int = 0, total: int = 0) -> None:
        callback = getattr(ctx, "progress_callback", None)
        if callable(callback):
            try:
                callback({
                    "progress_percent": max(0, min(99, int(percent))),
                    "message": message[:180],
                    "completed": max(0, int(completed)),
                    "total": max(0, int(total)),
                })
            except Exception:
                pass  # Progress reporting must not interrupt scanning.

    ffuf_available = shutil.which("ffuf") is not None
    proxy_url = os.environ.get("SECURITY_ANALYZER_PROXY", "").strip()
    egress_enforced = (
        os.environ.get("SECURITY_ANALYZER_EGRESS_ENFORCED") == "1"
        and _is_local_scope_proxy(proxy_url)
    )
    if ffuf_available and not egress_enforced:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id,
            "ffuf_egress",
            "ffuf skipped: external egress enforcement is not confirmed; use scoped HTTP probes instead",
        )
    use_ffuf_globally = ffuf_available and egress_enforced
    request_failures = 0

    seed_parts = urlsplit(ctx.target)
    seed_scheme = seed_parts.scheme or "https"
    seed_port = seed_parts.port or (443 if seed_scheme == "https" else 80)
    max_stage_targets = max(1, int(limits.get("max_urls_per_stage", 2500)))
    dir_scan_timeout = int(timeouts.get("directory_scan_sec", 180))
    max_concurrency = int(limits.get("max_concurrent_requests", 10))

    raw_hits: list[dict[str, Any]] = []
    if configured_wl and not Path(str(configured_wl)).is_file():
        partial_reasons.append(
            f"Configured wordlist {configured_wl!r} was not found; only the small built-in path list was used"
        )

    # Passive archive URL discovery (gau & waybackurls) when external egress proxy & governor are active
    non_loopback_hosts = [
        str(entry.get("hostname", "")).strip().lower().rstrip(".")
        for entry in hosts
        if str(entry.get("hostname", "")).strip()
        and not _is_loopback_host(str(entry.get("hostname", "")).strip())
    ]
    if egress_enforced and ctx.resource_governor is not None and non_loopback_hosts:
        allowed_domains = sorted(ctx.scope_engine.policy.allowed_domains)
        if allowed_domains:
            gau_hits, gau_err = _run_gau(
                allowed_domains,
                proxy_url=proxy_url,
                scope_engine=ctx.scope_engine,
                coverage=ctx.coverage,
                stage_id=stage_def.stage_id,
                check_dns=check_dns,
                max_urls=max_stage_targets,
                timeout_sec=min(int(timeouts.get("gau_sec", min(dir_scan_timeout, 120))), max(1, int(stage_deadline - time.monotonic()))),
                governor=ctx.resource_governor,
            )
            if gau_hits:
                tools_used.add("gau")
                raw_hits.extend(gau_hits)
            if gau_err:
                ctx.coverage.record_skipped_check(stage_def.stage_id, "gau", gau_err)

        wb_hits, wb_err = _run_waybackurls(
            non_loopback_hosts,
            proxy_url=proxy_url,
            scope_engine=ctx.scope_engine,
            coverage=ctx.coverage,
            stage_id=stage_def.stage_id,
            check_dns=check_dns,
            max_urls=max_stage_targets,
            timeout_sec=min(int(timeouts.get("waybackurls_sec", min(dir_scan_timeout, 120))), max(1, int(stage_deadline - time.monotonic()))),
            governor=ctx.resource_governor,
        )
        if wb_hits:
            tools_used.add("waybackurls")
            raw_hits.extend(wb_hits)
        if wb_err:
            ctx.coverage.record_skipped_check(stage_def.stage_id, "waybackurls", wb_err)

    known_urls_so_far: set[str] = set(existing_inventory_urls) | {
        str(item.get("url", "")) for item in raw_hits if item.get("url")
    }

    processed_candidates = 0
    stop_all_hosts = False
    planned_candidates = max(1, min(max_stage_targets, len(hosts) * len(words)))
    emit_progress(0, f"Directory discovery starting: {len(hosts)} host(s), {len(words)} word(s)", 0, planned_candidates)

    for host_index, host_entry in enumerate(hosts, start=1):
        if time.monotonic() >= stage_deadline:
            partial_reasons.append(
                "Directory stage time budget (timeouts.directory_stage_sec) exhausted; remaining hosts were not scanned"
            )
            ctx.coverage.record_skipped_check(
                stage_def.stage_id, "directory_stage_budget", "stage time budget exhausted"
            )
            break
        remaining = max_stage_targets - processed_candidates
        if remaining <= 0:
            partial_reasons.append(
                f"Candidate processing capped at max_urls_per_stage ({max_stage_targets})"
            )
            break

        base_url = str(host_entry.get("url", "")).strip()
        if not base_url:
            hostname = str(host_entry.get("hostname", "")).strip().lower().rstrip(".")
            if not hostname:
                continue
            host_for_url = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
            default_port = 443 if seed_scheme == "https" else 80
            authority = host_for_url if seed_port == default_port else f"{host_for_url}:{seed_port}"
            base_url = f"{seed_scheme}://{authority}/"

        try:
            is_loopback_target = ipaddress.ip_address(urlsplit(base_url).hostname or "").is_loopback
        except ValueError:
            is_loopback_target = (urlsplit(base_url).hostname or "").strip().lower() == "localhost"
        use_external_active = egress_enforced and not is_loopback_target and ctx.resource_governor is not None
        use_ffuf = use_ffuf_globally and not is_loopback_target

        if use_external_active:
            katana_hits, katana_err = _run_katana(
                base_url,
                proxy_url=proxy_url,
                scope_engine=ctx.scope_engine,
                coverage=ctx.coverage,
                stage_id=stage_def.stage_id,
                check_dns=check_dns,
                max_threads=max_concurrency,
                timeout_sec=min(int(timeouts.get("katana_sec", min(dir_scan_timeout, 120))), max(1, int(stage_deadline - time.monotonic()))),
                governor=ctx.resource_governor,
            )
            if katana_hits:
                tools_used.add("katana")
                raw_hits.extend(katana_hits)
                known_urls_so_far.update(item["url"] for item in katana_hits if item.get("url"))
            if katana_err:
                ctx.coverage.record_skipped_check(stage_def.stage_id, "katana", katana_err)

        # Deduplicate wordlist paths against URLs already in inventory or passive/crawler hits
        deduped_words: list[str] = []
        for word in words:
            candidate_url = urljoin(base_url.rstrip("/") + "/", word)
            if candidate_url in known_urls_so_far:
                skipped_count += 1
                continue
            deduped_words.append(word)

        host_words = deduped_words[:remaining]
        processed_candidates += len(host_words)
        if not host_words:
            continue

        ferox_completed = False
        if use_external_active:
            ferox_hits, ferox_err = _run_feroxbuster(
                base_url,
                host_words,
                workspace=ctx.workspace,
                proxy_url=proxy_url,
                scope_engine=ctx.scope_engine,
                coverage=ctx.coverage,
                stage_id=stage_def.stage_id,
                check_dns=check_dns,
                max_threads=max_concurrency,
                timeout_sec=min(int(timeouts.get("feroxbuster_sec", dir_scan_timeout)), max(1, int(stage_deadline - time.monotonic()))),
                governor=ctx.resource_governor,
            )
            if not ferox_err:
                ferox_completed = True
                tools_used.add("feroxbuster")
                raw_hits.extend(ferox_hits)
                known_urls_so_far.update(item["url"] for item in ferox_hits if item.get("url"))
                tested_count += len(host_words)
            else:
                if ferox_hits:
                    tools_used.add("feroxbuster")
                    raw_hits.extend(ferox_hits)
                ctx.coverage.record_skipped_check(stage_def.stage_id, "feroxbuster", ferox_err)

        if ferox_completed:
            continue

        if use_ffuf:
            ffuf_hits, skipped, ffuf_error = _run_ffuf(
                base_url,
                host_words,
                workspace=ctx.workspace,
                scope_engine=ctx.scope_engine,
                coverage=ctx.coverage,
                stage_id=stage_def.stage_id,
                check_dns=check_dns,
                max_threads=max_concurrency,
                timeout_sec=min(dir_scan_timeout, max(1, int(stage_deadline - time.monotonic()))),
                governor=ctx.resource_governor,
            )
            raw_hits.extend(ffuf_hits)
            known_urls_so_far.update(item["url"] for item in ffuf_hits if item.get("url"))
            skipped_count += skipped
            if ffuf_error:
                skipped_count += max(0, len(host_words) - skipped)
                partial_reasons.append(ffuf_error)
            else:
                tools_used.add("ffuf")
                tested_count += max(0, len(host_words) - skipped)
        else:
            baseline = _probe_soft_404_baseline(
                client,
                base_url,
                stage_def.stage_id,
                lambda u: ctx.scope_engine.evaluate_url(u, check_dns=check_dns),
            )
            if baseline is not None:
                partial_reasons.append(
                    f"{base_url}: catch-all/soft-404 behaviour detected (random path returned HTTP "
                    f"{baseline['status']}); matching responses were ignored"
                )
            for word_index, word in enumerate(host_words):
                candidate = urljoin(base_url.rstrip("/") + "/", word)
                decision = ctx.scope_engine.evaluate_url(
                    candidate,
                    check_dns=check_dns,
                )
                if not decision.allowed:
                    skipped_count += 1
                    ctx.coverage.record_out_of_scope(
                        stage_def.stage_id, candidate, decision.reason
                    )
                    continue
                try:
                    response = client.get(
                        decision.normalized_url,
                        stage_id=stage_def.stage_id,
                    )
                except ResourceLimitExceeded as exc:
                    remaining_for_host = len(host_words) - word_index
                    skipped_count += remaining_for_host
                    partial_reasons.append(
                        f"Directory probing stopped by scan-wide resource governor: {exc}"
                    )
                    ctx.coverage.record_skipped_check(
                        stage_def.stage_id, "http_resource_budget", str(exc)
                    )
                    stop_all_hosts = True
                    break
                except (ScopeViolationError, requests.RequestException) as exc:
                    tested_count += 1
                    request_failures += 1
                    ctx.coverage.record_request_failure(
                        stage_def.stage_id,
                        decision.normalized_url,
                        type(exc).__name__,
                    )
                    continue

                tested_count += 1
                known_urls_so_far.add(decision.normalized_url)
                ctx.coverage.record_target_tested(
                    stage_def.stage_id,
                    decision.normalized_url,
                    status_code=response.status_code,
                )
                if _is_soft_404(baseline, response.status_code, response.content):
                    continue
                if response.status_code in INTERESTING_STATUS_CODES:
                    raw_hits.append({
                        "url": decision.normalized_url,
                        "status_code": response.status_code,
                        "content_length": len(response.content or b""),
                        "content_type": response.headers.get("Content-Type", ""),
                        "source": "scoped_http_dir_probe",
                    })

        emit_progress(
            min(95, int(host_index * 95 / max(1, len(hosts)))),
            f"Directory discovery completed host {host_index}/{len(hosts)}",
            host_index,
            len(hosts),
        )
        if stop_all_hosts:
            break

    for hit in raw_hits:
        ep = normalizer.normalize(
            hit["url"],
            method="GET",
            source=hit["source"],
            stage_id=stage_def.stage_id,
            status_code=hit["status_code"],
            content_type=hit.get("content_type", ""),
            reachable=True if hit["status_code"] is not None else None,
            evidence_ref="discovery/directories.json",
        )
        if ep is None:
            skipped_count += 1
            continue
        inventory.upsert_endpoint(ep)
        if ep.url in seen_urls:
            # Same URL from several tools: keep the entry, but prefer one that has a verified status.
            for existing in discovered_paths:
                if existing["url"] == ep.url and existing["status_code"] is None and hit["status_code"] is not None:
                    existing["status_code"] = hit["status_code"]
                    existing["content_length"] = hit.get("content_length", 0)
                    existing["content_type"] = hit.get("content_type", "")
                    existing["source"] = hit["source"]
                    break
        if ep.url not in seen_urls:
            seen_urls.add(ep.url)
            discovered_paths.append({
                "endpoint_id": ep.endpoint_id,
                "url": ep.url,
                "path": ep.path,
                "status_code": hit["status_code"],
                "content_length": hit.get("content_length", 0),
                "content_type": hit.get("content_type", ""),
                "source": hit["source"],
            })

    if not hosts:
        partial_reasons.append("No upstream hosts were available for directory discovery")
    if not words:
        partial_reasons.append("Directory wordlist is empty; no path targets were tested")

    if not ffuf_available:
        partial_reasons.append("ffuf not installed; used built-in scoped Python path probe")
        ctx.coverage.record_skipped_check(
            stage_def.stage_id,
            "ffuf",
            "ffuf binary not installed; fell back to bounded scoped HTTP directory probe",
        )
    elif not egress_enforced:
        partial_reasons.append("ffuf skipped because external egress enforcement is not confirmed")
    elif any(
        _is_loopback_host(
            (urlsplit(str(entry.get("url", ""))).hostname or str(entry.get("hostname", ""))).strip()
        )
        for entry in hosts
    ):
        ctx.coverage.record_skipped_check(
            stage_def.stage_id,
            "ffuf",
            "Skipped external fuzzer for loopback target; used scoped HTTP probes",
        )

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "wordlist_size": len(words),
        "tools_used": sorted(tools_used),
        "request_failures": request_failures,
        "paths": discovered_paths,
        "notes": partial_reasons,
    }
    ctx.workspace.write_json_atomic("discovery/directories.json", payload)
    inventory.save(stage_id=stage_def.stage_id)

    # A Python fallback is useful coverage, but it does not make the optional
    # FFUF capability available. Keep the stage PARTIAL so reports disclose the
    # missing scanner rather than presenting the stage as fully complete.
    status = (
        StageStatus.PARTIAL
        if partial_reasons or request_failures or tested_count == 0
        else StageStatus.SUCCESS
    )
    deterministic_optional_fallback = (
        (not ffuf_available or not egress_enforced)
        and request_failures == 0
        and bool(hosts)
        and bool(words)
        and not any("ffuf exited" in reason or "ffuf timed out" in reason for reason in partial_reasons)
    )
    emit_progress(
        100,
        f"Directory discovery finished: {len(discovered_paths)} in-scope path(s) across {len(hosts)} host(s)",
        planned_candidates,
        planned_candidates,
    )
    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=f"Discovered {len(discovered_paths)} in-scope path(s) across {len(hosts)} host(s)",
        artifacts=["discovery/directories.json", "inventory/unified_endpoints.json", "inventory/contributions/directory_discovery.json"],
        reusable_partial=(status == StageStatus.PARTIAL and deterministic_optional_fallback),
        metrics={
            "targets_total": tested_count + skipped_count,
            "targets_tested": tested_count,
            "targets_skipped": skipped_count,
        },
    )