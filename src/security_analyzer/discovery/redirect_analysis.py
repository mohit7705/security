from __future__ import annotations

import ipaddress
import json
import os
import shutil
import tempfile
import time
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

CATCHALL_PROBE_WORDS: tuple[str, ...] = (
    "zzz-notreal-probe-1-xyzabc",
    "zzz-notreal-probe-2-xyzabc",
    "zzz-notreal-probe-3-xyzabc",
)


def _is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.strip().lower() == "localhost"


def _is_local_scope_proxy(proxy_url: str) -> bool:
    """Compatibility wrapper for the shared trusted-proxy policy."""
    return is_trusted_scope_proxy(proxy_url)


def _detect_catchall_origins_ffuf(
    origins: list[str],
    *,
    proxy_url: str,
    scope_engine,
    check_dns: bool,
    timeout_sec: int,
    governor,
) -> tuple[list[str], str]:
    binary = shutil.which("ffuf")
    if not binary:
        return [], "ffuf is not installed"
    if not origins:
        return [], "No origins available for ffuf catch-all calibration"

    catchall: list[str] = []
    err = ""
    max_origins = 25
    if len(origins) > max_origins:
        err = f"ffuf catch-all calibration limited to {max_origins} of {len(origins)} origin(s)"
        origins = origins[:max_origins]
    ffuf_deadline = time.monotonic() + 300
    rate = min(max(1, int(getattr(governor, "requests_per_host_per_sec", 5))), 20)

    with tempfile.TemporaryDirectory(prefix="security-analyzer-ffuf-catchall-") as tmp_dir:
        wl_path = Path(tmp_dir) / "probe_words.txt"
        wl_path.write_text("\n".join(CATCHALL_PROBE_WORDS) + "\n", encoding="utf-8")

        for idx, origin in enumerate(origins):
            if time.monotonic() >= ffuf_deadline:
                err = "ffuf catch-all calibration time budget reached; remaining origin(s) not checked"
                break
            decision = scope_engine.evaluate_url(origin.rstrip("/") + "/", check_dns=check_dns)
            if not decision.allowed:
                continue
            out_json = Path(tmp_dir) / f"ffuf_{idx}.json"
            cmd = [
                binary,
                "-u", origin.rstrip("/") + "/FUZZ",
                "-w", str(wl_path),
                "-x", proxy_url,
                "-mc", "200-299",
                "-t", "3",
                "-rate", str(rate),
                "-of", "json",
                "-o", str(out_json),
                "-s",
                "-noninteractive",
            ]
            try:
                proc = governor.run_process(cmd, timeout_sec=min(timeout_sec, 60))
            except (ResourceLimitExceeded, OSError) as exc:
                err = f"ffuf catch-all calibration stopped ({type(exc).__name__})"
                break
            if proc.timed_out or not out_json.is_file():
                continue
            try:
                parsed = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
                hits = parsed.get("results") or []
                if len(hits) >= 2:
                    catchall.append(origin)
            except json.JSONDecodeError:
                continue

    return sorted(catchall), err


def _safe_url(raw_url: str, normalizer: EndpointNormalizer, stage_id: str) -> str:
    endpoint = normalizer.normalize(raw_url, stage_id=stage_id)
    if endpoint is not None:
        return endpoint.url
    try:
        parsed = urlsplit(raw_url)
        if parsed.scheme and parsed.hostname:
            host = parsed.hostname.lower()
            authority = f"[{host}]" if ":" in host else host
            if parsed.port:
                authority += f":{parsed.port}"
            return f"{parsed.scheme.lower()}://{authority}{parsed.path or '/'}"
    except ValueError:
        pass
    return "[INVALID_OR_OUT_OF_SCOPE_URL]"


def run_redirect_analysis(ctx: ExecutionContext, stage_def: StageDefinition) -> StageResult:
    """Stage 06: Traces redirect chains, blocks out-of-scope hops, and finalizes unified_endpoints.json."""
    probes_art = ctx.upstream_artifacts["http_probing"]["discovery/http_probes.json"]
    probes = probes_art.get("probes", [])

    inventory = UnifiedEndpointInventory(ctx.workspace)
    check_dns = bool(ctx.config.get("scope", {}).get("check_dns", False))
    normalizer = EndpointNormalizer(
        ctx.scope_engine,
        ctx.coverage,
        check_dns=check_dns,
    )
    timeouts = ctx.config.get("timeouts", {})
    max_hops = max(0, min(int(timeouts.get("max_redirects", 5)), 20))

    client = ScopedHttpClient(
        ctx.scope_engine,
        coverage=ctx.coverage,
        connect_timeout=float(timeouts.get("http_connect_sec", 10)),
        read_timeout=float(timeouts.get("http_read_sec", 20)),
        max_redirects=0,  # Step manually so every hop is recorded and scope-checked
        check_dns=check_dns,
        governor=ctx.resource_governor,
    )

    redirect_probes = [
        p for p in probes if p.get("reachable") and int(p.get("status_code", 0)) in {301, 302, 303, 307, 308}
    ]

    chains: list[dict[str, Any]] = []
    tested = 0
    blocked_hops = 0
    request_failures = 0
    oversize = 0
    unprocessed = 0
    budget_exhausted = False
    hop_cache: dict[str, tuple[int, str, str]] = {}  # chains share hops (http->https->/login)
    deadline = time.monotonic() + float(timeouts.get("redirect_stage_sec", 600))

    for item in redirect_probes:
        if budget_exhausted or time.monotonic() >= deadline:
            unprocessed += 1
            continue
        start_url = str(item["url"])
        current_url = start_url
        hops: list[dict[str, Any]] = []
        terminated_reason = "completed"
        visited: set[str] = set()

        for hop_idx in range(max_hops + 1):
            if current_url in visited:
                terminated_reason = "redirect_loop"
                break
            visited.add(current_url)

            decision = ctx.scope_engine.evaluate_url(current_url, check_dns=check_dns)
            if not decision.allowed:
                terminated_reason = f"blocked_out_of_scope: {decision.reason}"
                blocked_hops += 1
                ctx.coverage.record_out_of_scope(stage_def.stage_id, current_url, decision.reason)
                hops.append({
                    "hop": hop_idx,
                    "url": _safe_url(current_url, normalizer, stage_def.stage_id),
                    "in_scope": False,
                    "blocked": True,
                })
                break

            cache_key = decision.normalized_url
            cached = hop_cache.get(cache_key)
            if cached is None:
                try:
                    resp = client.get(
                        decision.normalized_url,
                        stage_id=stage_def.stage_id,
                        allow_redirects=False,
                    )
                except ResourceLimitExceeded as exc:
                    # Same exception type for one oversized body and for the scan-wide budget.
                    if "Response body" in str(exc):
                        oversize += 1
                        terminated_reason = "response_too_large"
                    else:
                        budget_exhausted = True
                        terminated_reason = "resource_budget_exhausted"
                        ctx.coverage.record_skipped_check(stage_def.stage_id, "http_resource_budget", str(exc))
                    break
                except (ScopeViolationError, requests.RequestException) as exc:
                    request_failures += 1
                    terminated_reason = f"request_error: {type(exc).__name__}"
                    ctx.coverage.record_request_failure(stage_def.stage_id, decision.normalized_url, type(exc).__name__)
                    break

                tested += 1
                ctx.coverage.record_target_tested(stage_def.stage_id, decision.normalized_url, status_code=resp.status_code)
                cached = (
                    int(resp.status_code),
                    resp.headers.get("Location", "").strip(),
                    resp.headers.get("Content-Type", ""),
                )
                hop_cache[cache_key] = cached
            status_code, location, content_type = cached
            safe_location = (
                _safe_url(urljoin(decision.normalized_url, location), normalizer, stage_def.stage_id)
                if location
                else ""
            )
            hops.append(
                {
                    "hop": hop_idx,
                    "url": _safe_url(decision.normalized_url, normalizer, stage_def.stage_id),
                    "status_code": status_code,
                    "location": safe_location,
                    "in_scope": True,
                }
            )

            if status_code not in {301, 302, 303, 307, 308} or not location:
                landing_ep = normalizer.normalize(
                    decision.normalized_url,
                    method="GET",
                    source="redirect_analysis",
                    stage_id=stage_def.stage_id,
                    status_code=status_code,
                    content_type=content_type,
                    reachable=True,
                    evidence_ref="discovery/redirects.json",
                )
                if landing_ep is not None:
                    inventory.upsert_endpoint(landing_ep)
                break

            current_url = urljoin(decision.normalized_url, location)
        else:
            terminated_reason = f"max_redirects_exceeded ({max_hops})"

        start_host = (urlsplit(start_url).hostname or "").lower()
        # On an aborted chain the real destination is the unreached target, not the last source hop.
        if terminated_reason == "completed" and hops:
            final_url = hops[-1]["url"]
        else:
            final_url = _safe_url(current_url, normalizer, stage_def.stage_id)
        final_host = (urlsplit(final_url).hostname or "").lower()
        scheme_downgrade = (
            urlsplit(start_url).scheme == "https" and final_url.lower().startswith("http://")
        )

        chains.append(
            {
                "start_url": start_url,
                "final_url": final_url,
                "cross_host": start_host != final_host,
                "scheme_downgrade": scheme_downgrade,
                "hop_count": len(hops),
                "terminated_reason": terminated_reason,
                "hops": hops,
            }
        )

    catchall_hosts: list[str] = []
    proxy_url = os.environ.get("SECURITY_ANALYZER_PROXY", "").strip()
    egress_enforced = (
        os.environ.get("SECURITY_ANALYZER_EGRESS_ENFORCED") == "1"
        and _is_local_scope_proxy(proxy_url)
    )
    if not egress_enforced:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "ffuf_catchall", "scoped egress proxy is not enforced; catch-all calibration skipped"
        )
    if egress_enforced and ctx.resource_governor is not None:
        candidate_origins = sorted({
            f"{urlsplit(str(p['url'])).scheme}://{urlsplit(str(p['url'])).netloc}"
            for p in probes
            if p.get("reachable")
            and urlsplit(str(p.get("url", ""))).scheme in {"http", "https"}
            and urlsplit(str(p.get("url", ""))).hostname
            and not _is_loopback_host(urlsplit(str(p.get("url", ""))).hostname or "")
        })
        catchall_hosts, ffuf_err = _detect_catchall_origins_ffuf(
            candidate_origins,
            proxy_url=proxy_url,
            scope_engine=ctx.scope_engine,
            check_dns=check_dns,
            timeout_sec=int(timeouts.get("directory_scan_sec", 180)),
            governor=ctx.resource_governor,
        )
        if ffuf_err:
            ctx.coverage.record_skipped_check(stage_def.stage_id, "ffuf_catchall", ffuf_err)

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "catchall_hosts": catchall_hosts,
        "unprocessed_chains": unprocessed,
        "oversize_skipped": oversize,
        "chains": chains,
    }
    ctx.workspace.write_json_atomic("discovery/redirects.json", payload)
    inv_payload = inventory.save(stage_id=stage_def.stage_id)

    if unprocessed:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "redirect_stage_budget",
            f"{unprocessed} redirect chain(s) not traced (stage time budget or resource budget reached)",
        )
    attempted = tested + request_failures
    fail_ratio = (request_failures / attempted) if attempted else 0.0
    max_fail_ratio = float(ctx.config.get("limits", {}).get("redirect_max_failure_ratio", 0.5))
    status = (
        StageStatus.PARTIAL
        if not probes
        or budget_exhausted
        or unprocessed
        or (redirect_probes and tested == 0 and blocked_hops == 0)
        or fail_ratio > max_fail_ratio
        else StageStatus.SUCCESS
    )
    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Analyzed {len(chains)} redirect chain(s) ({blocked_hops} out-of-scope hop(s) blocked, "
            f"{request_failures} request failure(s)"
            + (f", {unprocessed} not traced" if unprocessed else "")
            + f"); unified inventory has "
            f"{inv_payload['summary']['total_endpoints']} endpoint(s)"
        ),
        artifacts=["discovery/redirects.json", "inventory/unified_endpoints.json", "inventory/contributions/redirect_analysis.json"],
        metrics={
            "targets_total": len(redirect_probes),
            "targets_tested": tested,
            "targets_skipped": blocked_hops + request_failures + unprocessed + oversize,
            "unprocessed_chains": unprocessed,
        },
    )