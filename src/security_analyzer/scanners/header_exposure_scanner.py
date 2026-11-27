from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import requests

from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.utils.http_client import ScopedHttpClient

RECOMMENDED_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("strict-transport-security", "MEDIUM", "Missing Strict-Transport-Security (HSTS) header"),
    ("content-security-policy", "MEDIUM", "Missing Content-Security-Policy (CSP) header"),
    ("x-content-type-options", "LOW", "Missing X-Content-Type-Options: nosniff header"),
    ("referrer-policy", "INFO", "Missing Referrer-Policy header"),
)

PROMETHEUS_HELP_RE = re.compile(r"(?m)^#\s*HELP\s+([a-zA-Z_:][a-zA-Z0-9_:]*)\b")
PROMETHEUS_TYPE_RE = re.compile(r"(?m)^#\s*TYPE\s+([a-zA-Z_:][a-zA-Z0-9_:]*)\s+(counter|gauge|histogram|summary|untyped)\b")


def _detect_prometheus_metrics(response: requests.Response) -> list[str]:
    """Return matched metric names if the HTTP 200 response exposes Prometheus metrics."""
    if response.status_code != 200:
        return []
    ctype = (response.headers.get("Content-Type") or "").lower()
    if ctype and not any(
        token in ctype
        for token in ("text/plain", "openmetrics", "text/", "application/octet-stream")
    ):
        return []

    sample = (response.text or "")[:16384]
    help_matches = PROMETHEUS_HELP_RE.findall(sample)
    type_matches = [name for name, _metric_type in PROMETHEUS_TYPE_RE.findall(sample)]
    if not help_matches or not type_matches:
        return []

    ordered_unique: list[str] = []
    for name in [*help_matches, *type_matches]:
        if name not in ordered_unique:
            ordered_unique.append(name)
        if len(ordered_unique) >= 5:
            break
    return ordered_unique


VERSION_RE = re.compile(r"\d+(?:\.\d+)+")


def _origin_key(ep) -> tuple[str, str, int | None]:
    return (ep.scheme, ep.hostname, getattr(ep, "port", None))


def _select_endpoints(reachable: list, limit: int) -> list:
    """/metrics first, then round-robin across origins (HTML/200 first) so one busy host
    cannot consume the whole review quota."""
    def is_metrics(ep) -> bool:
        return (urlsplit(ep.canonical_url or ep.url).path or "").rstrip("/").endswith("/metrics")

    def priority(ep) -> int:
        ctype = (getattr(ep, "content_type", "") or "").lower()
        return 0 if "html" in ctype else 1

    selected = [ep for ep in reachable if is_metrics(ep)][:limit]
    groups: dict[tuple, list] = {}
    for ep in sorted((e for e in reachable if not is_metrics(e)), key=priority):
        groups.setdefault(_origin_key(ep), []).append(ep)
    queues = list(groups.values())
    while len(selected) < limit and any(queues):
        for queue in queues:
            if queue and len(selected) < limit:
                selected.append(queue.pop(0))
    return selected


def run_security_review(
    ctx: ExecutionContext,
    stage_def: StageDefinition,
) -> StageResult:
    """Audit response headers, CORS, and exposed Prometheus metrics with bounded GET requests."""
    inventory = UnifiedEndpointInventory(ctx.workspace)
    timeouts = ctx.config.get("timeouts", {})
    limits = ctx.config.get("limits", {})
    max_endpoints = min(
        int(limits.get("max_urls_per_stage", 2500)),
        int(limits.get("max_header_review_endpoints", 50)),
    )

    client = ScopedHttpClient(
        ctx.scope_engine,
        coverage=ctx.coverage,
        connect_timeout=float(timeouts.get("http_connect_sec", 10)),
        read_timeout=float(timeouts.get("http_read_sec", 20)),
        max_redirects=int(timeouts.get("max_redirects", 5)),
        check_dns=bool(ctx.config.get("scope", {}).get("check_dns", True)),
        governor=ctx.resource_governor,
    )

    reachable = inventory.get_endpoints(
        reachable_only=True,
        include_excluded=False,
    )
    if not reachable:
        reachable = inventory.get_endpoints(
            include_excluded=False,
        )

    selected = _select_endpoints(reachable, max_endpoints)
    deadline = time.monotonic() + float(timeouts.get("security_review_stage_sec", 300))
    oversize = 0
    budget_stopped = False

    findings: list[dict[str, Any]] = []
    tested = 0
    request_failures = 0
    notes: list[str] = []

    for endpoint in selected:
        if time.monotonic() >= deadline:
            notes.append("Header review stopped: stage time budget reached")
            budget_stopped = True
            break
        try:
            response = client.get(
                endpoint.canonical_url or endpoint.url,
                stage_id=stage_def.stage_id,
                headers={"Origin": "https://untrusted-origin.example"},
            )
        except ResourceLimitExceeded as exc:
            # Same exception type for one oversized body and for the scan-wide budget.
            if "Response body" in str(exc):
                oversize += 1
                ctx.coverage.record_request_failure(stage_def.stage_id, endpoint.url, "ResponseTooLarge")
                continue
            budget_stopped = True
            notes.append(f"Header review stopped by scan-wide resource governor: {exc}")
            ctx.coverage.record_skipped_check(
                stage_def.stage_id,
                "http_resource_budget",
                str(exc),
            )
            break
        except (ScopeViolationError, requests.RequestException) as exc:
            request_failures += 1
            ctx.coverage.record_request_failure(
                stage_def.stage_id,
                endpoint.url,
                type(exc).__name__,
            )
            continue

        tested += 1
        ctx.coverage.record_target_tested(
            stage_def.stage_id,
            endpoint.url,
            status_code=response.status_code,
        )
        lower_headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        is_html = "html" in (response.headers.get("Content-Type") or "").lower()
        html_only = {"content-security-policy", "referrer-policy"}

        for header_name, severity, title in RECOMMENDED_HEADERS:
            if (
                header_name == "strict-transport-security"
                and endpoint.scheme != "https"
            ):
                continue
            if header_name in html_only and not is_html:
                continue  # CSP/Referrer-Policy matter for documents, not JSON/images/assets
            if header_name not in lower_headers:
                findings.append({
                    "category": f"missing_{header_name.replace('-', '_')}",
                    "severity": severity,
                    "url": endpoint.url,
                    "endpoint_id": endpoint.endpoint_id,
                    "title": title,
                    "evidence": (
                        f"HTTP {response.status_code} response lacked "
                        f"{header_name}"
                    ),
                })

        # Clickjacking protection can be supplied by either header.
        csp = lower_headers.get(
            "content-security-policy",
            "",
        ).lower()
        if (
            is_html
            and "x-frame-options" not in lower_headers
            and "frame-ancestors" not in csp
        ):
            findings.append({
                "category": "missing_clickjacking_protection",
                "severity": "LOW",
                "url": endpoint.url,
                "endpoint_id": endpoint.endpoint_id,
                "title": (
                    "Missing clickjacking protection "
                    "(X-Frame-Options or CSP frame-ancestors)"
                ),
                "evidence": (
                    f"HTTP {response.status_code} response defined neither "
                    "X-Frame-Options nor frame-ancestors"
                ),
            })

        # Reflection of a supplied, unrelated origin is stronger evidence
        # than wildcard ACAO. Browsers reject wildcard ACAO with credentials,
        # so that combination is not reported as a working credentialed CORS
        # bypass by this passive check.
        allow_origin = lower_headers.get(
            "access-control-allow-origin",
            "",
        ).strip()
        allow_credentials = lower_headers.get(
            "access-control-allow-credentials",
            "",
        ).strip().lower()

        if allow_origin == "https://untrusted-origin.example":
            findings.append({
                "category": "cors_origin_reflection",
                "severity": (
                    "HIGH" if allow_credentials == "true" else "MEDIUM"
                ),
                "url": endpoint.url,
                "endpoint_id": endpoint.endpoint_id,
                "title": "CORS reflects an unrelated Origin header",
                "evidence": (
                    f"Access-Control-Allow-Origin: {allow_origin}; "
                    "Access-Control-Allow-Credentials: "
                    f"{allow_credentials or 'unset'}"
                ),
            })

        for header_name in (
            "server",
            "x-powered-by",
            "x-aspnet-version",
        ):
            value = (response.headers.get(header_name) or "").strip()
            if value and VERSION_RE.search(value):
                findings.append({
                    "category": "technology_version_disclosure",
                    "severity": "INFO",
                    "url": endpoint.url,
                    "endpoint_id": endpoint.endpoint_id,
                    "title": (
                        f"Server/framework version disclosed via {header_name}"
                    ),
                    "evidence": f"{header_name}: {value[:120]}",
                })

        exposed_metrics = _detect_prometheus_metrics(response)
        if exposed_metrics:
            findings.append({
                "category": "exposed_prometheus_metrics",
                "severity": "MEDIUM",
                "url": endpoint.url,
                "endpoint_id": endpoint.endpoint_id,
                "title": "Unauthenticated Prometheus metrics endpoint exposed",
                "evidence": (
                    f"HTTP 200 response exposed Prometheus exposition metrics "
                    f"({', '.join(exposed_metrics)})"
                ),
            })

    if len(reachable) > len(selected):
        notes.append(
            f"Endpoint review capped at {len(selected)} of {len(reachable)} candidates"
        )

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "endpoints_reviewed": tested,
        "oversize_skipped": oversize,
        "findings": findings,
        "notes": notes,
    }
    ctx.workspace.write_json_atomic(
        "analysis/security_headers.json",
        payload,
    )

    # The endpoint cap is a deliberate limit (noted above), not a failure.
    skipped = max(0, len(reachable) - tested)
    attempted = tested + request_failures
    fail_ratio = (request_failures / attempted) if attempted else 0.0
    max_fail_ratio = float(limits.get("header_review_max_failure_ratio", 0.5))
    status = (
        StageStatus.PARTIAL
        if not selected or tested == 0 or budget_stopped or fail_ratio > max_fail_ratio
        else StageStatus.SUCCESS
    )
    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Reviewed {tested}/{len(selected)} selected endpoint(s), "
            f"{request_failures} request failure(s), and recorded "
            f"{len(findings)} header/CORS/metrics observation(s)"
            + (f"; {'; '.join(notes)}" if notes else "")
        ),
        artifacts=["analysis/security_headers.json"],
        metrics={
            "targets_total": len(reachable),
            "targets_tested": tested,
            "targets_skipped": skipped,
        },
    )