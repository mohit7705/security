from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.egress import is_trusted_scope_proxy
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.core.nuclei_templates import resolve_nuclei_templates
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.models.finding import Severity

_SECRET_PATTERN = re.compile(
    r"(?i)(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|secret|password)\s*[:=]\s*([^\r\n\"'&;]+)"
)
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_JWT_PATTERN = re.compile(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_SENSITIVE_QUERY_NAMES = {
    "token", "access_token", "refresh_token", "id_token", "secret",
    "password", "passwd", "api_key", "apikey", "authorization",
    "session", "sessionid", "sid", "jwt", "code", "email", "mail",
    "phone", "mobile", "user_id", "userid", "account_id", "customer_id",
}


def _redact_text(text: str, limit: int = 500) -> str:
    if not text:
        return ""
    scrubbed = _SECRET_PATTERN.sub(r"\1: [REDACTED]", str(text))
    scrubbed = _BEARER_PATTERN.sub("Bearer [REDACTED]", scrubbed)
    scrubbed = _JWT_PATTERN.sub("[REDACTED_JWT]", scrubbed)
    return scrubbed[:limit]


def _redact_url(raw_url: str) -> str:
    """Remove URL credentials and sensitive query values before persisting evidence."""
    try:
        parsed = urlsplit(raw_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        host = parsed.hostname.lower().rstrip(".")
        authority = f"[{host}]" if ":" in host else host
        port = parsed.port
        if port:
            authority += f":{port}"
        pairs = []
        for key, value in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=256):
            normalized = re.sub(r"[^a-z0-9_]", "", key.lower())
            pairs.append((key[:128], "[REDACTED]" if normalized in _SENSITIVE_QUERY_NAMES else value[:120]))

        safe_segments = []
        for segment in (parsed.path or "/").split("/"):
            decoded = unquote(segment)
            if (
                re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", decoded)
                or re.fullmatch(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", decoded)
            ):
                safe_segments.append(quote("[REDACTED]", safe=""))
            else:
                safe_segments.append(segment[:256])

        return urlunsplit((
            parsed.scheme.lower(),
            authority,
            "/".join(safe_segments) or "/",
            urlencode(pairs),
            "",
        ))[:2048]
    except (TypeError, ValueError):
        return ""


def _map_severity(raw_sev: str) -> str:
    upper = (raw_sev or "info").strip().upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL.value,
        "HIGH": Severity.HIGH.value,
        "MEDIUM": Severity.MEDIUM.value,
        "LOW": Severity.LOW.value,
        "INFO": Severity.INFO.value,
    }
    return mapping.get(upper, Severity.INFO.value)


def _is_ip_allowed_by_scope(ctx: ExecutionContext, raw_ip: str) -> bool:
    if not raw_ip:
        return True
    try:
        ip_obj = ipaddress.ip_address(raw_ip.strip())
    except ValueError:
        return False
    allowed, _ = ctx.scope_engine._is_ip_permitted(ip_obj)
    return allowed


def _validated_local_proxy(proxy_url: str) -> bool:
    """Only accept the approved loopback or Compose scope-aware proxy."""
    return is_trusted_scope_proxy(proxy_url)


def _write_empty_result(ctx: ExecutionContext, stage_def: StageDefinition, reason: str,
                        status: StageStatus = StageStatus.PARTIAL) -> StageResult:
    ctx.workspace.write_json_atomic(
        "analysis/nuclei_findings.json",
        {
            "schema_version": "1.0",
            "scan_id": ctx.workspace.scan_id,
            "stage_id": stage_def.stage_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "targets_scanned": [],
            "findings": [],
            "notes": [reason],
        },
    )
    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=reason,
        artifacts=["analysis/nuclei_findings.json"],
        metrics={"targets_total": 0, "targets_tested": 0, "targets_skipped": 0},
    )


def run_nuclei_assessment(ctx: ExecutionContext, stage_def: StageDefinition) -> StageResult:
    binary = shutil.which("nuclei")
    if not binary:
        reason = "nuclei binary is not installed; skipping template vulnerability scan"
        ctx.coverage.record_skipped_check(stage_def.stage_id, "nuclei", reason)
        return _write_empty_result(ctx, stage_def, reason, StageStatus.SKIPPED)

    proxy_url = os.environ.get("SECURITY_ANALYZER_PROXY", "").strip()
    egress_enforced = os.environ.get("SECURITY_ANALYZER_EGRESS_ENFORCED") == "1"
    if not egress_enforced or not _validated_local_proxy(proxy_url):
        reason = "Nuclei skipped: enforced local scope-aware egress proxy is not configured"
        ctx.coverage.record_skipped_check(stage_def.stage_id, "nuclei_egress", reason)
        return _write_empty_result(ctx, stage_def, reason)

    if ctx.resource_governor is None:
        reason = "Nuclei skipped: shared ResourceGovernor is unavailable; unbounded subprocess execution is forbidden"
        ctx.coverage.record_skipped_check(stage_def.stage_id, "nuclei_resource_governor", reason)
        return _write_empty_result(ctx, stage_def, reason)

    if ctx.scope_engine.policy.excluded_paths and not ctx.config.get("nuclei", {}).get("allow_with_excluded_paths", False):
        reason = (
            "Nuclei skipped: configured excluded paths cannot be enforced "
            "inside an HTTPS CONNECT tunnel"
        )
        ctx.coverage.record_skipped_check(stage_def.stage_id, "nuclei_excluded_paths", reason)
        return _write_empty_result(ctx, stage_def, reason)

    inventory = UnifiedEndpointInventory(ctx.workspace)
    check_dns = bool(ctx.config.get("scope", {}).get("check_dns", True))
    nuclei_cfg = ctx.config.get("nuclei", {})
    limits = ctx.config.get("limits", {})
    max_targets = min(
        int(nuclei_cfg.get("max_targets", 100)),
        int(limits.get("max_urls_per_stage", 2500)),
    )
    rate_limit = min(
        int(nuclei_cfg.get("rate_limit", 25)),
        max(1, int(float(limits.get("requests_per_host_per_sec", 5)))),
    )
    concurrency = min(int(nuclei_cfg.get("concurrency", 10)), rate_limit)
    bulk_size = min(int(nuclei_cfg.get("bulk_size", 10)), concurrency)
    severities = str(nuclei_cfg.get("severities", "low,medium,high,critical"))
    timeout_sec = float(ctx.config.get("timeouts", {}).get("nuclei_sec", 300))

    resolved_templates = resolve_nuclei_templates(
        nuclei_cfg,
        project_root=ctx.workspace.project_root,
    )
    templates_dir = str(resolved_templates) if resolved_templates else ""
    configured_templates = str(nuclei_cfg.get("templates_dir") or os.environ.get("NUCLEI_TEMPLATES_DIR", "")).strip()
    if configured_templates and not templates_dir:
        reason = (
            "Nuclei skipped: configured templates directory is missing or contains no YAML templates"
        )
        ctx.coverage.record_skipped_check(stage_def.stage_id, "nuclei_templates", reason)
        return _write_empty_result(ctx, stage_def, reason)

    target_urls: list[str] = []
    # Include all reachable, non-excluded endpoints across methods (GET, POST, etc.)
    # so API and JS endpoints added by api_js_intelligence are scanned by Nuclei.
    candidates = [
        r for r in inventory.all_endpoints()
        if r.reachable is not False and not r.excluded
    ]
    # One root URL per origin first: most templates are host-level, so this gives every
    # host coverage before individual paths consume the max_targets quota.
    ordered_urls: list[str] = []
    seen_origins: set[str] = set()
    for r in candidates:
        parsed_c = urlsplit(r.canonical_url or r.url)
        if parsed_c.scheme in {"http", "https"} and parsed_c.netloc:
            origin = f"{parsed_c.scheme}://{parsed_c.netloc.rsplit('@', 1)[-1]}/"
            if origin not in seen_origins:
                seen_origins.add(origin)
                ordered_urls.append(origin)
    ordered_urls.extend(r.canonical_url or r.url for r in candidates)
    for raw_url in ordered_urls:
        decision = ctx.scope_engine.evaluate_url(raw_url, check_dns=check_dns)
        if not decision.allowed:
            ctx.coverage.record_out_of_scope(stage_def.stage_id, raw_url, decision.reason)
            continue
        if decision.normalized_url not in target_urls:
            target_urls.append(decision.normalized_url)
        if len(target_urls) >= max_targets:
            break

    if not target_urls:
        seed_decision = ctx.scope_engine.evaluate_url(ctx.target, check_dns=check_dns)
        if seed_decision.allowed:
            target_urls = [seed_decision.normalized_url]
        else:
            ctx.coverage.record_out_of_scope(stage_def.stage_id, ctx.target, seed_decision.reason)

    if not target_urls:
        reason = "No DNS-validated in-scope target URLs available for Nuclei"
        ctx.coverage.record_skipped_check(stage_def.stage_id, "nuclei_targets", reason)
        return _write_empty_result(ctx, stage_def, reason)

    # -rl is a global rate. Keep the per-host budget: hosts run in parallel (-bs), so the
    # global rate may not exceed per_host_rate * hosts-in-flight.
    per_host_rate = max(1, int(float(limits.get("requests_per_host_per_sec", 5))))
    hosts_in_scan = {urlsplit(u).hostname for u in target_urls}
    bulk_size = max(1, min(bulk_size, len(hosts_in_scan)))
    rate_limit = min(int(nuclei_cfg.get("rate_limit", 25)), per_host_rate * bulk_size)
    concurrency = max(1, min(int(nuclei_cfg.get("concurrency", 10)), rate_limit))

    targets_rel = "analysis/.nuclei_targets.txt"
    targets_file: Path = ctx.workspace.write_text_atomic(
        targets_rel, "\n".join(target_urls) + "\n"
    )

    cmd = [
        binary,
        "-l", str(targets_file),
        "-jsonl",
        "-silent",
        "-stats",
        "-stats-interval", "15",
        "-nc",
        "-disable-update-check",
        "-no-interactsh",
        "-max-redirects", "0",
        "-rl", str(rate_limit),
        "-c", str(concurrency),
        "-bs", str(bulk_size),
        "-severity", severities,
        "-etags", "dos,fuzz,intrusive,bruteforce,default-login,token-spray,sqli,rce",
        "-H", f"User-Agent: {ctx.config.get('limits', {}).get('user_agent', 'SecurityAnalyzer/0.1.0')}",
        "-proxy", proxy_url,
    ]
    if templates_dir:
        cmd.extend(["-t", str(Path(templates_dir).expanduser().resolve())])
    elif nuclei_cfg.get("automatic_scan", True):
        # Wappalyzer-driven template selection: runs only templates relevant to detected
        # technologies instead of the full corpus (which cannot finish at a polite rate).
        cmd.append("-as")
    extra_tags = str(nuclei_cfg.get("tags", "")).strip()
    if extra_tags and re.fullmatch(r"[A-Za-z0-9_,.-]+", extra_tags):
        cmd.extend(["-tags", extra_tags])

    findings: list[dict[str, Any]] = []
    notes: list[str] = []
    completed = False
    events_rel = "analysis/nuclei_events.jsonl"
    ctx.workspace.write_text_atomic(events_rel, "")
    endpoint_map = {
        (record.canonical_url or record.url): record.endpoint_id
        for record in inventory.all_endpoints()
    }

    def persist_nuclei_event(line: str) -> None:
        try:
            raw_item = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(raw_item, dict):
            return
        raw_match = str(raw_item.get("matched-at") or "")
        safe_match = _redact_url(raw_match)
        if not safe_match:
            return
        decision = ctx.scope_engine.evaluate_url(safe_match, check_dns=check_dns)
        if not decision.allowed:
            return
        reported_ip = str(raw_item.get("ip") or "")
        if not _is_ip_allowed_by_scope(ctx, reported_ip):
            return
        normalized = parse_nuclei_jsonl([line], endpoint_map)
        if not normalized:
            return
        ctx.workspace.append_jsonl(
            events_rel,
            {
                "schema_version": "1.0",
                "scan_id": ctx.workspace.scan_id,
                "stage_id": stage_def.stage_id,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                **normalized[0],
            },
        )

    inactivity_timeout = float(nuclei_cfg.get("inactivity_timeout_sec", 180))
    proc = None
    try:
        proc = ctx.resource_governor.run_process(
            cmd,
            timeout_sec=timeout_sec,
            cwd=ctx.workspace.project_root,
            inactivity_timeout_sec=inactivity_timeout,
            stdout_line_callback=persist_nuclei_event,
        )
        if proc.timed_out:
            notes.append(f"Nuclei exceeded its configured timeout/resource budget ({timeout_sec:g}s)")
        if proc.inactivity_timed_out:
            notes.append(f"Nuclei produced no process output for {inactivity_timeout:g}s; inactivity watchdog stopped it")
        if proc.cancelled:
            notes.append("Nuclei was cancelled; streamed partial results were preserved")
        if proc.callback_error:
            notes.append(f"Nuclei streaming callback failed ({proc.callback_error}); streamed results may be incomplete")
        if proc.output_truncated:
            notes.append("Nuclei output exceeded the configured process-output limit; results are incomplete")
        if proc.returncode not in (0,):
            notes.append(
                f"Nuclei exited with non-zero code {proc.returncode}: "
                f"{_redact_text(proc.stderr or 'no stderr output')}"
            )
        completed = (
            proc.returncode == 0
            and not proc.timed_out
            and not proc.inactivity_timed_out
            and not proc.cancelled
            and not proc.output_truncated
            and not proc.callback_error
        )

        for line in (proc.stdout or "").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(parsed, dict):
                continue

            info = parsed.get("info") if isinstance(parsed.get("info"), dict) else {}
            matched_raw = str(parsed.get("matched-at") or "")
            reported_ip = str(parsed.get("ip") or "")
            if not _is_ip_allowed_by_scope(ctx, reported_ip):
                ctx.coverage.record_out_of_scope(
                    stage_def.stage_id,
                    matched_raw or reported_ip,
                    f"Nuclei reported disallowed IP {reported_ip}",
                )
                continue

            safe_location = _redact_url(matched_raw)
            if not safe_location:
                # Never turn an unqualified host/template string into trusted evidence.
                continue
            match_decision = ctx.scope_engine.evaluate_url(safe_location, check_dns=check_dns)
            if not match_decision.allowed:
                ctx.coverage.record_out_of_scope(
                    stage_def.stage_id, safe_location, match_decision.reason
                )
                continue

            extracted = parsed.get("extracted-results")
            if not isinstance(extracted, list):
                extracted = []
            findings.append({
                "template_id": _redact_text(str(parsed.get("template-id", "unknown")), 160),
                "title": _redact_text(str(info.get("name") or parsed.get("template-id") or "Nuclei Finding"), 200),
                "severity": _map_severity(str(info.get("severity", "info"))),
                "category": "nuclei_template_match",
                "location": match_decision.normalized_url,
                "matcher_name": _redact_text(str(parsed.get("matcher-name", "")), 120),
                "extracted_results": [
                    _redact_text(str(item), 300) for item in extracted[:10]
                ],
                "description": _redact_text(str(info.get("description", "")), 1000),
                "curl_command": "",
            })

    except ResourceLimitExceeded as exc:
        notes.append(f"Nuclei stopped by scan-wide resource governor: {exc}")
    except OSError as exc:
        notes.append(f"Nuclei execution failed: {type(exc).__name__}")
    finally:
        targets_file.unlink(missing_ok=True)

    if not findings:
        # proc raised or stdout was lost: rebuild from the scope-validated streamed events.
        findings = _findings_from_events(ctx, events_rel)
    unique_findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    for item in findings:
        key = (item["template_id"], item["location"], item.get("matcher_name", ""))
        if key not in seen_keys:
            seen_keys.add(key)
            unique_findings.append(item)
    findings = unique_findings

    if completed:
        for url in target_urls:
            ctx.coverage.record_target_tested(stage_def.stage_id, url)

    tested = len(target_urls) if completed else 0
    skipped = len(target_urls) - tested
    payload = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets_scanned": target_urls,
        "findings": findings,
        "notes": notes,
        "execution": {
            "completed": completed,
            "return_code": getattr(proc, "returncode", None),
            "timeout": bool(getattr(proc, "timed_out", False)),
            "output_truncated": bool(getattr(proc, "output_truncated", False)),
            "cancelled": bool(getattr(proc, "cancelled", False)),
            "inactivity_timed_out": bool(getattr(proc, "inactivity_timed_out", False)),
            "inactivity_timeout_sec": inactivity_timeout,
            "stderr_excerpt": _redact_text(
                getattr(proc, "stderr", "") or "",
                4000,
            ),
            "streamed_events_artifact": events_rel,
            "rate_limit": rate_limit,
            "concurrency": concurrency,
            "bulk_size": bulk_size,
        },
    }
    ctx.workspace.write_json_atomic("analysis/nuclei_findings.json", payload)

    status = StageStatus.SUCCESS if completed else StageStatus.PARTIAL
    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Nuclei processed {tested}/{len(target_urls)} target URL(s), "
            f"recorded {len(findings)} finding(s)"
            + (f"; {'; '.join(notes)}" if notes else "")
        ),
        artifacts=["analysis/nuclei_findings.json", events_rel],
        metrics={
            "targets_total": len(target_urls),
            "targets_tested": tested,
            "targets_skipped": skipped,
            "findings": len(findings),
        },
    )


def _findings_from_events(ctx: ExecutionContext, events_rel: str) -> list[dict[str, Any]]:
    try:
        text = ctx.workspace.resolve_path(events_rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            ev = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(ev, dict) or not ev.get("matched-at"):
            continue
        out.append({
            "template_id": str(ev.get("template_id", "unknown")),
            "title": str(ev.get("title", "Nuclei Finding")),
            "severity": str(ev.get("severity", Severity.INFO.value)),
            "category": "nuclei_template_match",
            "location": str(ev["matched-at"]),
            "matcher_name": "",
            "extracted_results": [],
            "description": "",
            "curl_command": "",
            "recovered_from_stream": True,
        })
    return out


def parse_nuclei_jsonl(
    raw_output: str | list[str], endpoint_map: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    """Parse Nuclei JSONL into a minimal, redacted result model.

    Raw request/response blobs are intentionally omitted because they can
    contain cookies, bearer tokens, API keys, and personal data.
    """
    parsed_items: list[dict[str, Any]] = []
    lines = raw_output if isinstance(raw_output, list) else (raw_output or "").splitlines()
    endpoint_map = endpoint_map or {}
    for line in lines:
        candidate = str(line).strip()
        if not candidate:
            continue
        try:
            item = json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(item, dict):
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        matched = _redact_url(str(item.get("matched-at") or ""))
        severity = _map_severity(str(info.get("severity", "info")))
        parsed_items.append({
            "template_id": _redact_text(str(item.get("template-id", "unknown")), 160),
            "host": _redact_url(str(item.get("host") or "")),
            "matched-at": matched,
            "severity": severity,
            "title": _redact_text(str(info.get("name") or item.get("template-id") or "Nuclei Finding"), 200),
            "tags": [
                _redact_text(str(tag), 80)
                for tag in (info.get("tags") or [])[:30]
                if isinstance(tag, (str, int, float))
            ],
            "endpoint_id": endpoint_map.get(matched, ""),
        })
    return parsed_items