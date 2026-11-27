from __future__ import annotations

import http.client
import ipaddress
import json
import os
import shutil
import socket
import ssl
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.egress import scope_proxy_parts
from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.models.finding import Severity


def _is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.strip().lower() == "localhost"


def _parse_cert_time(raw_value: str | None) -> datetime | None:
    if not raw_value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(raw_value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _local_proxy_parts(proxy_url: str) -> tuple[str, int]:
    parts = scope_proxy_parts(proxy_url)
    if parts is None:
        raise ValueError("TLS inspection requires an approved scope-aware HTTP proxy")
    return parts


LEGACY_TLS_VERSIONS: tuple[tuple[str, ssl.TLSVersion], ...] = (
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
)

_TESTSSL_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": Severity.CRITICAL.value,
    "HIGH": Severity.HIGH.value,
    "MEDIUM": Severity.MEDIUM.value,
    "LOW": Severity.LOW.value,
    "WARN": Severity.LOW.value,
}


def _map_testssl_findings(
    raw_items: list[dict[str, Any]],
    location: str,
    existing_categories: set[str],
) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for item in raw_items:
        if not isinstance(item, dict):
            continue
        check_id = str(item.get("id", "")).strip()
        raw_sev = str(item.get("severity", "")).strip().upper()
        finding_text = str(item.get("finding", "")).strip()
        if not check_id or raw_sev not in _TESTSSL_SEVERITY_MAP:
            continue
        if check_id in seen_ids:
            continue

        # Avoid duplicating findings already emitted by the native Python TLS check
        if check_id in {"TLS1", "TLS1_1"} and "tls_legacy_protocol" in existing_categories:
            continue
        if check_id == "cert_expirationStatus" and (
            "tls_certificate_expired" in existing_categories
            or "tls_certificate_expiring_soon" in existing_categories
        ):
            continue
        if check_id == "cert_chain_of_trust" and "tls_certificate_invalid" in existing_categories:
            continue

        seen_ids.add(check_id)
        cve = str(item.get("cve", "")).strip()
        cwe = str(item.get("cwe", "")).strip()
        suffix_parts = [p for p in (cve, cwe) if p]
        suffix = f" ({', '.join(suffix_parts)})" if suffix_parts else ""

        mapped.append({
            "category": f"testssl_{check_id.lower()[:64]}",
            "severity": _TESTSSL_SEVERITY_MAP[raw_sev],
            "title": f"TLS issue detected by testssl.sh ({check_id}){suffix}"[:200],
            "location": location,
            "evidence": finding_text[:400] or f"testssl.sh reported {raw_sev} for {check_id}",
            "source": "testssl.sh",
        })

    return mapped


def _run_testssl(
    origin_url: str,
    *,
    proxy_url: str,
    timeout_sec: float,
    governor,
    existing_categories: set[str],
) -> tuple[list[dict[str, Any]], bool, str]:
    binary = shutil.which("testssl.sh") or shutil.which("testssl")
    if not binary:
        return [], False, "testssl.sh is not installed"

    parsed = urlsplit(origin_url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or 443
    if not hostname:
        return [], False, "Missing hostname for testssl.sh"
    if _is_loopback_host(hostname):
        return [], False, "Skipped testssl.sh for loopback target"

    proxy_host, proxy_port = _local_proxy_parts(proxy_url)
    target_spec = f"{hostname}:{port}"

    with tempfile.TemporaryDirectory(prefix="security-analyzer-testssl-") as tmp_dir:
        out_json = Path(tmp_dir) / "testssl.json"
        cmd = [
            binary,
            "--quiet",
            "--color", "0",
            "--warnings", "off",
            "--connect-timeout", "10",
            "--openssl-timeout", "10",
            "--proxy", f"{proxy_host}:{proxy_port}",
            "--jsonfile", str(out_json),
            target_spec,
        ]
        try:
            proc = governor.run_process(
                cmd,
                timeout_sec=max(30.0, float(timeout_sec)),
            )
        except ResourceLimitExceeded:
            return [], False, f"testssl.sh stopped by scan-wide resource budget ({timeout_sec:g}s)"
        except OSError as exc:
            return [], False, f"testssl.sh could not run ({type(exc).__name__})"

        if proc.timed_out or proc.inactivity_timed_out or proc.cancelled:
            reason = "cancelled" if proc.cancelled else (
                "inactivity watchdog" if proc.inactivity_timed_out else "execution timeout"
            )
            return [], False, f"testssl.sh stopped by {reason}"
        if proc.output_truncated:
            return [], False, "testssl.sh output exceeded the process-output budget"
        if proc.returncode != 0:
            return [], False, f"testssl.sh exited with code {proc.returncode}"
        if not out_json.is_file() or out_json.stat().st_size == 0:
            return [], False, f"testssl.sh produced no JSON report (exit {proc.returncode})"

        try:
            parsed_json = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return [], False, "testssl.sh produced unreadable JSON output"

        raw_items: list[dict[str, Any]] = []
        if isinstance(parsed_json, list):
            raw_items = parsed_json
        elif isinstance(parsed_json, dict):
            scan_results = parsed_json.get("scanResult")
            if isinstance(scan_results, list):
                for entry in scan_results:
                    if not isinstance(entry, dict):
                        continue
                    for section_val in entry.values():
                        if isinstance(section_val, list):
                            raw_items.extend(x for x in section_val if isinstance(x, dict))

        findings = _map_testssl_findings(raw_items, origin_url, existing_categories)
        return findings, True, ""


def _probe_legacy_protocols(open_connection) -> dict[str, str]:
    """Probe each legacy protocol independently without sending application data."""
    results: dict[str, str] = {}
    for label, version in LEGACY_TLS_VERSIONS:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            context.set_ciphers("ALL:@SECLEVEL=0")
        except (ssl.SSLError, ValueError, AttributeError):
            results[label] = "untestable"
            continue

        connection = None
        try:
            connection = open_connection(context)
            results[label] = "supported"
        except ssl.SSLError as exc:
            reason = str(exc).upper()
            results[label] = (
                "not_supported"
                if any(
                    marker in reason
                    for marker in (
                        "PROTOCOL_VERSION",
                        "ALERT",
                        "HANDSHAKE_FAILURE",
                        "UNSUPPORTED",
                    )
                )
                else "untestable"
            )
        except (OSError, http.client.HTTPException):
            results[label] = "untestable"
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
    return results


def _inspect_tls_endpoint(
    url: str,
    scope_engine,
    timeout_sec: float = 10.0,
    governor=None,
    proxy_url: str = "",
    check_dns: bool = True,
) -> dict[str, Any]:
    """Inspect HTTPS through the local scope-aware CONNECT proxy."""
    decision = scope_engine.evaluate_url(url, check_dns=check_dns)
    if not decision.allowed:
        raise ScopeViolationError(
            f"Scope violation for {url!r}: {decision.reason}"
        )

    parsed = urlsplit(decision.normalized_url)
    if parsed.scheme.lower() != "https":
        raise ValueError("TLS posture scanner accepts HTTPS URLs only")

    hostname = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or 443
    if not hostname:
        raise ValueError("TLS target has no hostname")
    proxy_host, proxy_port = _local_proxy_parts(proxy_url)
    if governor is None:
        raise ResourceLimitExceeded(
            "TLS inspection requires the shared ResourceGovernor"
        )

    context = ssl.create_default_context()
    findings: list[dict[str, Any]] = []
    protocol_version = ""
    cipher_name = ""
    cert_valid: bool | None = None
    cert_error = ""
    not_after_iso = ""
    days_remaining: int | None = None
    subject_str = ""
    issuer_str = ""
    request_slot = False
    connection: http.client.HTTPSConnection | None = None

    try:
        effective_timeout = float(timeout_sec)
        if governor is not None:
            governor.acquire_request(
                decision.normalized_url,
                timeout=timeout_sec,
            )
            request_slot = True
            effective_timeout = governor.remaining_sec(timeout_sec)

        connection = http.client.HTTPSConnection(
            proxy_host,
            proxy_port,
            timeout=effective_timeout,
            context=context,
        )
        connection.set_tunnel(hostname, port)
        connection.connect()

        tls_sock = connection.sock
        if tls_sock is None:
            raise OSError("TLS proxy tunnel did not establish a socket")

        protocol_version = tls_sock.version() or ""
        cipher_tuple = tls_sock.cipher()
        cipher_name = cipher_tuple[0] if cipher_tuple else ""
        cert = tls_sock.getpeercert() or {}
        cert_valid = True
        subject_str = str(cert.get("subject", ""))[:500]
        issuer_str = str(cert.get("issuer", ""))[:500]

        not_after_dt = _parse_cert_time(cert.get("notAfter"))
        if not_after_dt is not None:
            not_after_iso = not_after_dt.isoformat()
            days_remaining = int(
                (not_after_dt - datetime.now(timezone.utc)).total_seconds() // 86400
            )
            if days_remaining < 0:
                findings.append({
                    "category": "tls_certificate_expired",
                    "severity": Severity.HIGH.value,
                    "title": "TLS certificate has expired",
                    "location": decision.normalized_url,
                    "evidence": f"Certificate expired on {not_after_iso}",
                })
            elif days_remaining < 14:
                findings.append({
                    "category": "tls_certificate_expiring_soon",
                    "severity": Severity.LOW.value,
                    "title": "TLS certificate expires within 14 days",
                    "location": decision.normalized_url,
                    "evidence": f"Expires in {days_remaining} day(s) ({not_after_iso})",
                })

    except ssl.SSLCertVerificationError as exc:
        cert_valid = False
        cert_error = str(exc)[:300]
        expired = "expired" in cert_error.lower()
        findings.append({
            "category": "tls_certificate_expired" if expired else "tls_certificate_invalid",
            "severity": Severity.HIGH.value,
            "title": (
                "TLS certificate has expired"
                if expired
                else "TLS certificate chain or hostname verification failed"
            ),
            "location": decision.normalized_url,
            "evidence": cert_error,
        })
    except (socket.timeout, TimeoutError) as exc:
        cert_valid = None
        cert_error = f"Connection timed out: {type(exc).__name__}"
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        cert_valid = None
        cert_error = f"TLS connection could not be completed: {type(exc).__name__}"
    finally:
        if connection is not None:
            connection.close()
        if request_slot:
            governor.release_request()

    legacy_probe: dict[str, str] = {}
    if cert_valid is not None or cert_error.startswith("TLS connection"):
        class _ConnectionLease:
            def __init__(self, connection, request_governor) -> None:
                self.connection = connection
                self.request_governor = request_governor

            def close(self) -> None:
                try:
                    self.connection.close()
                finally:
                    self.request_governor.release_request()

        def _open_legacy(context: ssl.SSLContext):
            governor.acquire_request(
                decision.normalized_url,
                timeout=min(float(timeout_sec), 10.0),
            )
            legacy_connection = None
            try:
                legacy_connection = http.client.HTTPSConnection(
                    proxy_host,
                    proxy_port,
                    timeout=min(float(timeout_sec), 10.0),
                    context=context,
                )
                legacy_connection.set_tunnel(hostname, port)
                legacy_connection.connect()
                return _ConnectionLease(legacy_connection, governor)
            except Exception:
                try:
                    if legacy_connection is not None:
                        legacy_connection.close()
                finally:
                    governor.release_request()
                raise

        legacy_probe = _probe_legacy_protocols(_open_legacy)
        for label, outcome in legacy_probe.items():
            if outcome == "supported" and label != protocol_version:
                findings.append({
                    "category": "tls_legacy_protocol",
                    "severity": Severity.MEDIUM.value,
                    "title": f"Server accepts legacy protocol {label}",
                    "location": decision.normalized_url,
                    "evidence": f"A handshake limited to {label} succeeded",
                })

    if protocol_version in {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}:
        findings.append({
            "category": "tls_legacy_protocol",
            "severity": Severity.MEDIUM.value,
            "title": f"Legacy transport protocol negotiated ({protocol_version})",
            "location": decision.normalized_url,
            "evidence": f"Negotiated {protocol_version} with cipher {cipher_name}",
        })

    return {
        "url": decision.normalized_url,
        "hostname": hostname,
        "destination_validation": "scope-aware-proxy",
        "port": port,
        "protocol_version": protocol_version,
        "cipher": cipher_name,
        "certificate_valid": cert_valid,
        "certificate_error": cert_error,
        "not_after": not_after_iso,
        "days_remaining": days_remaining,
        "subject": subject_str,
        "issuer": issuer_str,
        "legacy_protocol_probe": legacy_probe,
        "testssl_used": False,
        "findings": findings,
    }


def run_online_security_checks(
    ctx: ExecutionContext,
    stage_def: StageDefinition,
) -> StageResult:
    inventory = UnifiedEndpointInventory(ctx.workspace)
    timeouts = ctx.config.get("timeouts", {})
    timeout_sec = float(timeouts.get("tls_sec", 10.0))
    testssl_timeout_sec = float(timeouts.get("testssl_sec", max(timeout_sec * 12, 120.0)))
    max_origins = int(
        ctx.config.get("limits", {}).get("max_urls_per_stage", 2500)
    )

    check_dns = bool(ctx.config.get("scope", {}).get("check_dns", True))
    max_testssl_origins = int(ctx.config.get("limits", {}).get("max_testssl_origins", 5))
    stage_deadline = time.monotonic() + float(timeouts.get("tls_stage_sec", 1200))
    https_origins: dict[str, str] = {}
    origin_alive: dict[str, bool] = {}
    for record in inventory.all_endpoints():
        if record.scheme != "https" or record.excluded:
            continue
        parsed = urlsplit(record.canonical_url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        origin = f"https://[{host}]" if ":" in host else f"https://{host}"
        if port != 443:
            origin += f":{port}"
        https_origins.setdefault(origin, origin + "/")
        origin_alive[origin] = origin_alive.get(origin, False) or getattr(record, "reachable", None) is not False
        if len(https_origins) >= max_origins:
            break
    # Do not spend handshakes/testssl on origins whose every endpoint was unreachable.
    live_origins = {o: u for o, u in https_origins.items() if origin_alive.get(o)}
    if live_origins:
        https_origins = live_origins

    if not https_origins and urlsplit(ctx.target).scheme.lower() == "https":
        decision = ctx.scope_engine.evaluate_url(ctx.target, check_dns=check_dns)
        if decision.allowed:
            parsed = urlsplit(decision.normalized_url)
            host = parsed.hostname or ""
            port = parsed.port or 443
            origin = f"https://[{host}]" if ":" in host else f"https://{host}"
            if port != 443:
                origin += f":{port}"
            https_origins[origin] = origin + "/"
        else:
            ctx.coverage.record_out_of_scope(
                stage_def.stage_id, ctx.target, decision.reason
            )

    if not https_origins:
        reason = "No in-scope HTTPS origins discovered for TLS posture inspection"
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "tls_inspection", reason
        )
        ctx.workspace.write_json_atomic(
            "analysis/tls_posture.json",
            {
                "schema_version": "1.0",
                "scan_id": ctx.workspace.scan_id,
                "stage_id": stage_def.stage_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "results": [],
                "findings": [],
                "notes": [reason],
            },
        )
        return StageResult(
            stage_id=stage_def.stage_id,
            status=StageStatus.SKIPPED,
            summary=reason,
            artifacts=["analysis/tls_posture.json"],
            metrics={"targets_total": 0, "targets_tested": 0, "targets_skipped": 0},
        )

    proxy_url = os.environ.get("SECURITY_ANALYZER_PROXY", "").strip()
    egress_enforced = os.environ.get("SECURITY_ANALYZER_EGRESS_ENFORCED") == "1"
    try:
        if not egress_enforced:
            raise ValueError("egress enforcement marker is missing")
        _local_proxy_parts(proxy_url)
    except ValueError as exc:
        reason = f"TLS inspection skipped: {exc}"
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "tls_egress_proxy", reason
        )
        ctx.workspace.write_json_atomic(
            "analysis/tls_posture.json",
            {
                "schema_version": "1.0",
                "scan_id": ctx.workspace.scan_id,
                "stage_id": stage_def.stage_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "results": [],
                "findings": [],
                "notes": [reason],
            },
        )
        return StageResult(
            stage_id=stage_def.stage_id,
            status=StageStatus.PARTIAL,
            summary=reason,
            artifacts=["analysis/tls_posture.json"],
            metrics={
                "targets_total": len(https_origins),
                "targets_tested": 0,
                "targets_skipped": len(https_origins),
            },
        )

    if ctx.resource_governor is None:
        reason = "TLS inspection skipped: shared ResourceGovernor is unavailable"
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "tls_resource_governor", reason
        )
        ctx.workspace.write_json_atomic(
            "analysis/tls_posture.json",
            {
                "schema_version": "1.0",
                "scan_id": ctx.workspace.scan_id,
                "stage_id": stage_def.stage_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "results": [],
                "findings": [],
                "notes": [reason],
            },
        )
        return StageResult(
            stage_id=stage_def.stage_id,
            status=StageStatus.PARTIAL,
            summary=reason,
            artifacts=["analysis/tls_posture.json"],
            metrics={
                "targets_total": len(https_origins),
                "targets_tested": 0,
                "targets_skipped": len(https_origins),
            },
        )

    results: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    notes: list[str] = []
    tested = 0
    testssl_used_any = False
    testssl_runs = 0
    handshake_failed = 0
    budget_stopped = False
    deadline_skipped = 0
    target_host = (urlsplit(ctx.target).hostname or "").lower()
    ordered_origins = sorted(
        https_origins.values(),
        key=lambda o: (0 if (urlsplit(o).hostname or "").lower() == target_host else 1, o),
    )

    for idx, origin_url in enumerate(ordered_origins):
        if time.monotonic() >= stage_deadline:
            deadline_skipped = len(ordered_origins) - idx
            notes.append(f"TLS checks stopped: stage time budget reached ({deadline_skipped} origin(s) not inspected)")
            ctx.coverage.record_skipped_check(stage_def.stage_id, "tls_stage_budget", notes[-1])
            break
        try:
            result = _inspect_tls_endpoint(
                origin_url,
                ctx.scope_engine,
                timeout_sec=timeout_sec,
                governor=ctx.resource_governor,
                proxy_url=proxy_url,
                check_dns=check_dns,
            )
            legacy_vals = list(result.get("legacy_protocol_probe", {}).values())
            if legacy_vals and all(v == "untestable" for v in legacy_vals):
                ctx.coverage.record_skipped_check(
                    stage_def.stage_id, "tls_legacy_probe",
                    f"{origin_url}: legacy protocol probe untestable (local OpenSSL or network)",
                )
            if result["certificate_valid"] is not None and testssl_runs >= max_testssl_origins:
                if testssl_runs == max_testssl_origins:
                    ctx.coverage.record_skipped_check(
                        stage_def.stage_id, "testssl.sh",
                        f"testssl.sh limited to {max_testssl_origins} origin(s) (limits.max_testssl_origins)",
                    )
                    testssl_runs += 1
            elif result["certificate_valid"] is not None:
                testssl_runs += 1
                existing_cats = {f["category"] for f in result["findings"]}
                testssl_findings, testssl_ok, testssl_err = _run_testssl(
                    origin_url,
                    proxy_url=proxy_url,
                    timeout_sec=testssl_timeout_sec,
                    governor=ctx.resource_governor,
                    existing_categories=existing_cats,
                )
                if testssl_ok:
                    result["testssl_used"] = True
                    testssl_used_any = True
                    result["findings"].extend(testssl_findings)
                elif testssl_err:
                    ctx.coverage.record_skipped_check(
                        stage_def.stage_id, "testssl.sh", f"{origin_url}: {testssl_err}"
                    )

            results.append(result)
            all_findings.extend(result["findings"])
            if result["certificate_valid"] is None:
                handshake_failed += 1
                notes.append(
                    f"{origin_url}: {result['certificate_error'] or 'TLS handshake failed'}"
                )
                ctx.coverage.record_skipped_check(
                    stage_def.stage_id,
                    "tls_handshake",
                    f"{origin_url}: {result['certificate_error'] or 'TLS handshake failed'}",
                )
            else:
                tested += 1
                ctx.coverage.record_target_tested(
                    stage_def.stage_id,
                    origin_url,
                    metadata={
                        "tls_version": result["protocol_version"],
                        "certificate_valid": result["certificate_valid"],
                    },
                )
        except ResourceLimitExceeded as exc:
            notes.append(f"TLS checks stopped by scan-wide resource governor: {exc}")
            ctx.coverage.record_skipped_check(stage_def.stage_id, "tls_resource_budget", str(exc))
            budget_stopped = True
            break
        except (ScopeViolationError, OSError, ValueError, ssl.SSLError, http.client.HTTPException) as exc:
            notes.append(f"{origin_url}: {type(exc).__name__}")
            ctx.coverage.record_skipped_check(
                stage_def.stage_id,
                "tls_inspection",
                f"{origin_url}: {type(exc).__name__}",
            )

    payload = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "external_tools_used": ["testssl.sh"] if testssl_used_any else [],
        "results": results,
        "findings": all_findings,
        "notes": notes,
    }
    ctx.workspace.write_json_atomic("analysis/tls_posture.json", payload)

    skipped = max(0, len(https_origins) - tested)
    # Dead hosts from historical URLs are normal; only a high failure ratio or a truncated run is PARTIAL.
    attempted = tested + handshake_failed
    fail_ratio = (handshake_failed / attempted) if attempted else 0.0
    max_fail_ratio = float(ctx.config.get("limits", {}).get("tls_max_failure_ratio", 0.5))
    status = (
        StageStatus.PARTIAL
        if tested == 0 or budget_stopped or deadline_skipped or fail_ratio > max_fail_ratio
        else StageStatus.SUCCESS
    )
    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Inspected {tested}/{len(https_origins)} HTTPS origin(s); "
            f"{len(all_findings)} finding(s)"
            + (f"; {'; '.join(notes)}" if notes else "")
        ),
        artifacts=["analysis/tls_posture.json"],
        metrics={
            "targets_total": len(https_origins),
            "targets_tested": tested,
            "targets_skipped": skipped,
        },
    )