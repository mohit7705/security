from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.intelligence.openapi_analyzer import is_oversize_error
from security_analyzer.models.asset import make_asset_id
from security_analyzer.models.finding import FindingRecord, Severity, Verdict

REFLECTION_CANARY = "sa7x9q\"'><"
ERROR_SYNTAX_CANARY = "sa7x9q'\"{{7*7}}"
OPEN_REDIRECT_CANARY = "https://example.invalid/sa7x9q"

REDIRECT_PARAM_RE = re.compile(
    r"(?i)^(?:next|url|redirect|redirect[-_]?uri|redirect[-_]?url|return|return[-_]?(?:to|url|path)|"
    r"goto|dest|destination|continue|target|to|redir|forward|callback[-_]?url)$"
)

ERROR_SIGNATURE_RE = re.compile(
    r"(?i)(?:"
    r"you have an error in your sql syntax|"
    r"warning:\s*mysql_|"
    r"unclosed quotation mark after the character string|"
    r"quoted string not properly terminated|"
    r"pg_query\(\):|postgresql.*error|"
    r"ora-[0-9]{5}:|"
    r"sqlite3::|sqlite_error|"
    r"sqlstate\[[0-9a-z]{5}\]|"
    r"traceback \(most recent call last\)|"
    r"jinja2\.exceptions\.|templatesyntaxerror|"
    r"freemarker\.core\.|velocityexception"
    r")"
)


@dataclass
class CanaryRunStats:
    requests_sent: int = 0
    request_errors: int = 0
    budget_exhausted: bool = False
    endpoints_probed: set[str] | None = None

    def __post_init__(self) -> None:
        if self.endpoints_probed is None:
            self.endpoints_probed = set()


def _in_scope_url(ctx: ExecutionContext, raw_url: str) -> str | None:
    try:
        decision = ctx.scope_engine.evaluate_url(raw_url, check_dns=True)
    except (TypeError, ValueError):
        return None
    return decision.normalized_url if decision.allowed else None


def _build_mutated_url(
    parsed,
    base_pairs: list[tuple[str, str]],
    target_param: str,
    canary_value: str,
) -> str:
    found = False
    mutated: list[tuple[str, str]] = []
    for key, val in base_pairs:
        if key == target_param and not found:
            mutated.append((key, canary_value))
            found = True
        else:
            mutated.append((key, val))
    if not found:
        mutated.append((target_param, canary_value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(mutated), ""))


def run_parameter_canary_checks(
    ctx: ExecutionContext,
    *,
    stage_id: str,
    client: Any,
    endpoints: list[Any],
    active_identity: str,
    workflows: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    append_finding_fn,
    max_endpoints: int = 30,
    max_params_per_endpoint: int = 5,
) -> CanaryRunStats:
    """Send bounded, read-only GET parameter canaries for reflection, open redirect, and error leaks."""
    stats = CanaryRunStats()
    candidate_endpoints = endpoints[: max(1, max_endpoints)]

    for endpoint in candidate_endpoints:
        if stats.budget_exhausted:
            break

        parsed = urlsplit(endpoint.url)
        try:
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=128)
        except ValueError:
            continue

        param_names: list[str] = []
        seen_params: set[str] = set()
        for key, _ in query_pairs:
            if key and key not in seen_params:
                seen_params.add(key)
                param_names.append(key)
        for known_param in getattr(endpoint, "query_param_names", []) or []:
            clean_p = str(known_param).strip()
            if clean_p and clean_p not in seen_params:
                seen_params.add(clean_p)
                param_names.append(clean_p)

        if not param_names:
            continue

        for param_name in param_names[: max(1, max_params_per_endpoint)]:
            if stats.budget_exhausted:
                break

            # 1. Open-redirect canary on redirect-shaped parameter names
            if REDIRECT_PARAM_RE.fullmatch(param_name):
                redir_url = _build_mutated_url(parsed, query_pairs, param_name, OPEN_REDIRECT_CANARY)
                if _in_scope_url(ctx, redir_url) is not None:
                    try:
                        resp = client.get(redir_url, stage_id=stage_id, allow_redirects=False)
                        stats.requests_sent += 1
                        stats.endpoints_probed.add(endpoint.endpoint_id)
                        location_hdr = str(resp.headers.get("Location") or "").strip()
                        workflows.append({
                            "check_type": "parameter_canary:open_redirect",
                            "url": redir_url,
                            "parameter": param_name,
                            "status_code": resp.status_code,
                            "request_performed": True,
                        })
                        if resp.status_code in {301, 302, 303, 307, 308} and (
                            location_hdr.lower().startswith("https://example.invalid")
                            or location_hdr.lower().startswith("//example.invalid")
                        ):
                            append_finding_fn(
                                findings,
                                FindingRecord(
                                    title=f"Open redirect via unvalidated '{param_name}' parameter ({endpoint.path})",
                                    category="open_redirect",
                                    severity=Severity.MEDIUM,
                                    verdict=Verdict.LIKELY,
                                    confidence=0.88,
                                    asset_id=make_asset_id(endpoint.hostname),
                                    endpoint_id=endpoint.endpoint_id,
                                    identity_id=active_identity,
                                    description=(
                                        f"Setting query parameter '{param_name}' to an external URL caused the server "
                                        f"to return HTTP {resp.status_code} with Location: {location_hdr!r}."
                                    ),
                                    remediation=(
                                        "Validate redirect targets against a strict relative-path or allow-listed "
                                        "destination host policy."
                                    ),
                                    scanner_source="parameter_canary",
                                    metadata={
                                        "parameter": param_name,
                                        "location_header": location_hdr[:300],
                                        "status_code": resp.status_code,
                                        "target_url": redir_url,
                                        "request_performed": True,
                                    },
                                ),
                            )
                    except ResourceLimitExceeded as exc:
                        if is_oversize_error(exc):
                            continue
                        stats.budget_exhausted = True
                        break
                    except (ScopeViolationError, requests.RequestException):
                        stats.request_errors += 1

            # 2. Unencoded reflection canary (XSS context probe)
            refl_url = _build_mutated_url(parsed, query_pairs, param_name, REFLECTION_CANARY)
            if _in_scope_url(ctx, refl_url) is not None:
                try:
                    resp = client.get(refl_url, stage_id=stage_id, allow_redirects=False)
                    stats.requests_sent += 1
                    stats.endpoints_probed.add(endpoint.endpoint_id)
                    content_type = str(resp.headers.get("Content-Type") or "").lower()
                    body = (resp.text or "")[:65536]
                    workflows.append({
                        "check_type": "parameter_canary:reflection",
                        "url": refl_url,
                        "parameter": param_name,
                        "status_code": resp.status_code,
                        "request_performed": True,
                    })
                    if (
                        any(ct in content_type for ct in ("text/html", "application/xhtml", "text/plain"))
                        and ("sa7x9q\"'" in body or "sa7x9q'><" in body or REFLECTION_CANARY in body)
                    ):
                        append_finding_fn(
                            findings,
                            FindingRecord(
                                title=f"Unencoded parameter reflection on '{param_name}' ({endpoint.path})",
                                category="reflected_parameter_canary",
                                severity=Severity.MEDIUM,
                                verdict=Verdict.NEEDS_HUMAN_REVIEW,
                                confidence=0.80,
                                asset_id=make_asset_id(endpoint.hostname),
                                endpoint_id=endpoint.endpoint_id,
                                identity_id=active_identity,
                                description=(
                                    f"Query parameter '{param_name}' was reflected without HTML/quote encoding in a "
                                    f"{content_type or 'text'} response, indicating potential reflected XSS."
                                ),
                                remediation=(
                                    "Apply context-aware output encoding (HTML body, attribute, JavaScript, URL) "
                                    "and enforce a strict Content-Security-Policy."
                                ),
                                scanner_source="parameter_canary",
                                metadata={
                                    "parameter": param_name,
                                    "content_type": content_type[:120],
                                    "status_code": resp.status_code,
                                    "target_url": refl_url,
                                    "request_performed": True,
                                },
                            ),
                        )
                except ResourceLimitExceeded as exc:
                    if is_oversize_error(exc):
                        continue
                    stats.budget_exhausted = True
                    break
                except (ScopeViolationError, requests.RequestException):
                    stats.request_errors += 1

            # 3. Error-based SQL / template / stack-trace canary
            err_url = _build_mutated_url(parsed, query_pairs, param_name, ERROR_SYNTAX_CANARY)
            if _in_scope_url(ctx, err_url) is not None:
                try:
                    resp = client.get(err_url, stage_id=stage_id, allow_redirects=False)
                    stats.requests_sent += 1
                    stats.endpoints_probed.add(endpoint.endpoint_id)
                    body = (resp.text or "")[:65536]
                    sig_match = ERROR_SIGNATURE_RE.search(body)
                    workflows.append({
                        "check_type": "parameter_canary:error_syntax",
                        "url": err_url,
                        "parameter": param_name,
                        "status_code": resp.status_code,
                        "request_performed": True,
                    })
                    if sig_match or (resp.status_code >= 500 and "49" not in body and "sa7x9q" not in body):
                        matched_label = sig_match.group(0)[:120] if sig_match else f"HTTP {resp.status_code}"
                        append_finding_fn(
                            findings,
                            FindingRecord(
                                title=f"Parser or backend error triggered via '{param_name}' ({endpoint.path})",
                                category="parameter_error_disclosure",
                                severity=Severity.MEDIUM if sig_match else Severity.LOW,
                                verdict=Verdict.NEEDS_HUMAN_REVIEW,
                                confidence=0.82 if sig_match else 0.65,
                                asset_id=make_asset_id(endpoint.hostname),
                                endpoint_id=endpoint.endpoint_id,
                                identity_id=active_identity,
                                description=(
                                    f"Sending a non-destructive syntax canary in parameter '{param_name}' triggered "
                                    f"an error indicator ({matched_label}). Manually verify whether SQL, template, "
                                    "or parser injection is reachable."
                                ),
                                remediation=(
                                    "Use parameterized queries, safe template auto-escaping, and generic error handlers "
                                    "that do not expose stack traces or database errors."
                                ),
                                scanner_source="parameter_canary",
                                metadata={
                                    "parameter": param_name,
                                    "error_indicator": matched_label,
                                    "status_code": resp.status_code,
                                    "target_url": err_url,
                                    "request_performed": True,
                                },
                            ),
                        )
                except ResourceLimitExceeded as exc:
                    if is_oversize_error(exc):
                        continue
                    stats.budget_exhausted = True
                    break
                except (ScopeViolationError, requests.RequestException):
                    stats.request_errors += 1

    return stats