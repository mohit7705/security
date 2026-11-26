from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from security_analyzer.authentication.token_refresher import audit_identity_tokens
from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.deep_checks.authorization_idor import (
    _get_or_init_auth_manager,
)
from security_analyzer.utils.request_safety import DESTRUCTIVE_PATH_RE
from security_analyzer.deep_checks.parameter_canary import run_parameter_canary_checks
from security_analyzer.deep_checks.response_diff import (
    ResponseFingerprint,
)
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.models.asset import make_asset_id
from security_analyzer.models.finding import FindingRecord, Severity, Verdict

PRIVILEGED_FIELD_RE = re.compile(
    r"(?i)^(?:role|roles|is[-_]?admin|admin|is[-_]?staff|superuser|"
    r"permissions|scopes|balance|credits?|price|amount|discount|tier|plan|"
    r"verified|email[-_]?verified|status)$"
)
WORKFLOW_TERMINAL_STEP_RE = re.compile(
    r"(?i)/(?:confirm|complete|finalize|success|receipt|invoice|export|"
    r"download|approve|verify/done|onboarding/finish)(?:/|$)"
)
SENSITIVE_RATE_LIMIT_PATH_RE = re.compile(
    r"(?i)/(?:login|signin|auth|token|otp|verify|forgot[-_]?password|"
    r"reset|register|signup|export)(?:/|$)"
)
PAGINATION_PARAM_NAMES = {
    "limit", "per_page", "page_size", "size", "count", "take", "max",
}
WORKFLOW_ACTIONS = {
    "create": "create",
    "new": "create",
    "validate": "validate",
    "verify": "verify",
    "approve": "approve",
    "authorize": "approve",
    "pay": "pay",
    "payment": "pay",
    "fulfil": "fulfil",
    "fulfill": "fulfil",
    "ship": "fulfil",
    "complete": "complete",
    "finalize": "complete",
    "finalise": "complete",
    "cancel": "cancel",
    "refund": "refund",
    "return": "return",
    "confirm": "confirm",
    "delete": "delete",
    "remove": "delete",
    "transfer": "transfer",
    "update": "update",
}
WORKFLOW_ACTION_ORDER = (
    "create", "validate", "verify", "approve", "pay",
    "fulfil", "complete", "confirm", "cancel", "refund", "return",
    "delete", "transfer", "update",
)
SENSITIVE_WORKFLOW_ACTIONS = {
    "create", "update", "approve", "pay", "fulfil", "cancel", "refund",
    "return", "delete", "transfer", "complete", "confirm",
}
RESOURCE_ID_SEGMENT_RE = re.compile(
    r"(?i)^(?:[0-9]{1,18}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)


def _workflow_action(path: str, method: str) -> tuple[str, int | None]:
    segments = [segment.lower() for segment in (path or "/").split("/") if segment]
    if any(segment in {
        "auth", "login", "signin", "logout", "token", "oauth",
        "graphql", "search", "query", "upload", "download", "export",
    } for segment in segments):
        return "", None
    for index, segment in enumerate(segments):
        action = WORKFLOW_ACTIONS.get(segment)
        if action:
            return action, index
    method = method.upper()
    if len(segments) >= 2 and method == "POST":
        return "create", None
    if len(segments) >= 2 and method in {"PUT", "PATCH"}:
        return "update", None
    if len(segments) >= 2 and method == "DELETE":
        return "delete", None
    return "", None


def _build_workflow_models(
    operations: list[dict[str, Any]],
    endpoints: list[Any],
) -> list[dict[str, Any]]:
    """Build non-executing workflow hypotheses from catalogued route operations."""
    grouped: dict[str, dict[str, Any]] = {}

    records: list[tuple[str, str, str, str]] = []
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        path = str(operation.get("path") or "")
        method = str(operation.get("method") or "GET").upper()
        if path.startswith("/"):
            records.append((
                path,
                method,
                str(operation.get("operation_id") or ""),
                str(operation.get("source") or "api_catalog"),
            ))
    for endpoint in endpoints:
        path = str(getattr(endpoint, "path", "") or "")
        method = str(getattr(endpoint, "method", "GET")).upper()
        if path.startswith("/"):
            records.append((
                path,
                method,
                str(getattr(endpoint, "endpoint_id", "")),
                "endpoint_inventory",
            ))

    seen: set[tuple[str, str]] = set()
    for path, method, operation_id, source in records:
        action, action_index = _workflow_action(path, method)
        if not action:
            continue
        segments = [segment for segment in path.split("/") if segment]
        if action_index is not None:
            resource_segments = segments[:action_index]
        else:
            resource_segments = segments
        resource_segments = [
            "{id}" if RESOURCE_ID_SEGMENT_RE.fullmatch(segment) else segment
            for segment in resource_segments
        ]
        resource_path = "/" + "/".join(resource_segments) if resource_segments else "/"
        if resource_segments and resource_segments[-1] == "{id}":
            resource_segments.pop()
            resource_path = "/" + "/".join(resource_segments) if resource_segments else "/"
        key = (path, method)
        if key in seen:
            continue
        seen.add(key)
        model = grouped.setdefault(resource_path, {
            "resource_path": resource_path,
            "actions": [],
        })
        if not any(item["action"] == action and item["operation_id"] == operation_id for item in model["actions"]):
            model["actions"].append({
                "action": action,
                "method": method,
                "path": path,
                "operation_id": operation_id,
                "source": source,
                "sensitive": action in SENSITIVE_WORKFLOW_ACTIONS,
            })

    result: list[dict[str, Any]] = []
    for resource_path, model in sorted(grouped.items()):
        actions = model["actions"]
        present = {item["action"] for item in actions}
        ordered = [action for action in WORKFLOW_ACTION_ORDER if action in present]
        transitions = []
        for before, after in zip(ordered, ordered[1:]):
            before_ops = [item for item in actions if item["action"] == before]
            after_ops = [item for item in actions if item["action"] == after]
            transitions.append({
                "from_action": before,
                "to_action": after,
                "from_operation_ids": [item["operation_id"] for item in before_ops],
                "to_operation_ids": [item["operation_id"] for item in after_ops],
                "inferred_order_only": True,
                "validated": False,
                "request_performed": False,
                "approval_required": True,
                "approved": False,
            })
        result.append({
            "resource_path": resource_path,
            "actions": actions,
            "candidate_transitions": transitions,
            "model_status": "HYPOTHESIS_NEEDS_HUMAN_REVIEW",
            "state_values_inferred": False,
            "state_changing_requests_performed": False,
            "human_approval_gate": {
                "required_for_transition_tests": True,
                "approved": False,
                "execution_enabled": False,
            },
        })
    return result


def _safe_endpoint_url(ctx: ExecutionContext, value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 8192:
        return None
    try:
        decision = ctx.scope_engine.evaluate_url(value, check_dns=True)
    except (TypeError, ValueError):
        return None
    return decision.normalized_url if decision.allowed else None


def _least_privileged_identity(auth_mgr: Any) -> str:
    candidates: list[tuple[int, str]] = []
    for identity_id in auth_mgr.list_identities():
        if identity_id == "anonymous":
            continue
        try:
            identity = auth_mgr.get_context(identity_id)
        except Exception:
            continue
        if not (identity.authenticated and identity.session_valid):
            continue

        role = str(getattr(identity, "role", "")).strip().lower()
        rank = (
            3 if any(term in role for term in ("admin", "owner", "superuser", "root"))
            else 2 if any(term in role for term in ("manager", "staff", "operator"))
            else 1
        )
        candidates.append((rank, identity_id))

    if not candidates:
        return "anonymous"
    return sorted(candidates)[0][1]


def _append_finding(
    findings: list[dict[str, Any]],
    finding: FindingRecord,
) -> None:
    key = (
        finding.category,
        finding.endpoint_id,
        finding.identity_id,
        str(finding.metadata.get("parameter", "")),
        str(finding.metadata.get("operation_id", "")),
    )
    existing = {
        (
            item.get("category"),
            item.get("endpoint_id"),
            item.get("identity_id"),
            str((item.get("metadata") or {}).get("parameter", "")),
            str((item.get("metadata") or {}).get("operation_id", "")),
        )
        for item in findings
    }
    if key not in existing:
        findings.append(finding.to_dict())


def run_business_logic_checks(
    ctx: ExecutionContext,
    stage_def: StageDefinition,
) -> StageResult:
    """Perform bounded, read-only business-logic surface, JWT token, and boundary checks.

    This stage never submits workflow transitions, payments, account changes,
    or arbitrary mass-assignment payloads. It inspects schemas/tokens and performs
    only explicitly bounded GET probes against in-scope endpoints.
    """
    inventory = UnifiedEndpointInventory(ctx.workspace)
    auth_mgr = _get_or_init_auth_manager(ctx)

    deep_cfg = ctx.config.get("deep_checks", {})
    max_endpoints = min(500, max(1, int(deep_cfg.get("max_logic_endpoints", 60))))
    max_pagination_value = min(
        1000,
        max(10, int(deep_cfg.get("max_pagination_probe_value", 1000))),
    )
    timeouts = ctx.config.get("timeouts", {})
    connect_timeout = float(timeouts.get("http_connect_sec", 10))
    read_timeout = float(timeouts.get("http_read_sec", 20))

    active_identity = _least_privileged_identity(auth_mgr)
    identity = auth_mgr.get_context(active_identity)
    client = identity.create_http_client(
        ctx.scope_engine,
        coverage=ctx.coverage,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        max_redirects=0,
        governor=ctx.resource_governor,
    )

    api_catalog = (
        ctx.upstream_artifacts.get("api_js_intelligence", {})
        .get("analysis/api_catalog.json", {})
    )
    operations = api_catalog.get("operations", []) if isinstance(api_catalog, dict) else []
    if not isinstance(operations, list):
        operations = []

    workflows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    budget_exhausted = False

    # Passive JWT & session token security audit across configured identities
    for id_name in auth_mgr.list_identities():
        try:
            id_ctx = auth_mgr.get_context(id_name)
        except Exception:
            continue
        for jwt_finding in audit_identity_tokens(id_ctx, target_url=ctx.target):
            if not any(
                existing.get("category") == jwt_finding.get("category")
                and existing.get("endpoint_id") == jwt_finding.get("endpoint_id")
                for existing in findings
            ):
                findings.append(jwt_finding)

    # Static request-schema inspection. This does not submit a modified body.
    for operation in operations:
        if not isinstance(operation, dict):
            continue

        operation_url = _safe_endpoint_url(ctx, operation.get("url"))
        if operation_url is None:
            continue

        body_fields_raw = operation.get("body_fields") or []
        if not isinstance(body_fields_raw, list):
            continue

        body_fields = [
            str(field)[:128]
            for field in body_fields_raw
            if isinstance(field, (str, int))
        ]
        sensitive_fields = sorted(
            {
                field
                for field in body_fields
                if PRIVILEGED_FIELD_RE.fullmatch(field)
            }
        )
        if not sensitive_fields:
            continue

        parsed_operation = urlsplit(operation_url)
        operation_id = str(operation.get("operation_id", ""))[:256]
        method = str(operation.get("method", "POST")).upper()[:16]
        path = str(operation.get("path", parsed_operation.path))[:2048]

        workflows.append(
            {
                "check_type": "mass_assignment_schema_surface",
                "url": operation_url,
                "method": method,
                "operation_id": operation_id,
                "sensitive_fields": sensitive_fields,
                "request_performed": False,
            }
        )

        _append_finding(
            findings,
            FindingRecord(
                title=(
                    f"Sensitive privilege or billing fields exposed in API schema "
                    f"({method} {path})"
                ),
                category="mass_assignment_surface",
                severity=Severity.MEDIUM,
                verdict=Verdict.NEEDS_HUMAN_REVIEW,
                confidence=0.72,
                asset_id=make_asset_id(parsed_operation.hostname or "target"),
                endpoint_id=operation_id or f"schema_{method}_{path}",
                identity_id=active_identity,
                description=(
                    f"The in-scope API request schema declares sensitive fields "
                    f"{sensitive_fields}. Schema presence alone does not prove the "
                    "server accepts unauthorized changes."
                ),
                remediation=(
                    "Use explicit request DTO allow-lists and derive privileged, "
                    "billing, verification, and role fields exclusively from "
                    "trusted server-side state."
                ),
                scanner_source="business_logic_checks",
                metadata={
                    "sensitive_fields": sensitive_fields,
                    "operation_id": operation_id,
                    "request_performed": False,
                },
            ),
        )

    endpoints = [
        endpoint
        for endpoint in inventory.get_endpoints(
            include_excluded=False,
            include_out_of_scope=False,
        )
        if endpoint.scope_status == "in_scope"
        and endpoint.method == "GET"
        and endpoint.reachable is not False
        and "{" not in urlsplit(endpoint.url).path
        and "}" not in urlsplit(endpoint.url).path
        and not DESTRUCTIVE_PATH_RE.search(endpoint.path)
    ][:max_endpoints]

    workflow_models = _build_workflow_models(operations, endpoints)
    tested_count = 0
    request_errors = 0
    requests_sent = 0
    endpoints_with_responses: set[str] = set()

    for endpoint in endpoints:
        if budget_exhausted:
            break

        # Workflow terminal routes are only recorded as review surfaces.
        # A direct GET can still trigger side effects on misdesigned systems.
        if WORKFLOW_TERMINAL_STEP_RE.search(endpoint.path):
            workflows.append(
                {
                    "check_type": "workflow_terminal_route_surface",
                    "url": endpoint.url,
                    "identity_id": active_identity,
                    "request_performed": False,
                    "reason": (
                        "Direct terminal-step requests are disabled because GET "
                        "routes can have application side effects."
                    ),
                }
            )
            tested_count += 1
            continue

        # Never actively probe authentication, OTP, reset, registration or
        # export routes merely to infer rate-limiting from response headers.
        if SENSITIVE_RATE_LIMIT_PATH_RE.search(endpoint.path):
            workflows.append(
                {
                    "check_type": "rate_limit_review_surface",
                    "url": endpoint.url,
                    "identity_id": active_identity,
                    "request_performed": False,
                    "reason": (
                        "No request was sent; rate limiting cannot be inferred "
                        "from the absence of advertised headers."
                    ),
                }
            )
            tested_count += 1
            continue

        parsed = urlsplit(endpoint.url)
        try:
            query_pairs = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                max_num_fields=128,
            )
        except ValueError:
            tested_count += 1
            continue

        pagination_params = [
            key for key, _ in query_pairs
            if key.lower() in PAGINATION_PARAM_NAMES
        ]
        if not pagination_params:
            tested_count += 1
            continue

        target_parameter = pagination_params[0]
        for test_value, label in (
            ("-1", "negative_limit"),
            (str(max_pagination_value), "bounded_large_limit"),
        ):
            mutated_pairs = [
                (key, test_value if key == target_parameter else value)
                for key, value in query_pairs
            ]
            mutated_url = urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    urlencode(mutated_pairs),
                    "",
                )
            )

            if _safe_endpoint_url(ctx, mutated_url) is None:
                continue

            try:
                response = client.get(
                    mutated_url,
                    stage_id=stage_def.stage_id,
                    allow_redirects=False,
                )
            except ResourceLimitExceeded:
                budget_exhausted = True
                break
            except (ScopeViolationError, requests.RequestException):
                request_errors += 1
                continue

            requests_sent += 1
            endpoints_with_responses.add(endpoint.endpoint_id)
            fingerprint = ResponseFingerprint.from_response(
                identity_id=active_identity,
                url=mutated_url,
                method="GET",
                response=response,
            )
            workflows.append(
                {
                    "check_type": f"pagination_boundary:{label}",
                    "url": mutated_url,
                    "parameter": target_parameter,
                    "status_code": fingerprint.status_code,
                    "response_bytes": fingerprint.content_length,
                    "request_performed": True,
                }
            )

            if fingerprint.status_code >= 500:
                _append_finding(
                    findings,
                    FindingRecord(
                        title=(
                            f"Server error on bounded pagination input "
                            f"({target_parameter}={test_value})"
                        ),
                        category="unhandled_boundary_exception",
                        severity=Severity.LOW,
                        verdict=Verdict.NEEDS_HUMAN_REVIEW,
                        confidence=0.70,
                        asset_id=make_asset_id(endpoint.hostname),
                        endpoint_id=endpoint.endpoint_id,
                        identity_id=active_identity,
                        description=(
                            f"The in-scope GET endpoint returned HTTP "
                            f"{fingerprint.status_code} for a bounded pagination "
                            f"boundary value. This is an error-handling signal, "
                            "not proof of exploitable impact."
                        ),
                        remediation=(
                            "Validate pagination inputs server-side, reject "
                            "negative values, and enforce conservative maximum "
                            "page sizes before database operations."
                        ),
                        scanner_source="business_logic_checks",
                        metadata={
                            "parameter": target_parameter,
                            "value": test_value,
                            "status_code": fingerprint.status_code,
                            "target_url": mutated_url,
                            "request_performed": True,
                        },
                    ),
                )

        tested_count += 1

    # Non-destructive GET parameter canary probing (reflection, open redirect, error leaks)
    if not budget_exhausted and bool(deep_cfg.get("enable_parameter_canary", False)):
        canary_candidates = [
            ep
            for ep in endpoints
            if not WORKFLOW_TERMINAL_STEP_RE.search(ep.path)
            and not SENSITIVE_RATE_LIMIT_PATH_RE.search(ep.path)
        ]
        canary_stats = run_parameter_canary_checks(
            ctx,
            stage_id=stage_def.stage_id,
            client=client,
            endpoints=canary_candidates,
            active_identity=active_identity,
            workflows=workflows,
            findings=findings,
            append_finding_fn=_append_finding,
            max_endpoints=min(100, max(1, int(deep_cfg.get("max_canary_endpoints", 30)))),
            max_params_per_endpoint=min(15, max(1, int(deep_cfg.get("max_canary_params_per_endpoint", 5)))),
        )
        requests_sent += canary_stats.requests_sent
        request_errors += canary_stats.request_errors
        endpoints_with_responses.update(canary_stats.endpoints_probed or set())
        if canary_stats.budget_exhausted:
            budget_exhausted = True

    no_assessable_inputs = not endpoints
    status = (
        StageStatus.PARTIAL
        if budget_exhausted or no_assessable_inputs or request_errors
        else StageStatus.SUCCESS
    )
    payload: dict[str, Any] = {
        "schema_version": "1.1",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "identity_used": active_identity,
        "summary": {
            "endpoints_total": len(endpoints),
            "endpoints_evaluated": tested_count,
            "workflows_checked": len(workflows),
            "workflow_models": len(workflow_models),
            "candidate_transitions": sum(
                len(model["candidate_transitions"]) for model in workflow_models
            ),
            "findings_count": len(findings),
            "request_errors": request_errors,
            "requests_sent": requests_sent,
            "endpoints_with_responses": len(endpoints_with_responses),
            "budget_exhausted": budget_exhausted,
        },
        "workflows": workflows,
        "workflow_models": workflow_models,
        "findings": findings,
    }
    ctx.workspace.write_json_atomic(
        "analysis/business_logic.json",
        payload,
    )

    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Evaluated {tested_count}/{len(endpoints)} endpoint(s), "
            f"recorded {len(workflows)} workflow observation(s) and "
            f"{len(findings)} finding(s)"
            + ("; scan resource budget exhausted" if budget_exhausted else "")
            + ("; no eligible endpoints were available for active assessment" if no_assessable_inputs else "")
            + (f"; {request_errors} request(s) failed" if request_errors else "")
        ),
        artifacts=["analysis/business_logic.json"],
        metrics={
            "targets_total": len(endpoints),
            "targets_tested": len(endpoints_with_responses),
            "targets_evaluated": tested_count,
            "targets_skipped": len(endpoints) - tested_count,
            "requests_sent": requests_sent,
            "request_errors": request_errors,
        },
    )
