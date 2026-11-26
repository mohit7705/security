from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

import requests

from security_analyzer.authentication.auth_manager import AuthManager
from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.deep_checks.response_diff import (
    ResponseFingerprint,
    is_substantive_success,
    json_shape_similarity,
)
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.models.asset import make_asset_id
from security_analyzer.models.endpoint import EndpointRecord
from security_analyzer.models.finding import FindingRecord, Severity, Verdict
from security_analyzer.utils.request_safety import (
    is_destructive_request,
)

OBJECT_ID_PARAM_RE = re.compile(
    r"(?i)^(?:id|user[-_]?id|account[-_]?id|order[-_]?id|profile[-_]?id|"
    r"org[-_]?id|tenant[-_]?id|customer[-_]?id|invoice[-_]?id|doc[-_]?id|item[-_]?id)$"
)
NUMERIC_ID_RE = re.compile(r"^\d{1,18}$")
UUID_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
SAFE_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
REWRITE_HEADERS = ("X-Original-URL", "X-Rewrite-URL")
ADMIN_PATH_RE = re.compile(
    r"(?i)/(admin|administrator|manage|management|internal|superuser)(/|$)"
)
ADMIN_ROLES = {"admin", "administrator", "superuser", "root", "owner"}
GRAPHQL_SAFE_FIELD_RE = re.compile(r"^[_A-Za-z][_0-9A-Za-z]{0,127}$")
GRAPHQL_MUTATING_NAME_RE = re.compile(
    r"(?i)(?:create|update|delete|remove|destroy|drop|submit|purchase|pay|transfer|cancel|approve|confirm|reset|send|invite|revoke)"
)


def _role_of(auth_mgr: Any, identity_id: str) -> str:
    try:
        return str(getattr(auth_mgr.get_context(identity_id), "role", "") or "").strip().lower()
    except Exception:
        return ""


def _get_or_init_auth_manager(ctx: ExecutionContext) -> AuthManager:
    if ctx.auth_manager is not None:
        return ctx.auth_manager

    auth_path_str = str(ctx.config.get("auth_profiles_path", "")).strip()
    auth_path = Path(auth_path_str) if auth_path_str else None
    manager = AuthManager(
        scope_engine=ctx.scope_engine,
        project_root=ctx.workspace.project_root,
        scan_id=ctx.workspace.scan_id or "default",
        default_target_url=ctx.target,
        coverage=ctx.coverage,
        auth_profiles_path=auth_path,
        resource_governor=ctx.resource_governor,
    )
    manager.initialize_all(stage_id="authorization_idor")
    ctx.auth_manager = manager
    return manager


def _extract_resource_ids(url: str) -> list[tuple[str, str]]:
    """Extract identifiers from a URL without generating or requesting alternate IDs."""
    parsed = urlsplit(url)
    found: list[tuple[str, str]] = []

    for index, raw_segment in enumerate((parsed.path or "/").split("/")):
        value = unquote(raw_segment).strip()
        if NUMERIC_ID_RE.fullmatch(value) or UUID_ID_RE.fullmatch(value):
            found.append((f"path_segment[{index}]", value))

    try:
        query_pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            max_num_fields=128,
        )
    except ValueError:
        return found

    for key, raw_value in query_pairs:
        value = unquote(raw_value).strip()
        if (
            OBJECT_ID_PARAM_RE.fullmatch(key)
            and value
            and value != "[REDACTED]"
            and SAFE_OPAQUE_ID_RE.fullmatch(value)
        ):
            found.append((f"query_param:{key}", value))

    # Preserve order while avoiding duplicate location/value pairs.
    return list(dict.fromkeys(found))


def _path_matches_template(actual_path: str, template_path: str) -> bool:
    """Match /orders/123 against an OpenAPI path such as /orders/{orderId}."""
    if not isinstance(actual_path, str) or not isinstance(template_path, str):
        return False
    if not template_path.startswith("/") or not actual_path.startswith("/"):
        return False

    pattern = re.escape(template_path)
    pattern = re.sub(r"\\\{[^{}]+\\\}", r"[^/]+", pattern)
    return re.fullmatch(pattern, actual_path.rstrip("/") or "/", flags=re.IGNORECASE) is not None


def _operation_requires_auth(
    operations: list[dict[str, Any]],
    endpoint: EndpointRecord,
) -> bool:
    for operation in operations:
        if not isinstance(operation, dict) or operation.get("requires_auth") is not True:
            continue
        if str(operation.get("method", endpoint.method)).upper() != endpoint.method:
            continue
        if _path_matches_template(endpoint.path, str(operation.get("path", ""))):
            return True
    return False


def _endpoint_declared_protected(
    operations: list[dict[str, Any]],
    endpoint: EndpointRecord,
) -> bool:
    """Discovery identity is provenance only; protection must be explicitly declared."""
    return _operation_requires_auth(operations, endpoint)


def _profile_owned_ids(auth_mgr: AuthManager, identity_id: str) -> set[str]:
    profile = getattr(auth_mgr, "profiles", {}).get(identity_id)
    values = getattr(profile, "owned_resource_ids", []) if profile else []
    if not isinstance(values, list):
        return set()
    return {
        str(value).strip()
        for value in values
        if isinstance(value, (str, int)) and str(value).strip()
    }


def _resource_owner(
    auth_mgr: AuthManager,
    authenticated_ids: list[str],
    endpoint: EndpointRecord,
) -> tuple[str | None, str | None, str | None]:
    """Return an owner only when exactly one configured identity claims an ID in this URL."""
    resources = _extract_resource_ids(endpoint.url)
    owners: list[tuple[str, str, str]] = []

    for location, resource_id in resources:
        for identity_id in authenticated_ids:
            if resource_id in _profile_owned_ids(auth_mgr, identity_id):
                owners.append((identity_id, location, resource_id))

    unique = list(dict.fromkeys(owners))
    if len(unique) != 1:
        return None, None, None
    return unique[0]


def _response_is_same_protected_object(
    owner_fp: ResponseFingerprint,
    other_fp: ResponseFingerprint,
) -> bool:
    return (
        is_substantive_success(owner_fp)
        and is_substantive_success(other_fp)
        and owner_fp.is_json
        and other_fp.is_json
        and owner_fp.normalized_body_sha256 == other_fp.normalized_body_sha256
        and json_shape_similarity(owner_fp, other_fp) >= 0.80
    )


def _origin_root(url: str) -> str:
    parsed = urlsplit(url)
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    port = parsed.port or default_port
    host = f"[{parsed.hostname}]" if parsed.hostname and ":" in parsed.hostname else (parsed.hostname or "")
    netloc = host if port == default_port else f"{host}:{port}"
    return f"{parsed.scheme}://{netloc}/"


def run_authorization_idor(ctx: ExecutionContext, stage_def: StageDefinition) -> StageResult:
    """Read-only, multi-identity authorization and IDOR/BOLA assessment.

    Horizontal ownership claims are made only when an identity explicitly declares
    the resource ID in auth_profiles.yaml -> identities.<id>.owned_resource_ids.
    No neighboring IDs are generated or requested.
    """
    inventory = UnifiedEndpointInventory(ctx.workspace)
    auth_mgr = _get_or_init_auth_manager(ctx)

    deep_cfg = ctx.config.get("deep_checks", {})
    max_endpoints = min(500, max(1, int(deep_cfg.get("max_authz_endpoints", 60))))
    enable_rewrite_probes = bool(deep_cfg.get("enable_rewrite_header_probes", False))
    timeouts = ctx.config.get("timeouts", {})
    connect_timeout = float(timeouts.get("http_connect_sec", 10))
    read_timeout = float(timeouts.get("http_read_sec", 20))

    api_catalog = (
        ctx.upstream_artifacts.get("api_js_intelligence", {})
        .get("analysis/api_catalog.json", {})
    )
    operations = api_catalog.get("operations", []) if isinstance(api_catalog, dict) else []
    if not isinstance(operations, list):
        operations = []

    clients: dict[str, Any] = {}
    for identity_id in auth_mgr.list_identities():
        try:
            identity = auth_mgr.get_context(identity_id)
        except Exception:
            continue
        if identity_id != "anonymous" and not (
            identity.authenticated and identity.session_valid
        ):
            continue
        try:
            clients[identity_id] = identity.create_http_client(
                ctx.scope_engine,
                coverage=ctx.coverage,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                max_redirects=0,
                governor=ctx.resource_governor,
            )
        except Exception:
            continue

    authenticated_ids = [
        identity_id
        for identity_id in clients
        if identity_id != "anonymous"
    ]

    candidates = [
        endpoint
        for endpoint in inventory.get_endpoints(
            include_excluded=False,
            include_out_of_scope=False,
        )
        if endpoint.scope_status == "in_scope"
        and endpoint.method == "GET"
        and not is_destructive_request(endpoint.url, method=endpoint.method)
        and "{" not in urlsplit(endpoint.url).path
        and "}" not in urlsplit(endpoint.url).path
        and endpoint.reachable is not False
    ][:max_endpoints]

    matrix_tests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    tested_endpoints = 0
    request_errors = 0
    budget_exhausted = False

    for endpoint in candidates:
        fingerprints: dict[str, ResponseFingerprint] = {}

        for identity_id, client in clients.items():
            try:
                response = client.request(
                    endpoint.method,
                    endpoint.url,
                    stage_id=stage_def.stage_id,
                    allow_redirects=False,
                )
            except ResourceLimitExceeded:
                budget_exhausted = True
                break
            except (ScopeViolationError, requests.RequestException):
                request_errors += 1
                continue

            fingerprints[identity_id] = ResponseFingerprint.from_response(
                identity_id=identity_id,
                url=endpoint.url,
                method=endpoint.method,
                response=response,
            )

        if budget_exhausted:
            break
        if not fingerprints:
            continue

        tested_endpoints += 1
        anonymous_fp = fingerprints.get("anonymous")
        protected_by_catalog = _operation_requires_auth(operations, endpoint)
        # Discovery under an authenticated browser session is provenance, not
        # proof that the route requires authentication. Only an explicit API
        # security declaration can establish this precondition.
        discovered_under_authenticated_context = bool(endpoint.authenticated)
        declared_protected = _endpoint_declared_protected(operations, endpoint)

        # Vertical access-control check: only flag an anonymously successful
        # response when the endpoint is independently declared as protected.
        if (
            anonymous_fp is not None
            and declared_protected
            and is_substantive_success(anonymous_fp)
        ):
            authenticated_reference = next(
                (
                    fingerprints[identity_id]
                    for identity_id in authenticated_ids
                    if identity_id in fingerprints
                    and is_substantive_success(fingerprints[identity_id])
                ),
                None,
            )
            similarity = (
                json_shape_similarity(anonymous_fp, authenticated_reference)
                if authenticated_reference is not None
                else 0.0
            )
            findings.append(
                FindingRecord(
                    title=f"Missing authentication enforcement on {endpoint.method} {endpoint.path}",
                    category="broken_authentication_enforcement",
                    severity=Severity.HIGH,
                    verdict=Verdict.LIKELY,
                    confidence=0.82 if authenticated_reference else 0.72,
                    asset_id=make_asset_id(endpoint.hostname),
                    endpoint_id=endpoint.endpoint_id,
                    identity_id="anonymous",
                    description=(
                        f"Endpoint {endpoint.method} {endpoint.path} is declared as protected but returned "
                        f"HTTP {anonymous_fp.status_code} with a substantive response to an anonymous request."
                    ),
                    remediation=(
                        "Enforce authentication server-side before resolving protected handlers and verify "
                        "authorization independently of client-side routing."
                    ),
                    scanner_source="authorization_idor",
                    metadata={
                        "anonymous_status": anonymous_fp.status_code,
                        "authenticated_reference_status": (
                            authenticated_reference.status_code
                            if authenticated_reference else None
                        ),
                        "structural_similarity": similarity,
                        "catalog_declared_protected": protected_by_catalog,
                        "discovered_under_authenticated_context": discovered_under_authenticated_context,
                    },
                ).to_dict()
            )

        # Horizontal IDOR/BOLA requires explicit ownership attribution.
        owner_id, owner_location, owned_resource_id = _resource_owner(
            auth_mgr,
            authenticated_ids,
            endpoint,
        )
        idor_probes: list[dict[str, Any]] = []

        anonymous_blocked = (
            anonymous_fp is not None
            and anonymous_fp.status_code in {401, 403, 404}
        )
        owner_fp = fingerprints.get(owner_id) if owner_id else None

        if owner_id and owner_fp and anonymous_blocked:
            for attacker_id in authenticated_ids:
                if attacker_id == owner_id:
                    continue
                attacker_fp = fingerprints.get(attacker_id)
                if attacker_fp is None:
                    continue

                same_object = _response_is_same_protected_object(
                    owner_fp,
                    attacker_fp,
                )
                reproduced = False
                if same_object:
                    try:
                        repeat = clients[attacker_id].request(
                            endpoint.method,
                            endpoint.url,
                            stage_id=stage_def.stage_id,
                            allow_redirects=False,
                        )
                        repeat_fp = ResponseFingerprint.from_response(
                            identity_id=attacker_id,
                            url=endpoint.url,
                            method=endpoint.method,
                            response=repeat,
                        )
                        reproduced = _response_is_same_protected_object(
                            owner_fp, repeat_fp
                        )
                    except ResourceLimitExceeded:
                        budget_exhausted = True
                    except (ScopeViolationError, requests.RequestException):
                        reproduced = False
                same_object = reproduced
                idor_probes.append(
                    {
                        "parameter_location": owner_location,
                        "object_reference": owned_resource_id,
                        "owner_identity": owner_id,
                        "tested_identity": attacker_id,
                        "owner_status": owner_fp.status_code,
                        "attacker_status": attacker_fp.status_code,
                        "same_object_response": _response_is_same_protected_object(owner_fp, attacker_fp),
                        "reproduced": reproduced,
                        "suspected_idor": reproduced,
                    }
                )

                if same_object:
                    findings.append(
                        FindingRecord(
                            title=f"Potential horizontal IDOR / BOLA on {endpoint.method} {endpoint.path}",
                            category="idor_bola",
                            severity=Severity.HIGH,
                            verdict=Verdict.LIKELY,
                            confidence=0.90,
                            asset_id=make_asset_id(endpoint.hostname),
                            endpoint_id=endpoint.endpoint_id,
                            identity_id=attacker_id,
                            description=(
                                f"Resource {owned_resource_id!r} is explicitly assigned to identity "
                                f"{owner_id!r}, but identity {attacker_id!r} received an identical successful "
                                "JSON representation for the same protected resource."
                            ),
                            remediation=(
                                "Enforce object-level authorization on every request using the authenticated "
                                "principal and the resource's server-side ownership/tenant relationship."
                            ),
                            scanner_source="authorization_idor",
                            metadata={
                                "parameter_location": owner_location,
                                "object_reference": owned_resource_id,
                                "owner_identity": owner_id,
                                "attacker_identity": attacker_id,
                                "owner_status": owner_fp.status_code,
                                "attacker_status": attacker_fp.status_code,
                                "normalized_body_sha256": owner_fp.normalized_body_sha256,
                                "reproduced": True,
                            },
                        ).to_dict()
                    )

            if budget_exhausted:
                break

        # A lower role reading an admin-style endpoint is a vertical access-control issue.
        # Require both an authenticated admin reference and an anonymous denial.
        if (
            ADMIN_PATH_RE.search(endpoint.path)
            and anonymous_fp is not None
            and anonymous_fp.status_code in {401, 403, 404}
        ):
            roles = {identity_id: _role_of(auth_mgr, identity_id) for identity_id in authenticated_ids}
            admin_ref = next(
                (
                    identity_id
                    for identity_id in authenticated_ids
                    if roles.get(identity_id) in ADMIN_ROLES
                    and identity_id in fingerprints
                    and is_substantive_success(fingerprints[identity_id])
                ),
                None,
            )
            if admin_ref is not None:
                for low_id in authenticated_ids:
                    if roles.get(low_id) in ADMIN_ROLES or roles.get(low_id) in {"", "anonymous"}:
                        continue
                    low_fp = fingerprints.get(low_id)
                    if low_fp is None or not is_substantive_success(low_fp):
                        continue
                    findings.append(
                        FindingRecord(
                            title=f"Potential vertical privilege escalation on {endpoint.method} {endpoint.path}",
                            category="vertical_privilege_escalation",
                            severity=Severity.HIGH,
                            verdict=Verdict.LIKELY,
                            confidence=0.80,
                            asset_id=make_asset_id(endpoint.hostname),
                            endpoint_id=endpoint.endpoint_id,
                            identity_id=low_id,
                            description=(
                                f"Identity {low_id!r} (role {roles[low_id]!r}) received HTTP "
                                f"{low_fp.status_code} with a substantive response from an admin-style route "
                                f"that identity {admin_ref!r} (role {roles[admin_ref]!r}) can also read."
                            ),
                            remediation=(
                                "Enforce role checks server-side for administrative routes and deny "
                                "requests from lower-privileged roles."
                            ),
                            scanner_source="authorization_idor",
                            metadata={
                                "low_role_identity": low_id,
                                "low_role": roles[low_id],
                                "admin_reference_identity": admin_ref,
                                "low_status": low_fp.status_code,
                            },
                        ).to_dict()
                    )

        # Rewrite-header probes are opt-in. X-Forwarded-For is deliberately
        # excluded because spoofing client IPs is not a reliable authorization test.
        bypass_probes: list[dict[str, Any]] = []
        if (
            enable_rewrite_probes
            and anonymous_fp is not None
            and anonymous_fp.status_code in {401, 403}
            and endpoint.path != "/"
            and authenticated_ids
        ):
            root_url = _origin_root(endpoint.url)
            if ctx.scope_engine.evaluate_url(root_url, check_dns=True).allowed:
                expected_identity = next(
                    (
                        identity_id
                        for identity_id in authenticated_ids
                        if identity_id in fingerprints
                        and is_substantive_success(fingerprints[identity_id])
                    ),
                    None,
                )
                expected_fp = fingerprints.get(expected_identity) if expected_identity else None

                if expected_fp is not None:
                    for header_name in REWRITE_HEADERS:
                        try:
                            response = clients["anonymous"].request(
                                "GET",
                                root_url,
                                stage_id=stage_def.stage_id,
                                headers={header_name: endpoint.path},
                                allow_redirects=False,
                            )
                        except ResourceLimitExceeded:
                            budget_exhausted = True
                            break
                        except (ScopeViolationError, requests.RequestException):
                            request_errors += 1
                            continue

                        probe_fp = ResponseFingerprint.from_response(
                            identity_id="anonymous",
                            url=root_url,
                            method="GET",
                            response=response,
                        )
                        bypassed = (
                            is_substantive_success(probe_fp)
                            and probe_fp.normalized_body_sha256
                            == expected_fp.normalized_body_sha256
                        )
                        bypass_probes.append(
                            {
                                "vector": header_name,
                                "baseline_status": anonymous_fp.status_code,
                                "probe_status": probe_fp.status_code,
                                "bypassed": bypassed,
                            }
                        )
                        if bypassed:
                            findings.append(
                                FindingRecord(
                                    title=f"Access-control bypass via {header_name} on {endpoint.path}",
                                    category="access_control_header_bypass",
                                    severity=Severity.HIGH,
                                    verdict=Verdict.LIKELY,
                                    confidence=0.86,
                                    asset_id=make_asset_id(endpoint.hostname),
                                    endpoint_id=endpoint.endpoint_id,
                                    identity_id="anonymous",
                                    description=(
                                        f"The direct anonymous request was denied, but a request to the same "
                                        f"origin using {header_name} returned the same response fingerprint "
                                        "as an authenticated identity."
                                    ),
                                    remediation=(
                                        "Strip untrusted rewrite headers at the reverse proxy and enforce "
                                        "authorization after final route resolution."
                                    ),
                                    scanner_source="authorization_idor",
                                    metadata={
                                        "vector": header_name,
                                        "target_path": endpoint.path,
                                        "baseline_status": anonymous_fp.status_code,
                                        "probe_status": probe_fp.status_code,
                                        "authenticated_identity": expected_identity,
                                    },
                                ).to_dict()
                            )
                    if budget_exhausted:
                        break

        matrix_tests.append(
            {
                "endpoint_id": endpoint.endpoint_id,
                "method": endpoint.method,
                "url": endpoint.url,
                "path": endpoint.path,
                "declared_protected": declared_protected,
                "owner_identity": owner_id,
                "responses_by_identity": {
                    key: value.to_dict()
                    for key, value in fingerprints.items()
                },
                "idor_probes": idor_probes,
                "header_bypass_probes": bypass_probes,
            }
        )

    # GraphQL query-root authorization matrix. Only introspected query fields with
    # no required arguments are queried; mutations and state-changing-looking names
    # are never executed. Responses are fingerprinted, not stored.
    graphql_field_checks: list[dict[str, Any]] = []
    graphql_incomplete = False
    graphql_ops = [
        operation for operation in operations
        if isinstance(operation, dict)
        and "graphql" in (operation.get("tags") or [])
        and "query" in (operation.get("tags") or [])
        and isinstance(operation.get("graphql_field"), str)
    ]
    max_graphql_fields = max(1, min(max_endpoints, 60))
    if len(graphql_ops) > max_graphql_fields:
        graphql_incomplete = True
    for operation in graphql_ops[:max_graphql_fields]:
        field_name = str(operation.get("graphql_field", ""))
        if (
            not GRAPHQL_SAFE_FIELD_RE.fullmatch(field_name)
            or field_name.startswith("__")
            or GRAPHQL_MUTATING_NAME_RE.search(field_name)
        ):
            graphql_incomplete = True
            graphql_field_checks.append({
                "operation_id": operation.get("operation_id", ""),
                "field": field_name[:128],
                "skipped": True,
                "reason": "Field name is invalid, introspection-only, or state-changing-looking.",
            })
            continue
        args = operation.get("graphql_args") or []
        if not isinstance(args, list) or any(
            isinstance(arg, dict) and arg.get("required") is True
            for arg in args
        ):
            graphql_incomplete = True
            graphql_field_checks.append({
                "operation_id": operation.get("operation_id", ""),
                "field": field_name,
                "skipped": True,
                "reason": "Field requires arguments; no synthetic argument values are generated.",
            })
            continue

        gql_url = str(operation.get("url", ""))
        try:
            decision = ctx.scope_engine.evaluate_url(gql_url, check_dns=True)
        except (TypeError, ValueError):
            continue
        if not decision.allowed:
            continue

        selection = " { __typename }" if operation.get("graphql_returns_object") else ""
        query = "{ " + field_name + selection + " }"
        per_identity: dict[str, Any] = {}
        for identity_id, client in clients.items():
            try:
                response = client.request(
                    "POST",
                    gql_url,
                    stage_id=stage_def.stage_id,
                    json_body={"query": query},
                    headers={"Accept": "application/json"},
                    allow_redirects=False,
                )
            except ResourceLimitExceeded:
                budget_exhausted = True
                break
            except (ScopeViolationError, requests.RequestException):
                request_errors += 1
                graphql_incomplete = True
                per_identity[identity_id] = {"request_error": True}
                continue

            fingerprint = ResponseFingerprint.from_response(
                identity_id=identity_id,
                url=gql_url,
                method="POST",
                response=response,
            )
            try:
                response_json = response.json()
                valid_json = isinstance(response_json, dict)
            except ValueError:
                response_json = {}
                valid_json = False
            if fingerprint.status_code >= 500 or not valid_json:
                graphql_incomplete = True
            data = response_json.get("data") if isinstance(response_json, dict) else None
            field_value = data.get(field_name) if isinstance(data, dict) else None
            errors = response_json.get("errors") if isinstance(response_json, dict) else None
            per_identity[identity_id] = {
                "status_code": fingerprint.status_code,
                "field_present": isinstance(data, dict) and field_name in data,
                "field_non_null": field_value is not None,
                "errors_count": len(errors) if isinstance(errors, list) else 0,
                "response_bytes": fingerprint.content_length,
                "response_sha256": fingerprint.normalized_body_sha256,
                "request_error": False,
            }
        graphql_field_checks.append({
            "operation_id": operation.get("operation_id", ""),
            "url": gql_url,
            "field": field_name,
            "query": query,
            "responses_by_identity": per_identity,
            "access_differs_by_identity": (
                len({
                    item.get("field_non_null")
                    for item in per_identity.values()
                    if isinstance(item, dict) and not item.get("request_error")
                }) > 1
            ),
            "finding_created": False,
            "note": (
                "Field-level response comparison only. A difference is not a vulnerability "
                "without declared data sensitivity and ownership/authorization evidence."
            ),
        })
        if budget_exhausted:
            break

    insufficient_identities = len(authenticated_ids) < 2
    status = (
        StageStatus.PARTIAL
        if budget_exhausted or insufficient_identities or graphql_incomplete or request_errors
        else StageStatus.SUCCESS
    )
    summary_suffix = (
        "fewer than two authenticated identities; horizontal IDOR coverage is incomplete"
        if insufficient_identities
        else "scan resource budget exhausted before all candidates were evaluated"
        if budget_exhausted
        else "GraphQL field coverage is incomplete; required-argument fields or failed requests were skipped"
        if graphql_incomplete
        else f"{request_errors} request(s) failed; authorization coverage is incomplete"
        if request_errors
        else "all configured identity comparisons completed"
    )

    payload: dict[str, Any] = {
        "schema_version": "1.1",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "identities_tested": sorted(clients),
        "authenticated_identities": authenticated_ids,
        "summary": {
            "endpoints_total": len(candidates),
            "endpoints_tested": tested_endpoints,
            "findings_count": len(findings),
            "horizontal_idor_attribution": "explicit_owned_resource_ids",
            "rewrite_header_probes_enabled": enable_rewrite_probes,
            "graphql_fields_checked": len(graphql_field_checks),
            "graphql_coverage_incomplete": graphql_incomplete,
            "request_errors": request_errors,
            "budget_exhausted": budget_exhausted,
        },
        "tests": matrix_tests,
        "graphql_field_access_checks": graphql_field_checks,
        "findings": findings,
    }
    ctx.workspace.write_json_atomic(
        "analysis/authorization_matrix.json",
        payload,
    )

    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Evaluated {tested_endpoints}/{len(candidates)} endpoint(s) across "
            f"{len(clients)} identity context(s); found {len(findings)} potential issue(s); "
            f"{summary_suffix}"
        ),
        artifacts=["analysis/authorization_matrix.json"],
        metrics={
            "targets_total": len(candidates),
            "targets_tested": tested_endpoints,
            "targets_skipped": len(candidates) - tested_endpoints,
        },
    )
