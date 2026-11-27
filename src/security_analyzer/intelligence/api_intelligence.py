from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.authentication.identity_context import load_auth_profiles
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.intelligence.graphql_analyzer import GraphQlAnalyzer
from security_analyzer.intelligence.js_bundle_analyzer import JsBundleAnalyzer
from security_analyzer.intelligence.openapi_analyzer import ApiOperationRecord, OpenApiAnalyzer
from security_analyzer.utils.http_client import ScopedHttpClient


_TEMPLATE_PARAMETER_RE = re.compile(r"\{([^{}]+)\}")
# The old pattern `id$` matched any name ending in "id" (paid, valid, grid, invalid).
_ID_PARAMETER_RE = re.compile(
    r"(?:(?i:^id$|[_-]id$|uuid|^key$|[_-]key$"
    r"|(?:user|account|order|customer|item|post|product|resource|object|session|doc|file|team|org|tenant|project|invoice|comment|ticket|message|record|entity)id$)"
    r"|[a-z]Id$|[a-z]ID$)"
)


def _concrete_route_variants(route_url: str, owned_ids: list[str]) -> list[str]:
    """Replace every path template token before an endpoint can enter active checks."""
    parameter_names = _TEMPLATE_PARAMETER_RE.findall(route_url)
    if not parameter_names:
        return [route_url]
    id_parameters = [name for name in parameter_names if _ID_PARAMETER_RE.search(name)]
    samples = list(dict.fromkeys(owned_ids))[:100] if id_parameters else ["1"]
    if not samples:
        samples = ["1"]

    concrete: list[str] = []
    for sample in samples:
        candidate = route_url
        for name in parameter_names:
            replacement = quote(sample, safe="") if name in id_parameters else "1"
            candidate = candidate.replace("{" + name + "}", replacement)
        if not _TEMPLATE_PARAMETER_RE.search(candidate) and "{" not in candidate and "}" not in candidate:
            concrete.append(candidate)
    return list(dict.fromkeys(concrete))



def run_api_js_intelligence(ctx: ExecutionContext, stage_def: StageDefinition) -> StageResult:
    """Stage 11: Builds structured API catalog (OpenAPI, GraphQL, JS, browser XHR) and updates inventory."""
    inventory = UnifiedEndpointInventory(ctx.workspace)
    normalizer = EndpointNormalizer(
        ctx.scope_engine,
        ctx.coverage,
        check_dns=bool(ctx.config.get("scope", {}).get("check_dns", False)),
    )

    timeouts = ctx.config.get("timeouts", {})
    limits = ctx.config.get("limits", {})
    client = ScopedHttpClient(
        ctx.scope_engine,
        coverage=ctx.coverage,
        connect_timeout=float(timeouts.get("http_connect_sec", 10)),
        read_timeout=float(timeouts.get("http_read_sec", 20)),
        max_redirects=int(timeouts.get("max_redirects", 5)),
        check_dns=bool(ctx.config.get("scope", {}).get("check_dns", False)),
        governor=ctx.resource_governor,
    )

    check_dns = bool(ctx.config.get("scope", {}).get("check_dns", False))
    stage_deadline = time.monotonic() + float(timeouts.get("api_intel_stage_sec", 600))
    api_inventory_cap = int(limits.get("max_api_inventory_endpoints", 5000))
    inventory_added = 0
    inventory_cap_hit = False

    all_eps = inventory.get_endpoints()
    base_urls = sorted({f"{ep.scheme}://{ep.hostname}" + (f":{ep.port}" if ep.port not in {80, 443} else "") for ep in all_eps})[:100]
    if not base_urls:
        base_urls = [ctx.target]

    known_urls = [ep.url for ep in all_eps][:2000]
    html_pages = [ep.url for ep in all_eps if ep.reachable and "html" in ep.content_type.lower()][:30] or base_urls
    candidate_specs = [
        url for url in known_urls
        if "{" not in url and "}" not in url
        and any(marker in url.lower() for marker in ("openapi", "swagger", "api-docs"))
    ]
    candidate_gql = [
        url for url in known_urls
        if "{" not in url and "}" not in url and "graphql" in url.lower()
    ]

    openapi_analyzer = OpenApiAnalyzer(client, stage_id=stage_def.stage_id, check_dns=check_dns)
    openapi_analyzer.deadline = stage_deadline
    specs, openapi_ops, openapi_findings = openapi_analyzer.discover_and_parse(base_urls, candidate_specs)

    graphql_analyzer = GraphQlAnalyzer(client, stage_id=stage_def.stage_id, check_dns=check_dns)
    graphql_analyzer.deadline = stage_deadline
    gql_endpoints, gql_ops, gql_findings = graphql_analyzer.analyze(base_urls, candidate_gql)

    js_analyzer = JsBundleAnalyzer(
        client,
        stage_id=stage_def.stage_id,
        max_bundles=int(limits.get("max_js_bundles", 30)),
        check_dns=check_dns,
    )
    js_analyzer.deadline = stage_deadline
    bundle_urls = js_analyzer.discover_bundle_urls(html_pages, known_urls)
    bundle_records, js_routes, js_findings = js_analyzer.analyze_bundles(bundle_urls)

    owned_ids: list[str] = []
    profiles_path = ctx.config.get("auth_profiles_path")
    if profiles_path:
        try:
            profiles, _ = load_auth_profiles(Path(str(profiles_path)))
            for profile in profiles.values():
                owned_ids.extend(
                    str(resource_id)
                    for resource_id in profile.owned_resource_ids
                    if str(resource_id)
                )
        except Exception:
            # The authentication lifecycle reports invalid profiles; discovery remains
            # conservative and uses the generic sample if no valid owned IDs are available.
            owned_ids = []

    # Keep every explicitly configured resource ID available for endpoint
    # inventory construction. A bounded unique set prevents profile mistakes
    # from multiplying endpoint records without limit.
    owned_ids = list(dict.fromkeys(owned_ids))[:100]
    id_parameter_re = _ID_PARAMETER_RE

    def _owned_id_variants(operation: ApiOperationRecord) -> list[str]:
        """Return one concrete URL per configured owned ID, never a {id} template."""
        id_params = [
            name for name in operation.path_params
            if id_parameter_re.search(str(name))
        ]
        values = owned_ids or ["1"]
        if not id_params:
            values = ["1"]

        variants: list[str] = []
        for owned_id in values:
            concrete_url = operation.url
            for param_name in operation.path_params:
                replacement = quote(owned_id, safe="") if param_name in id_params else "1"
                concrete_url = concrete_url.replace(f"{{{param_name}}}", replacement)
            if operation.query_params:
                q_str = "&".join(f"{key}=1" for key in operation.query_params)
                concrete_url = f"{concrete_url}{'&' if '?' in concrete_url else '?'}{q_str}"
            if "{" not in concrete_url and "}" not in concrete_url:
                variants.append(concrete_url)
        return list(dict.fromkeys(variants))[:100]

    # Merge all discovered API operations and JS routes into UnifiedEndpointInventory
    all_operations: list[ApiOperationRecord] = [*openapi_ops, *gql_ops]

    for route_url in js_routes[:2000]:
        if inventory_cap_hit:
            break
        for concrete_route in _concrete_route_variants(route_url, owned_ids):
            if inventory_added >= api_inventory_cap:
                inventory_cap_hit = True
                break
            ep = normalizer.normalize(
                concrete_route,
                method="GET",
                source="javascript_intel",
                stage_id=stage_def.stage_id,
                evidence_ref="analysis/javascript_intel.json",
                tags=["api_candidate", "js_extracted"],
            )
            if ep is not None:
                inventory_added += 1
                inventory.upsert_endpoint(ep)
                all_operations.append(
                    ApiOperationRecord(
                        operation_id=f"js.{ep.endpoint_id}",
                        method="GET",
                        url=ep.url,
                        path=ep.path,
                        source="javascript",
                        query_params=ep.query_param_names,
                        tags=["js_extracted"],
                    )
                )

    for op in [*openapi_ops, *gql_ops][:5000]:
        # Inventory all configured owned resource IDs so later identity-aware
        # authorization checks can select the correct actor-owned resource.
        if inventory_cap_hit:
            break
        for concrete_url in _owned_id_variants(op):
            if inventory_added >= api_inventory_cap:
                inventory_cap_hit = True
                break
            ep = normalizer.normalize(
                concrete_url,
                method=op.method,
                source=f"api_spec:{op.source}",
                stage_id=stage_def.stage_id,
                request_content_type=op.request_content_type or (
                    "application/json" if op.source == "graphql" else ""
                ),
                request_body_schema=op.request_body_schema,
                evidence_ref="analysis/api_catalog.json",
                tags=[
                    "api_operation",
                    op.source,
                    *op.tags,
                    *([f"template:{op.path}"] if op.path_params else []),
                ],
            )
            if ep is not None:
                inventory_added += 1
                inventory.upsert_endpoint(ep)

    # Include browser-captured API candidates already in inventory
    known_ops = {(o.url, o.method) for o in all_operations}  # set lookup instead of O(n^2) scan
    for ep in inventory.get_endpoints():
        if "api_candidate" in ep.tags and (ep.url, ep.method) not in known_ops:
            known_ops.add((ep.url, ep.method))
            all_operations.append(
                ApiOperationRecord(
                    operation_id=f"obs.{ep.endpoint_id}",
                    method=ep.method,
                    url=ep.url,
                    path=ep.path,
                    source="observed_traffic",
                    query_params=ep.query_param_names,
                    tags=list(ep.tags),
                )
            )

    combined_findings = [*openapi_findings, *gql_findings, *js_findings]

    analyzers = (openapi_analyzer, graphql_analyzer, js_analyzer)
    budget_exhausted = any(a.budget_exhausted for a in analyzers)
    deadline_hit = any(a.deadline_hit for a in analyzers)
    oversize_skipped = sum(a.oversize_skipped for a in analyzers)
    if budget_exhausted:
        ctx.coverage.record_skipped_check(stage_def.stage_id, "http_resource_budget", "Scan-wide resource budget exhausted during API/JS discovery")
    if deadline_hit:
        ctx.coverage.record_skipped_check(stage_def.stage_id, "api_intel_stage_budget", "API/JS discovery stopped at the stage time budget")
    if inventory_cap_hit:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "max_api_inventory_endpoints",
            f"API inventory expansion capped at {api_inventory_cap} endpoint(s)",
        )
    if oversize_skipped:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "oversize_responses",
            f"{oversize_skipped} spec/bundle/source-map response(s) exceeded the response size limit and were skipped",
        )

    api_catalog_payload: dict[str, Any] = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "openapi_specs": specs,
        "graphql_endpoints": gql_endpoints,
        "total_operations": len(all_operations),
        "operations": [op.to_dict() for op in all_operations],
        "findings": combined_findings,
        "budget_exhausted": budget_exhausted,
        "deadline_hit": deadline_hit,
        "oversize_skipped": oversize_skipped,
        "inventory_cap_hit": inventory_cap_hit,
    }
    js_intel_payload: dict[str, Any] = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "bundles_analyzed": len(bundle_records),
        "extracted_routes_count": len(js_routes),
        "bundles": bundle_records,
        "findings": js_findings,
    }

    ctx.workspace.write_json_atomic("analysis/api_catalog.json", api_catalog_payload)
    ctx.workspace.write_json_atomic("analysis/javascript_intel.json", js_intel_payload)
    inv_saved = inventory.save(stage_id=stage_def.stage_id)

    no_discovery = not all_operations and not bundle_records
    # An application with no API/JS surface is a valid result; only a truncated run is PARTIAL.
    status = (
        StageStatus.PARTIAL
        if budget_exhausted or deadline_hit or inventory_cap_hit or not base_urls
        else StageStatus.SUCCESS
    )
    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Cataloged {len(all_operations)} API operation(s) ({len(specs)} OpenAPI spec(s), "
            f"{len(gql_endpoints)} GraphQL endpoint(s), {len(bundle_records)} JS bundle(s)); "
            f"inventory now has {inv_saved['summary']['total_endpoints']} endpoint(s)"
            + ("; no API operations or JavaScript bundles were discovered" if no_discovery else "")
        ),
        artifacts=["analysis/api_catalog.json", "analysis/javascript_intel.json", "inventory/unified_endpoints.json", "inventory/contributions/api_js_intelligence.json"],
        metrics={
            "targets_total": len(base_urls) + len(bundle_urls),
            "targets_tested": len(base_urls) + len(bundle_records),
            "targets_skipped": max(0, len(bundle_urls) - len(bundle_records)),
            "oversize_skipped": oversize_skipped,
        },
    )