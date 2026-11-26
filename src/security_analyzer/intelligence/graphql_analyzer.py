from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.intelligence.openapi_analyzer import ApiOperationRecord
from security_analyzer.utils.http_client import ScopedHttpClient

COMMON_GRAPHQL_PATHS: tuple[str, ...] = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/graphql/api",
)

TYPENAME_QUERY = {"query": "{__typename}"}

BOUNDED_INTROSPECTION_QUERY = {
    "query": """
    query BoundedIntrospection {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields {
            name
            args {
              name
              defaultValue
              type {
                kind
                name
                ofType { kind name ofType { kind name ofType { kind name } } }
              }
            }
            type {
              kind
              name
              ofType { kind name ofType { kind name ofType { kind name } } }
            }
          }
        }
      }
    }
    """
}


def _type_ref_label(type_ref: Any) -> tuple[str, str]:
    """Return the named GraphQL type and outer named kind from a bounded type-ref chain."""
    current = type_ref
    outer_kind = str(current.get("kind", "")) if isinstance(current, dict) else ""
    depth = 0
    while isinstance(current, dict) and depth < 8:
        if current.get("name"):
            return outer_kind or str(current.get("kind", "")), str(current["name"])
        current = current.get("ofType")
        depth += 1
    return outer_kind, ""


def _field_is_object(field: dict[str, Any], type_by_name: dict[str, dict[str, Any]]) -> bool:
    kind, name = _type_ref_label(field.get("type"))
    named = type_by_name.get(name, {})
    return str(named.get("kind", "")) in {"OBJECT", "INTERFACE", "UNION"} or kind in {"OBJECT", "INTERFACE", "UNION"}


class GraphQlAnalyzer:
    """Detects GraphQL endpoints, tests read-only introspection exposure, and extracts query/mutation operations."""

    def __init__(self, client: ScopedHttpClient, stage_id: str = "api_js_intelligence") -> None:
        self.client = client
        self.stage_id = stage_id

    def analyze(
        self,
        base_urls: list[str],
        candidate_graphql_urls: list[str] | None = None,
    ) -> tuple[list[dict[str, Any]], list[ApiOperationRecord], list[dict[str, Any]]]:
        candidates: list[str] = []
        seen: set[str] = set()

        for u in candidate_graphql_urls or []:
            if self.client.scope_engine.evaluate_url(u, check_dns=True).allowed and u not in seen:
                seen.add(u)
                candidates.append(u)

        for base in base_urls:
            parsed = urlsplit(base)
            if not parsed.scheme or not parsed.netloc:
                continue
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for suffix in COMMON_GRAPHQL_PATHS:
                full = urljoin(origin, suffix)
                if self.client.scope_engine.evaluate_url(full, check_dns=True).allowed and full not in seen:
                    seen.add(full)
                    candidates.append(full)

        endpoints_info: list[dict[str, Any]] = []
        operations: list[ApiOperationRecord] = []
        findings: list[dict[str, Any]] = []

        for gql_url in candidates[:100]:
            try:
                probe = self.client.request(
                    "POST",
                    gql_url,
                    stage_id=self.stage_id,
                    json_body=TYPENAME_QUERY,
                    headers={"Accept": "application/json"},
                )
            except (ScopeViolationError, requests.RequestException):
                continue

            if probe.status_code not in {200, 400}:
                continue

            try:
                body = probe.json()
            except ValueError:
                continue

            if not isinstance(body, dict) or not isinstance(body.get("data"), dict) or "__typename" not in body["data"]:
                continue

            # Confirmed GraphQL endpoint; test bounded schema introspection
            introspection_enabled = False
            query_fields: list[str] = []
            mutation_fields: list[str] = []
            query_field_records: list[dict[str, Any]] = []
            mutation_field_records: list[dict[str, Any]] = []

            try:
                intro_resp = self.client.request(
                    "POST",
                    gql_url,
                    stage_id=self.stage_id,
                    json_body=BOUNDED_INTROSPECTION_QUERY,
                    headers={"Accept": "application/json"},
                )
                if intro_resp.status_code == 200:
                    intro_json = intro_resp.json()
                    schema_data = (intro_json.get("data") or {}).get("__schema") if isinstance(intro_json, dict) and isinstance(intro_json.get("data"), dict) else None
                    if isinstance(schema_data, dict):
                        introspection_enabled = True
                        q_type_name = ((schema_data.get("queryType") or {}).get("name")) or "Query"
                        m_type_name = ((schema_data.get("mutationType") or {}).get("name")) or "Mutation"
                        type_by_name = {
                            str(item.get("name")): item
                            for item in (schema_data.get("types") or [])[:1000]
                            if isinstance(item, dict) and isinstance(item.get("name"), str)
                        }
                        query_field_records: list[dict[str, Any]] = []
                        mutation_field_records: list[dict[str, Any]] = []
                        for t_obj in (schema_data.get("types") or [])[:1000]:
                            if not isinstance(t_obj, dict):
                                continue
                            t_name = str(t_obj.get("name", ""))
                            if t_name not in {q_type_name, m_type_name}:
                                continue
                            target = query_field_records if t_name == q_type_name else mutation_field_records
                            for field_obj in (
                                t_obj.get("fields")
                                if isinstance(t_obj.get("fields"), list)
                                else []
                            )[:200]:
                                if not isinstance(field_obj, dict) or not isinstance(field_obj.get("name"), str):
                                    continue
                                args: list[dict[str, Any]] = []
                                for arg in (field_obj.get("args") if isinstance(field_obj.get("args"), list) else [])[:100]:
                                    if not isinstance(arg, dict) or not isinstance(arg.get("name"), str):
                                        continue
                                    arg_kind, arg_name = _type_ref_label(arg.get("type"))
                                    args.append({
                                        "name": arg["name"][:128],
                                        "type": arg_name,
                                        "required": arg_kind == "NON_NULL" and arg.get("defaultValue") is None,
                                    })
                                return_kind, return_name = _type_ref_label(field_obj.get("type"))
                                target.append({
                                    "name": field_obj["name"][:128],
                                    "args": args,
                                    "return_kind": return_kind,
                                    "return_type": return_name,
                                    "returns_object": _field_is_object(field_obj, type_by_name),
                                })
                        query_field_records = sorted(query_field_records, key=lambda item: item["name"])
                        mutation_field_records = sorted(mutation_field_records, key=lambda item: item["name"])
                        query_fields = [item["name"] for item in query_field_records]
                        mutation_fields = [item["name"] for item in mutation_field_records]
            except Exception:
                introspection_enabled = False

            parsed_path = urlsplit(gql_url).path or "/graphql"
            endpoints_info.append(
                {
                    "url": gql_url,
                    "introspection_enabled": introspection_enabled,
                    "query_fields_count": len(query_fields),
                    "mutation_fields_count": len(mutation_fields),
                    "query_fields": query_fields[:100],
                    "mutation_fields": mutation_fields[:100],
                    "query_field_details": query_field_records[:100],
                    "mutation_field_details": mutation_field_records[:100],
                }
            )

            for field_info in query_field_records[:100]:
                q_field = field_info["name"]
                operations.append(
                    ApiOperationRecord(
                        operation_id=f"graphql.query.{q_field}",
                        method="POST",
                        url=gql_url,
                        path=parsed_path,
                        source="graphql",
                        summary=f"GraphQL Query: {q_field}",
                        tags=["graphql", "query"],
                        graphql_field=q_field,
                        graphql_args=field_info["args"],
                        graphql_return_kind=field_info["return_kind"],
                        graphql_return_type=field_info["return_type"],
                        graphql_returns_object=field_info["returns_object"],
                    )
                )
            for field_info in mutation_field_records[:100]:
                m_field = field_info["name"]
                operations.append(
                    ApiOperationRecord(
                        operation_id=f"graphql.mutation.{m_field}",
                        method="POST",
                        url=gql_url,
                        path=parsed_path,
                        source="graphql",
                        summary=f"GraphQL Mutation: {m_field}",
                        tags=["graphql", "mutation"],
                        graphql_field=m_field,
                        graphql_args=field_info["args"],
                        graphql_return_kind=field_info["return_kind"],
                        graphql_return_type=field_info["return_type"],
                        graphql_returns_object=field_info["returns_object"],
                    )
                )

            if introspection_enabled:
                findings.append(
                    {
                        "category": "graphql_introspection_enabled",
                        "severity": "INFO",
                        "url": gql_url,
                        "title": "GraphQL schema introspection available (informational)",
                        "details": (
                            f"Introspection returned {len(query_fields)} query field(s) and "
                            f"{len(mutation_fields)} mutation field(s). Exposure alone is not a confirmed vulnerability."
                        ),
                    }
                )

        return endpoints_info, operations, findings
