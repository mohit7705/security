from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import requests
import yaml

from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.utils.http_client import ScopedHttpClient

COMMON_SPEC_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api-docs",
)

MAX_SPEC_BYTES = 1_500_000
MAX_SPEC_CANDIDATES = 120
MAX_SPEC_OPERATIONS = 3000

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


@dataclass
class ApiOperationRecord:
    operation_id: str
    method: str
    url: str
    path: str
    source: str  # "openapi", "graphql", "javascript", "browser_network"
    requires_auth: bool | None = None
    security_schemes: list[str] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    path_params: list[str] = field(default_factory=list)
    body_fields: list[str] = field(default_factory=list)
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    graphql_field: str = ""
    graphql_args: list[dict[str, Any]] = field(default_factory=list)
    graphql_return_kind: str = ""
    graphql_return_type: str = ""
    graphql_returns_object: bool = False
    request_content_type: str = ""
    request_body_schema: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_oversize_error(exc: Exception) -> bool:
    """ResourceLimitExceeded is used for one oversized body AND for the scan-wide budget."""
    return "Response body" in str(exc)


class OpenApiAnalyzer:
    """Discovers and parses OpenAPI 3.x / Swagger 2.0 specifications into structured API operations."""

    def __init__(
        self,
        client: ScopedHttpClient,
        stage_id: str = "api_js_intelligence",
        *,
        check_dns: bool = True,
    ) -> None:
        self.client = client
        self.stage_id = stage_id
        self.check_dns = check_dns
        self.deadline: float | None = None
        self.deadline_hit = False
        self.budget_exhausted = False
        self.oversize_skipped = 0
        self._scope_cache: dict[str, bool] = {}

    def _expired(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline

    def _allowed(self, url: str) -> bool:
        cached = self._scope_cache.get(url)
        if cached is not None:
            return cached
        try:
            ok = self.client.scope_engine.evaluate_url(url, check_dns=self.check_dns).allowed
        except (TypeError, ValueError):
            ok = False
        self._scope_cache[url] = ok
        return ok

    @staticmethod
    def _parse_spec_document(raw_text: str, content_type: str) -> dict[str, Any] | None:
        trimmed = raw_text.strip()
        if not trimmed:
            return None
        try:
            if "json" in content_type.lower() or trimmed.startswith("{"):
                loaded = json.loads(trimmed)
            else:
                loaded = yaml.safe_load(trimmed)
        except Exception:
            return None

        if not isinstance(loaded, dict):
            return None
        if ("openapi" in loaded or "swagger" in loaded) and isinstance(loaded.get("paths"), dict):
            return loaded
        return None

    def discover_and_parse(
        self,
        base_urls: list[str],
        candidate_spec_urls: list[str] | None = None,
    ) -> tuple[list[dict[str, Any]], list[ApiOperationRecord], list[dict[str, Any]]]:
        candidates: list[str] = []
        seen: set[str] = set()

        for u in candidate_spec_urls or []:
            if self._allowed(u) and u not in seen:
                seen.add(u)
                candidates.append(u)

        for base in base_urls:
            parsed = urlsplit(base)
            if not parsed.scheme or not parsed.netloc:
                continue
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for suffix in COMMON_SPEC_PATHS:
                full = urljoin(origin, suffix)
                if self._allowed(full) and full not in seen:
                    seen.add(full)
                    candidates.append(full)

        discovered_specs: list[dict[str, Any]] = []
        operations: list[ApiOperationRecord] = []
        findings: list[dict[str, Any]] = []

        for spec_url in candidates[:MAX_SPEC_CANDIDATES]:
            if self._expired():
                self.deadline_hit = True
                break
            try:
                resp = self.client.get(spec_url, stage_id=self.stage_id)
            except ResourceLimitExceeded as exc:
                if is_oversize_error(exc):
                    self.oversize_skipped += 1
                    continue
                self.budget_exhausted = True
                break
            except (ScopeViolationError, requests.RequestException):
                continue

            if resp.status_code != 200:
                continue

            if len(resp.content) > MAX_SPEC_BYTES:
                continue
            spec = self._parse_spec_document(resp.text, resp.headers.get("Content-Type", ""))
            if spec is None:
                continue

            spec_version = str(spec.get("openapi") or spec.get("swagger") or "unknown")
            global_security = spec.get("security")
            has_global_security = isinstance(global_security, list) and any(bool(item) for item in global_security if isinstance(item, dict))

            # Resolve the API origin and base path. Swagger 2.0 uses host/basePath/schemes;
            # OpenAPI 3.x uses servers. Never trust a declared server until it passes scope.
            spec_parts = urlsplit(spec_url)
            origin = f"{spec_parts.scheme}://{spec_parts.netloc}"
            base_prefix = ""
            if str(spec.get("swagger", "")).startswith("2"):
                swagger_host = str(spec.get("host") or spec_parts.netloc).strip()
                swagger_schemes = spec.get("schemes")
                candidate_schemes = (
                    [str(item).lower() for item in swagger_schemes
                     if isinstance(item, str) and str(item).lower() in {"http", "https"}]
                    if isinstance(swagger_schemes, list)
                    else []
                ) or [spec_parts.scheme]
                candidate_origin = next(
                    (
                        f"{scheme}://{swagger_host}"
                        for scheme in candidate_schemes
                        if self._allowed(f"{scheme}://{swagger_host}/")
                    ),
                    "",
                )
                if candidate_origin:
                    origin = candidate_origin
                else:
                    findings.append({
                        "category": "out_of_scope_spec_server",
                        "severity": "INFO",
                        "url": spec_url,
                        "title": "Ignored out-of-scope Swagger server",
                        "details": "Swagger host/scheme was excluded from endpoint inventory.",
                    })
                    continue
                base_prefix = str(spec.get("basePath") or "").rstrip("/")
            elif isinstance(spec.get("servers"), list) and spec["servers"]:
                selected_server: tuple[str, str] | None = None
                for server_obj in spec["servers"][:20]:
                    if not isinstance(server_obj, dict) or not isinstance(server_obj.get("url"), str):
                        continue
                    server_url = server_obj["url"].strip()
                    variables = server_obj.get("variables", {})
                    if not isinstance(variables, dict):
                        variables = {}

                    def replace_server_variable(match: re.Match[str]) -> str:
                        variable = variables.get(match.group(1))
                        if not isinstance(variable, dict) or "default" not in variable:
                            return match.group(0)
                        return quote(str(variable["default"]), safe=".-_~")

                    server_url = re.sub(r"\{([^{}]+)\}", replace_server_variable, server_url)
                    if "{" in server_url or "}" in server_url:
                        continue
                    resolved_server = urljoin(origin + "/", server_url)
                    resolved_parts = urlsplit(resolved_server)
                    if (
                        not resolved_parts.scheme
                        or not resolved_parts.netloc
                        or resolved_parts.query
                        or resolved_parts.fragment
                        or not self._allowed(resolved_server)
                    ):
                        findings.append({
                            "category": "out_of_scope_spec_server",
                            "severity": "INFO",
                            "url": spec_url,
                            "title": "Ignored out-of-scope OpenAPI server",
                            "details": "Server URL was excluded from endpoint inventory.",
                        })
                        continue
                    selected_server = (
                        f"{resolved_parts.scheme}://{resolved_parts.netloc}",
                        (resolved_parts.path or "").rstrip("/"),
                    )
                    break
                if selected_server is None:
                    # Do not silently substitute the documentation host when the
                    # specification declares only unusable/out-of-scope API servers.
                    continue
                origin, base_prefix = selected_server
            elif isinstance(spec.get("basePath"), str):
                base_prefix = spec["basePath"].rstrip("/")

            parsed_ops_count = 0
            unauthenticated_ops: list[str] = []

            for raw_path, path_item in (spec.get("paths") or {}).items():
                if parsed_ops_count >= MAX_SPEC_OPERATIONS:
                    break
                if not isinstance(raw_path, str) or not raw_path.startswith("/") or "?" in raw_path or "#" in raw_path:
                    continue
                if not isinstance(path_item, dict):
                    continue
                path_item = self._resolve_local_ref(path_item, spec)
                if not isinstance(path_item, dict):
                    continue
                shared_params = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []

                for method_key, op_obj in path_item.items():
                    method_lower = str(method_key).lower()
                    if method_lower not in HTTP_METHODS or not isinstance(op_obj, dict):
                        continue

                    if parsed_ops_count >= MAX_SPEC_OPERATIONS:
                        break
                    method_upper = method_lower.upper()
                    full_path = f"{base_prefix}/{str(raw_path).lstrip('/')}".replace("//", "/")
                    if not full_path.startswith("/"):
                        full_path = f"/{full_path}"
                    if "?" in full_path or "#" in full_path or "\\" in full_path:
                        continue
                    op_url = f"{origin}{full_path}"
                    # Scope-check a concrete template substitution without contacting it.
                    scope_url = re.sub(r"\{[^{}]+\}", "1", op_url)
                    if not self._allowed(scope_url):
                        continue

                    op_security = op_obj.get("security")
                    if op_security is not None:
                        requires_auth = isinstance(op_security, list) and any(bool(item) for item in op_security if isinstance(item, dict))
                        schemes = [key for entry in (op_security if isinstance(op_security, list) else []) if isinstance(entry, dict) for key in entry]
                    else:
                        requires_auth = has_global_security if isinstance(global_security, list) else None
                        schemes = [key for entry in (global_security if isinstance(global_security, list) else []) if isinstance(entry, dict) for key in entry]

                    query_params: list[str] = []
                    path_params: list[str] = []
                    op_params = op_obj.get("parameters") if isinstance(op_obj.get("parameters"), list) else []
                    for raw_param in [*shared_params, *op_params]:
                        param = self._resolve_local_ref(raw_param, spec)
                        if not isinstance(param, dict):
                            continue
                        p_name = str(param.get("name", "")).strip()
                        p_in = str(param.get("in", "")).strip().lower()
                        if p_name and p_in == "query":
                            query_params.append(p_name)
                        elif p_name and p_in == "path":
                            path_params.append(p_name)

                    body_fields = self._extract_body_properties(
                        op_obj,
                        spec,
                        shared_parameters=shared_params,
                    )
                    request_content_type = self._request_content_type(op_obj, spec)
                    op_id = str(op_obj.get("operationId") or f"{method_upper}_{full_path}")

                    operations.append(
                        ApiOperationRecord(
                            operation_id=op_id,
                            method=method_upper,
                            url=op_url,
                            path=full_path,
                            source="openapi",
                            requires_auth=requires_auth,
                            security_schemes=sorted(set(schemes)),
                            query_params=sorted(set(query_params)),
                            path_params=sorted(set(path_params)),
                            body_fields=sorted(set(body_fields)),
                            request_content_type=request_content_type,
                            request_body_schema={
                                "fields": sorted(set(body_fields)),
                            } if body_fields else {},
                            summary=str(op_obj.get("summary", ""))[:200],
                            tags=[str(t) for t in (op_obj.get("tags") or [])],
                        )
                    )
                    parsed_ops_count += 1
                    if requires_auth is False:
                        unauthenticated_ops.append(f"{method_upper} {full_path}")

            discovered_specs.append(
                {
                    "spec_url": spec_url,
                    "spec_version": spec_version,
                    "title": str((spec.get("info") or {}).get("title", "")),
                    "operations_count": parsed_ops_count,
                    "unauthenticated_operations_count": len(unauthenticated_ops),
                }
            )

            findings.append(
                {
                    "category": "api_specification_discovered",
                    "severity": "INFO",
                    "url": spec_url,
                    "title": f"Accessible OpenAPI/Swagger specification ({spec_version})",
                    "details": f"Parsed {parsed_ops_count} operation(s); {len(unauthenticated_ops)} explicitly declare no authentication. This is inventory metadata, not a confirmed vulnerability.",
                    "sample_unauthenticated_operations": unauthenticated_ops[:15],
                }
            )

        return discovered_specs, operations, findings

    @staticmethod
    def _resolve_local_ref(value: Any, spec: dict[str, Any]) -> Any:
        """Resolve a bounded local JSON Pointer; external references are never fetched."""
        if not isinstance(value, dict) or not isinstance(value.get("$ref"), str):
            return value
        ref = value["$ref"]
        if not ref.startswith("#/") or len(ref) > 1024:
            return None
        current: Any = spec
        try:
            for raw_part in ref[2:].split("/"):
                part = raw_part.replace("~1", "/").replace("~0", "~")
                if not isinstance(current, dict) or part not in current:
                    return None
                current = current[part]
        except (TypeError, KeyError):
            return None
        return current

    @staticmethod
    def _request_content_type(op_obj: dict[str, Any], spec: dict[str, Any]) -> str:
        request_body = op_obj.get("requestBody")
        if isinstance(request_body, dict):
            resolved = OpenApiAnalyzer._resolve_local_ref(request_body, spec)
            content = resolved.get("content") if isinstance(resolved, dict) else None
            if isinstance(content, dict) and content:
                return str(next(iter(content.keys())))[:128]
        consumes = op_obj.get("consumes", spec.get("consumes", []))
        if isinstance(consumes, list):
            for item in consumes:
                if isinstance(item, str) and item.strip():
                    return item.strip()[:128]
        return ""

    @classmethod
    def _extract_body_properties(
        cls,
        op_obj: dict[str, Any],
        spec: dict[str, Any] | None = None,
        *,
        shared_parameters: list[Any] | None = None,
    ) -> list[str]:
        """Collect property names from OpenAPI 3 and Swagger 2 request schemas.

        Local refs and composition keywords are followed with cycle/depth bounds.
        External refs are intentionally ignored.
        """
        spec = spec or {}
        fields: set[str] = set()
        visited: set[str] = set()

        def walk_schema(schema: Any, depth: int = 0) -> None:
            if depth > 12 or not isinstance(schema, dict):
                return
            ref = schema.get("$ref")
            if isinstance(ref, str):
                if ref in visited:
                    return
                visited.add(ref)
                walk_schema(cls._resolve_local_ref(schema, spec), depth + 1)
                return

            props = schema.get("properties")
            if isinstance(props, dict):
                for name, child in props.items():
                    if isinstance(name, str):
                        fields.add(name[:128])
                    walk_schema(child, depth + 1)

            for key in ("items", "additionalProperties", "not"):
                child = schema.get(key)
                if isinstance(child, dict):
                    walk_schema(child, depth + 1)
            for key in ("allOf", "oneOf", "anyOf"):
                children = schema.get(key)
                if isinstance(children, list):
                    for child in children[:100]:
                        walk_schema(child, depth + 1)

        request_body = op_obj.get("requestBody")
        if isinstance(request_body, dict):
            request_body = cls._resolve_local_ref(request_body, spec)
            content = request_body.get("content") if isinstance(request_body, dict) else None
            if isinstance(content, dict):
                for media_obj in list(content.values())[:30]:
                    if isinstance(media_obj, dict):
                        walk_schema(media_obj.get("schema"))

        # Swagger 2.0 request bodies are parameters with in: body/formData.
        params = [
            *(shared_parameters or []),
            *(op_obj.get("parameters") if isinstance(op_obj.get("parameters"), list) else []),
        ]
        if params:
            for raw_param in params[:200]:
                param = cls._resolve_local_ref(raw_param, spec)
                if not isinstance(param, dict):
                    continue
                if str(param.get("in", "")).lower() == "body":
                    walk_schema(param.get("schema"))
                elif str(param.get("in", "")).lower() == "formdata":
                    name = param.get("name")
                    if isinstance(name, str):
                        fields.add(name[:128])

        return sorted(fields)