from __future__ import annotations

import copy
import threading
from datetime import datetime, timezone
from typing import Any

from security_analyzer.core.exceptions import ArtifactValidationError
from security_analyzer.core.workspace import WorkspaceManager
from security_analyzer.models.asset import AssetRecord, make_asset_id
from security_analyzer.models.endpoint import EndpointRecord


class UnifiedEndpointInventory:
    """Thread-safe, scan-scoped canonical asset and endpoint inventory."""

    RELATIVE_PATH = "inventory/unified_endpoints.json"
    SCHEMA_VERSION = "1.2"
    CONTRIBUTION_DIR = "inventory/contributions"

    @classmethod
    def contribution_path(cls, stage_id: str) -> str:
        raw = str(stage_id).lower()
        clean = "".join(ch for ch in raw if ch.isalnum() or ch in "_-")
        if not clean or clean != raw:
            raise ValueError("stage_id must contain only letters, digits, underscores or hyphens")
        return f"{cls.CONTRIBUTION_DIR}/{clean}.json"

    def __init__(self, workspace: WorkspaceManager) -> None:
        self.workspace = workspace
        self._lock = threading.RLock()

        self._assets: dict[str, AssetRecord] = {}
        self._endpoints: dict[str, EndpointRecord] = {}

        self._load_existing()

    def _load_existing(self) -> None:
        path = self.workspace.resolve_path(
            self.RELATIVE_PATH
        )

        if not path.exists():
            return

        if not path.is_file() or path.stat().st_size == 0:
            raise ArtifactValidationError(
                f"Existing endpoint inventory is not a valid non-empty file: {path}"
            )

        try:
            data = self.workspace.read_json(
                self.RELATIVE_PATH
            )
        except Exception as exc:
            raise ArtifactValidationError(
                f"Cannot read endpoint inventory: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ArtifactValidationError(
                "Endpoint inventory root must be a JSON object"
            )

        if data.get("scan_id") != self.workspace.scan_id:
            raise ArtifactValidationError(
                "Endpoint inventory belongs to a different scan; "
                "refusing to merge stale data"
            )

        assets = data.get("assets", [])
        endpoints = data.get("endpoints", [])

        if (
            not isinstance(assets, list)
            or not isinstance(endpoints, list)
        ):
            raise ArtifactValidationError(
                "Endpoint inventory assets/endpoints must be arrays"
            )

        try:
            loaded_assets: dict[str, AssetRecord] = {}
            loaded_endpoints: dict[str, EndpointRecord] = {}

            for item in assets:
                if not isinstance(item, dict):
                    raise ValueError(
                        "asset entry must be an object"
                    )

                record = AssetRecord.from_dict(item)

                host = (
                    record.hostname.strip()
                    .lower()
                    .rstrip(".")
                )

                if not host or host in loaded_assets:
                    raise ValueError(
                        f"invalid or duplicate asset hostname: {host!r}"
                    )

                record.hostname = host
                loaded_assets[host] = record

            for item in endpoints:
                if not isinstance(item, dict):
                    raise ValueError(
                        "endpoint entry must be an object"
                    )

                record = EndpointRecord.from_dict(item)

                if (
                    not record.endpoint_id
                    or record.endpoint_id in loaded_endpoints
                ):
                    raise ValueError(
                        f"invalid or duplicate endpoint id: {record.endpoint_id!r}"
                    )

                if (
                    not record.hostname
                    or not record.url
                    or not record.canonical_url
                ):
                    raise ValueError(
                        f"incomplete endpoint record: {record.endpoint_id!r}"
                    )

                loaded_endpoints[record.endpoint_id] = record

        except Exception as exc:
            raise ArtifactValidationError(
                f"Endpoint inventory contains invalid records: {exc}"
            ) from exc

        with self._lock:
            self._assets = loaded_assets
            self._endpoints = loaded_endpoints

    @staticmethod
    def _clean_text(
        value: str,
        *,
        limit: int = 256,
    ) -> str:
        if not isinstance(value, str):
            return ""

        return "".join(
            ch
            for ch in value
            if ch >= " " and ch != "\x7f"
        ).strip()[:limit]

    def upsert_asset(
        self,
        hostname: str,
        *,
        root_domain: str = "",
        ip_addresses: list[str] | None = None,
        ports: list[int] | None = None,
        source: str = "",
        in_scope: bool = True,
        technologies: list[str] | None = None,
    ) -> AssetRecord:

        clean_host = (
            self._clean_text(hostname, limit=253)
            .lower()
            .rstrip(".")
        )

        if not clean_host:
            raise ValueError(
                "hostname must be non-empty"
            )

        clean_root = (
            self._clean_text(
                root_domain or clean_host,
                limit=253,
            )
            .lower()
            .rstrip(".")
        )

        clean_ips = sorted(
            {
                self._clean_text(ip, limit=64)
                for ip in (ip_addresses or [])
                if ip
            }
        )

        clean_ports = sorted(
            {
                int(port)
                for port in (ports or [])
                if 1 <= int(port) <= 65535
            }
        )

        clean_source = self._clean_text(
            source,
            limit=128,
        )

        clean_technologies = sorted(
            {
                self._clean_text(item, limit=128)
                for item in (technologies or [])
                if item
            }
        )

        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            existing = self._assets.get(clean_host)

            if existing is None:
                record = AssetRecord(
                    asset_id=make_asset_id(clean_host),
                    hostname=clean_host,
                    root_domain=clean_root,
                    ip_addresses=clean_ips,
                    ports=clean_ports,
                    sources=(
                        [clean_source]
                        if clean_source
                        else []
                    ),
                    in_scope=bool(in_scope),
                    technologies=clean_technologies,
                    first_seen=now,
                    last_seen=now,
                )

                self._assets[clean_host] = record

                return copy.deepcopy(record)

            existing.last_seen = now

            existing.ip_addresses = sorted(
                set(existing.ip_addresses) | set(clean_ips)
            )

            existing.ports = sorted(
                set(existing.ports) | set(clean_ports)
            )

            if (
                clean_source
                and clean_source not in existing.sources
            ):
                existing.sources.append(clean_source)

            existing.technologies = sorted(
                set(existing.technologies)
                | set(clean_technologies)
            )

            # A single out-of-scope observation must never
            # upgrade an asset to in-scope.
            existing.in_scope = (
                existing.in_scope and bool(in_scope)
            )

            return copy.deepcopy(existing)

    def upsert_endpoint(
        self,
        record: EndpointRecord,
    ) -> EndpointRecord:

        if not isinstance(record, EndpointRecord):
            raise TypeError(
                "record must be an EndpointRecord"
            )

        if (
            not record.endpoint_id
            or not record.hostname
            or not record.canonical_url
        ):
            raise ValueError(
                "endpoint record is missing identity fields"
            )

        incoming = copy.deepcopy(record)

        incoming.method = incoming.method.upper()
        incoming.hostname = (
            incoming.hostname.lower().rstrip(".")
        )

        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            existing = self._endpoints.get(
                incoming.endpoint_id
            )

            if existing is None:
                incoming.first_observed = (
                    incoming.first_observed or now
                )

                incoming.last_observed = now

                self._endpoints[incoming.endpoint_id] = incoming

                return copy.deepcopy(incoming)

            existing.last_observed = now

            for src in incoming.discovery_sources:
                if (
                    src
                    and src not in existing.discovery_sources
                ):
                    existing.discovery_sources.append(src)

            for code in incoming.status_codes:
                if code not in existing.status_codes:
                    existing.status_codes.append(code)

            existing.status_codes.sort()

            for context in incoming.auth_contexts:
                if (
                    context
                    and context not in existing.auth_contexts
                ):
                    existing.auth_contexts.append(context)

            for ref in incoming.evidence_refs:
                if (
                    ref
                    and ref not in existing.evidence_refs
                ):
                    existing.evidence_refs.append(ref)

            for tag in incoming.tags:
                if (
                    tag
                    and tag not in existing.tags
                ):
                    existing.tags.append(tag)

            # Preserve first observed safe samples.
            # Do not replace an existing redaction with a later value.
            for key, value in incoming.sample_query_params.items():
                if key not in existing.sample_query_params:
                    existing.sample_query_params[key] = value

            if (
                incoming.content_type
                and not existing.content_type
            ):
                existing.content_type = incoming.content_type
            if incoming.request_content_type and not existing.request_content_type:
                existing.request_content_type = incoming.request_content_type
            for header_name, header_value in incoming.request_headers.items():
                if header_name not in existing.request_headers:
                    existing.request_headers[header_name] = header_value
            for field_name, field_type in incoming.request_body_schema.items():
                if field_name not in existing.request_body_schema:
                    existing.request_body_schema[field_name] = field_type

            if incoming.title and not existing.title:
                existing.title = incoming.title

            if incoming.reachable is True:
                existing.reachable = True

            elif (
                incoming.reachable is False
                and existing.reachable is None
            ):
                existing.reachable = False

            existing.authenticated = (
                existing.authenticated
                or incoming.authenticated
            )

            existing.tested = (
                existing.tested or incoming.tested
            )

            existing.excluded = (
                existing.excluded or incoming.excluded
            )

            existing.discovered = (
                existing.discovered or incoming.discovered
            )

            if (
                existing.scope_status != "in_scope"
                or incoming.scope_status != "in_scope"
            ):
                existing.scope_status = "out_of_scope"

            return copy.deepcopy(existing)

    def all_assets(self) -> list[AssetRecord]:
        with self._lock:
            return [
                copy.deepcopy(record)
                for record in sorted(
                    self._assets.values(),
                    key=lambda item: item.hostname,
                )
            ]

    def all_endpoints(self) -> list[EndpointRecord]:
        with self._lock:
            return [
                copy.deepcopy(record)
                for record in sorted(
                    self._endpoints.values(),
                    key=lambda item: (
                        item.hostname,
                        item.path,
                        item.method,
                        item.canonical_url,
                        item.endpoint_id,
                    ),
                )
            ]

    def get_endpoints(
        self,
        *,
        reachable_only: bool = False,
        include_excluded: bool = False,
        methods: set[str] | None = None,
        include_out_of_scope: bool = False,
    ) -> list[EndpointRecord]:

        normalized_methods = (
            {method.upper() for method in methods}
            if methods
            else None
        )

        results: list[EndpointRecord] = []

        for endpoint in self.all_endpoints():

            if (
                not include_excluded
                and endpoint.excluded
            ):
                continue

            if (
                not include_out_of_scope
                and endpoint.scope_status != "in_scope"
            ):
                continue

            if (
                reachable_only
                and endpoint.reachable is not True
            ):
                continue

            if (
                normalized_methods
                and endpoint.method not in normalized_methods
            ):
                continue

            results.append(endpoint)

        return results

    def save(
        self,
        stage_id: str = "inventory_sync",
    ) -> dict[str, Any]:

        clean_stage = self._clean_text(
            stage_id,
            limit=128,
        )

        if not clean_stage:
            raise ValueError(
                "stage_id must be non-empty"
            )

        with self._lock:

            contributors: list[str] = []
            try:
                previous = self.workspace.read_json(self.RELATIVE_PATH)
                if previous.get("scan_id") == self.workspace.scan_id:
                    prior = previous.get("contributors", [])
                    if isinstance(prior, list):
                        contributors = [str(item) for item in prior if item]
            except Exception:
                contributors = []
            if clean_stage not in contributors:
                contributors.append(clean_stage)

            assets_list = [
                record.to_dict()
                for record in sorted(
                    self._assets.values(),
                    key=lambda item: item.hostname,
                )
            ]

            endpoints_list = [
                record.to_dict()
                for record in sorted(
                    self._endpoints.values(),
                    key=lambda item: (
                        item.hostname,
                        item.path,
                        item.method,
                        item.canonical_url,
                        item.endpoint_id,
                    ),
                )
            ]

            payload: dict[str, Any] = {
                "schema_version": self.SCHEMA_VERSION,
                "scan_id": self.workspace.scan_id,
                "stage_id": clean_stage,
                "last_writer": clean_stage,
                "contributors": contributors,
                "updated_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "summary": {
                    "total_assets": len(assets_list),
                    "total_endpoints": len(endpoints_list),
                    "unique_urls": len({endpoint["canonical_url"] for endpoint in endpoints_list}),
                    "unprobed_endpoints": sum(
                        1 for endpoint in endpoints_list if endpoint["reachable"] is None
                    ),
                    "unreachable_endpoints": sum(
                        1 for endpoint in endpoints_list if endpoint["reachable"] is False
                    ),
                    "reachable_endpoints": sum(
                        1
                        for endpoint in endpoints_list
                        if endpoint["reachable"] is True
                    ),
                    "authenticated_endpoints": sum(
                        1
                        for endpoint in endpoints_list
                        if endpoint["authenticated"]
                    ),
                    "out_of_scope_endpoints": sum(
                        1
                        for endpoint in endpoints_list
                        if endpoint["scope_status"] != "in_scope"
                    ),
                },
                "assets": assets_list,
                "endpoints": endpoints_list,
            }

            self.workspace.write_json_atomic(
                self.RELATIVE_PATH,
                payload,
            )
            # Keep the mutable aggregate for consumers, but give each producer
            # a stage-owned snapshot whose identity is never reassigned by later
            # stages. The orchestrator stamps provenance after runner completion.
            contribution_payload = copy.deepcopy(payload)
            contribution_payload["artifact_kind"] = "stage_inventory_snapshot"
            self.workspace.write_json_atomic(
                self.contribution_path(clean_stage), contribution_payload
            )
            self.workspace.write_json_atomic(
                f"inventory/export/unified_endpoints.v{self.SCHEMA_VERSION}.json",
                payload,
            )

            return copy.deepcopy(payload)
