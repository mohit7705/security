from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class EndpointRecord:
    """Canonical representation of a web or API endpoint across all pipeline stages."""

    endpoint_id: str
    url: str
    canonical_url: str
    method: str
    scheme: str
    hostname: str
    port: int
    path: str
    query_param_names: list[str] = field(default_factory=list)
    sample_query_params: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    request_content_type: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body_schema: dict[str, Any] = field(default_factory=dict)
    title: str = ""
    status_codes: list[int] = field(default_factory=list)
    discovery_sources: list[str] = field(default_factory=list)
    auth_contexts: list[str] = field(default_factory=list)
    scope_status: str = "in_scope"
    discovered: bool = True
    reachable: bool | None = None
    authenticated: bool = False
    tested: bool = False
    excluded: bool = False
    evidence_refs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    first_observed: str = field(default_factory=_utc_now)
    last_observed: str = field(default_factory=_utc_now)

    @property
    def raw_url(self) -> str:
        # Raw request URLs are intentionally not retained; this alias preserves callers
        # while exposing only the canonical, redacted URL.
        return self.url

    @property
    def query_params(self) -> list[str]:
        return self.query_param_names

    @property
    def sources(self) -> list[str]:
        return self.discovery_sources

    @property
    def sample_params(self) -> dict[str, str]:
        return self.sample_query_params

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EndpointRecord":
        return cls(
            endpoint_id=str(data["endpoint_id"]),
            url=str(data["url"]),
            canonical_url=str(data.get("canonical_url", data["url"])),
            method=str(data.get("method", "GET")).upper(),
            scheme=str(data.get("scheme", "https")).lower(),
            hostname=str(data["hostname"]).lower(),
            port=int(data.get("port", 443)),
            path=str(data.get("path", "/")),
            query_param_names=list(data.get("query_param_names", [])),
            sample_query_params=dict(data.get("sample_query_params", {})),
            content_type=str(data.get("content_type", "")),
            request_content_type=str(data.get("request_content_type", "")),
            request_headers={str(k): str(v) for k, v in dict(data.get("request_headers", {})).items()},
            request_body_schema=dict(data.get("request_body_schema", {})),
            title=str(data.get("title", "")),
            status_codes=[int(c) for c in data.get("status_codes", [])],
            discovery_sources=list(data.get("discovery_sources", [])),
            auth_contexts=list(data.get("auth_contexts", [])),
            scope_status=str(data.get("scope_status", "in_scope")),
            discovered=bool(data.get("discovered", True)),
            reachable=data.get("reachable"),
            authenticated=bool(data.get("authenticated", False)),
            tested=bool(data.get("tested", False)),
            excluded=bool(data.get("excluded", False)),
            evidence_refs=list(data.get("evidence_refs", [])),
            tags=list(data.get("tags", [])),
            first_observed=str(data.get("first_observed", _utc_now())),
            last_observed=str(data.get("last_observed", _utc_now())),
        )
