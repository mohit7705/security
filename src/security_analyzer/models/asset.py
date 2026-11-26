from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_asset_id(hostname: str) -> str:
    digest = hashlib.sha256(hostname.strip().lower().encode("utf-8")).hexdigest()[:16]
    return f"asset_{digest}"


@dataclass
class AssetRecord:
    asset_id: str
    hostname: str
    root_domain: str
    ip_addresses: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    in_scope: bool = True
    technologies: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AssetRecord":
        return cls(
            asset_id=str(data["asset_id"]),
            hostname=str(data["hostname"]),
            root_domain=str(data.get("root_domain", data["hostname"])),
            ip_addresses=list(data.get("ip_addresses", [])),
            ports=[int(p) for p in data.get("ports", [])],
            sources=list(data.get("sources", [])),
            in_scope=bool(data.get("in_scope", True)),
            technologies=list(data.get("technologies", [])),
            first_seen=str(data.get("first_seen", utc_now_iso())),
            last_seen=str(data.get("last_seen", utc_now_iso())),
        )
