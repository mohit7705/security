from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class HttpRequestRecord:
    method: str
    url: str
    normalized_url: str
    headers: dict[str, str] = field(default_factory=dict)
    query_param_names: list[str] = field(default_factory=list)
    body_preview: str = ""
    content_type: str = ""
    identity_id: str = "anonymous"
    request_id: str = field(default_factory=lambda: f"req_{uuid.uuid4().hex[:16]}")
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HttpResponseRecord:
    request_id: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    content_length: int = 0
    title: str = ""
    body_sha256: str = ""
    body_snippet: str = ""
    redirect_location: str = ""
    elapsed_ms: float = 0.0
    response_id: str = field(default_factory=lambda: f"resp_{uuid.uuid4().hex[:16]}")
    timestamp: str = field(default_factory=_now_iso)

    @staticmethod
    def hash_body(raw_bytes: bytes) -> str:
        return hashlib.sha256(raw_bytes).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
