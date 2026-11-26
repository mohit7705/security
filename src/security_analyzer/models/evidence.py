from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class EvidenceRecord:
    artifact_path: str
    evidence_type: str
    summary: str
    sha256: str = ""
    request_id: str | None = None
    response_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence_id: str = field(default_factory=lambda: f"ev_{uuid.uuid4().hex[:16]}")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
