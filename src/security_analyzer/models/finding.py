from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"
    INCONCLUSIVE = "INCONCLUSIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class FindingRecord:
    title: str
    category: str
    severity: Severity
    verdict: Verdict
    confidence: float
    asset_id: str
    endpoint_id: str
    identity_id: str = "anonymous"
    description: str = ""
    remediation: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    scanner_source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: f"find_{uuid.uuid4().hex[:16]}")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["verdict"] = self.verdict.value
        return data
