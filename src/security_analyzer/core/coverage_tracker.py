from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from security_analyzer.core.exceptions import ArtifactValidationError
from security_analyzer.core.workspace import WorkspaceManager
from security_analyzer.utils.redaction import scrub_text


class CoverageTracker:
    """Tracks tested, skipped, out-of-scope, and failed targets/checks in ./output/<scan_id>/coverage_summary.json."""

    def __init__(self, workspace: WorkspaceManager, limits: dict[str, Any] | None = None) -> None:
        self.workspace = workspace
        self._limits = dict(limits or {})
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {
            "schema_version": "1.0",
            "scan_id": workspace.scan_id,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "configured_limits": dict(self._limits),
            "stages": {},
            "tested_targets": [],
            "out_of_scope_blocks": [],
            "request_failures": [],
            "skipped_checks": [],
        }
        self._load_existing()

    def _load_existing(self) -> None:
        """Restore this scan's coverage before appending resumed-stage results."""
        path = self.workspace.coverage_file
        if not path.is_file():
            return
        try:
            existing = self.workspace.read_json("coverage_summary.json")
        except Exception as exc:
            raise ArtifactValidationError(
                f"Cannot restore existing coverage summary: {type(exc).__name__}"
            ) from exc
        if not isinstance(existing, dict):
            raise ArtifactValidationError("Existing coverage summary must be a JSON object")
        if existing.get("scan_id") != self.workspace.scan_id:
            raise ArtifactValidationError(
                "Existing coverage summary belongs to a different scan"
            )

        restored = dict(self._data)
        restored["updated_at"] = str(existing.get("updated_at") or restored["updated_at"])
        restored["stages"] = existing.get("stages", {})
        for key in ("tested_targets", "out_of_scope_blocks", "request_failures", "skipped_checks"):
            restored[key] = existing.get(key, [])
        if not isinstance(restored["stages"], dict):
            raise ArtifactValidationError("Coverage stages must be a JSON object")
        for key in ("tested_targets", "out_of_scope_blocks", "request_failures", "skipped_checks"):
            if not isinstance(restored[key], list):
                raise ArtifactValidationError(f"Coverage field {key!r} must be an array")
        # Current configuration is authoritative, while historical observations survive.
        restored["configured_limits"] = dict(self._limits)
        restored["schema_version"] = "1.0"
        restored["scan_id"] = self.workspace.scan_id
        self._data = restored

    @staticmethod
    def _safe_target(value: str) -> str:
        try:
            parsed = urlsplit(value)
            if not parsed.scheme or not parsed.hostname:
                return value[:1000]
            host = parsed.hostname.lower()
            authority = f"[{host}]" if ":" in host else host
            if parsed.port:
                authority += f":{parsed.port}"
            query = urlencode([(key, "[REDACTED]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
            return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", query, ""))[:1000]
        except ValueError:
            return "[INVALID_URL]"

    def save(self) -> None:
        with self._lock:
            self._data["updated_at"] = datetime.now(timezone.utc).isoformat()
            self.workspace.write_json_atomic("coverage_summary.json", self._data)

    def record_stage_coverage(
        self,
        stage_id: str,
        *,
        status: str,
        targets_total: int = 0,
        targets_tested: int = 0,
        targets_skipped: int = 0,
        reason: str = "",
    ) -> None:
        with self._lock:
            self._data["stages"][stage_id] = {
                "status": status,
                "targets_total": targets_total,
                "targets_tested": targets_tested,
                "targets_skipped": targets_skipped,
                "reason": scrub_text(reason),
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }
        self.save()

    def record_target_tested(
        self,
        stage_id: str,
        url: str,
        *,
        status_code: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            if len(self._data["tested_targets"]) < 5000:
                self._data["tested_targets"].append({
                    "stage_id": stage_id,
                    "url": self._safe_target(url),
                    "status_code": status_code,
                    "metadata": metadata or {},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        self.save()

    def record_out_of_scope(self, stage_id: str, url: str, reason: str) -> None:
        with self._lock:
            if len(self._data["out_of_scope_blocks"]) < 500:
                self._data["out_of_scope_blocks"].append(
                    {
                        "stage_id": stage_id,
                        "url": self._safe_target(url),
                        "reason": scrub_text(reason),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
        self.save()

    def record_request_failure(self, stage_id: str, url: str, error: str) -> None:
        with self._lock:
            if len(self._data["request_failures"]) < 500:
                self._data["request_failures"].append(
                    {
                        "stage_id": stage_id,
                        "url": self._safe_target(url),
                        "error": scrub_text(str(error)[:300]),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
        self.save()

    def record_skipped_check(self, stage_id: str, check_name: str, reason: str) -> None:
        with self._lock:
            if len(self._data["skipped_checks"]) < 5000:
                self._data["skipped_checks"].append(
                    {
                        "stage_id": stage_id,
                        "check_name": check_name,
                        "reason": scrub_text(reason),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
        self.save()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._data))
