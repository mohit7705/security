from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_analyzer.core.exceptions import WorkspaceBoundaryError


class WorkspaceManager:
    """Enforces a single root ./output/<scan_id>/ boundary for all scan inputs and outputs."""

    SUBDIRS = (
        "inventory",
        "discovery",
        "browser",
        "browser/screenshots",
        "analysis",
        "verification",
        "reports",
        "logs",
    )

    def __init__(self, project_root: Path | None = None, output_root_name: str = "output") -> None:
        self.project_root = (project_root or Path.cwd()).resolve()
        configured_output = Path(output_root_name)
        if configured_output.is_absolute() or ".." in configured_output.parts:
            raise WorkspaceBoundaryError("output_root must be a relative path inside the project root")
        unresolved_output = self.project_root / configured_output
        probe = self.project_root
        for part in configured_output.parts:
            probe = probe / part
            if probe.is_symlink():
                raise WorkspaceBoundaryError("output_root path cannot contain symlinks")
        self.output_root = unresolved_output.resolve()
        try:
            self.output_root.relative_to(self.project_root)
        except ValueError as exc:
            raise WorkspaceBoundaryError("output_root must resolve inside the project root") from exc
        if self.output_root == self.project_root:
            raise WorkspaceBoundaryError("output_root must be a child of the project root")
        self.output_root.mkdir(parents=True, exist_ok=True)
        if self.output_root.is_symlink():
            raise WorkspaceBoundaryError("output_root cannot be a symlink")
        self.scan_id: str | None = None
        self.scan_dir: Path | None = None

    @staticmethod
    def generate_scan_id(target: str) -> str:
        cleaned = re.sub(r"^https?://", "", target.strip().lower())
        cleaned = re.sub(r"[^a-z0-9.-]+", "_", cleaned).strip("._-") or "target"
        cleaned = cleaned[:48]
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        suffix = uuid.uuid4().hex[:6]
        return f"{cleaned}_{ts}_{suffix}"

    def init_scan(self, target: str, scan_id: str | None = None) -> Path:
        chosen_id = scan_id or self.generate_scan_id(target)
        if not re.match(r"^[a-zA-Z0-9._-]+$", chosen_id):
            raise WorkspaceBoundaryError(f"Invalid scan_id format: {chosen_id!r}")

        requested_candidate = self.output_root / chosen_id
        if requested_candidate.is_symlink():
            raise WorkspaceBoundaryError("Scan workspace cannot be a symlink")
        candidate = requested_candidate.resolve()
        if candidate.parent != self.output_root:
            raise WorkspaceBoundaryError(f"Scan directory escapes output root: {candidate}")

        self.scan_id = chosen_id
        self.scan_dir = candidate
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        for rel in self.SUBDIRS:
            (self.scan_dir / rel).mkdir(parents=True, exist_ok=True)
        return self.scan_dir

    def load_scan(self, scan_id: str) -> Path:
        if not re.match(r"^[a-zA-Z0-9._-]+$", scan_id):
            raise WorkspaceBoundaryError(f"Invalid scan_id format: {scan_id!r}")

        requested_candidate = self.output_root / scan_id
        if requested_candidate.is_symlink():
            raise WorkspaceBoundaryError("Scan workspace cannot be a symlink")
        candidate = requested_candidate.resolve()
        if candidate.parent != self.output_root or not candidate.is_dir():
            raise WorkspaceBoundaryError(f"Scan workspace does not exist inside {self.output_root}: {scan_id}")

        self.scan_id = scan_id
        self.scan_dir = candidate
        for rel in self.SUBDIRS:
            (self.scan_dir / rel).mkdir(parents=True, exist_ok=True)
        return self.scan_dir

    def resolve_path(self, relative_path: str | Path) -> Path:
        """Resolve a path strictly inside ./output/<scan_id>/."""
        if self.scan_dir is None:
            raise WorkspaceBoundaryError("WorkspaceManager has no active scan_dir initialized.")

        rel = Path(relative_path)
        if rel.is_absolute():
            resolved = rel.resolve()
        else:
            resolved = (self.scan_dir / rel).resolve()

        try:
            resolved.relative_to(self.scan_dir)
        except ValueError as exc:
            raise WorkspaceBoundaryError(
                f"Blocked access outside active scan workspace ({self.scan_dir}): {resolved}"
            ) from exc

        return resolved

    @property
    def state_file(self) -> Path:
        return self.resolve_path("scan_state.json")

    @property
    def scope_snapshot_file(self) -> Path:
        return self.resolve_path("scope_snapshot.json")

    @property
    def coverage_file(self) -> Path:
        return self.resolve_path("coverage_summary.json")

    @property
    def execution_log_file(self) -> Path:
        return self.resolve_path("logs/execution.jsonl")

    def write_json_atomic(self, relative_path: str | Path, payload: dict[str, Any]) -> Path:
        target = self.resolve_path(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"

        fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, target)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise
        return target

    def write_text_atomic(self, relative_path: str | Path, content: str) -> Path:
        target = self.resolve_path(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)

        fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, target)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise
        return target

    def read_json(self, relative_path: str | Path) -> dict[str, Any]:
        target = self.resolve_path(relative_path)
        data = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise WorkspaceBoundaryError(f"Expected JSON object in {target}, got {type(data).__name__}")
        return data

    def append_jsonl(self, relative_path: str | Path, record: dict[str, Any]) -> None:
        target = self.resolve_path(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, sort_keys=True) + "\n"
        with target.open("a", encoding="utf-8") as handle:
            handle.write(line)

    def file_sha256(self, relative_path: str | Path) -> str:
        target = self.resolve_path(relative_path)
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
