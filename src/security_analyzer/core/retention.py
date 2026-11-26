from __future__ import annotations

import json
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AUDIT_FILE_NAME = "retention_audit.jsonl"
MIN_RETENTION_DAYS = 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_audit(audit_path: Path, record: dict[str, Any]) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    try:
        audit_path.chmod(0o600)
    except OSError:
        pass


def _is_inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def find_expired_scans(
    output_root: Path, max_age_days: int, now: float | None = None
) -> list[Path]:
    """Return scan directories whose scan_state.json is older than max_age_days."""
    if max_age_days < MIN_RETENTION_DAYS:
        raise ValueError(f"max_age_days must be at least {MIN_RETENTION_DAYS}")
    cutoff = (now if now is not None else time.time()) - max_age_days * 86400
    expired: list[Path] = []
    if not output_root.is_dir():
        return expired
    for child in sorted(output_root.iterdir()):
        if child.is_symlink() or not child.is_dir():
            continue
        state_file = child / "scan_state.json"
        if state_file.is_file() and state_file.stat().st_mtime < cutoff:
            expired.append(child)
    return expired


def cleanup_expired(
    output_root: Path,
    secrets_root: Path,
    max_age_days: int,
    *,
    execute: bool = False,
    audit_path: Path | None = None,
) -> dict[str, Any]:
    """Dry-run by default; optionally delete expired scan and secrets folders."""
    audit_file = audit_path or (output_root / AUDIT_FILE_NAME)
    affected: list[str] = []
    candidates = find_expired_scans(output_root, max_age_days)

    for scan_dir in candidates:
        scan_id = scan_dir.name
        targets = [scan_dir]
        secret_dir = secrets_root / scan_id
        if secret_dir.is_dir() and not secret_dir.is_symlink():
            targets.append(secret_dir)

        for target in targets:
            allowed_root = output_root if target == scan_dir else secrets_root
            if not _is_inside(target, allowed_root):
                _write_audit(audit_file, {
                    "time": _utc_now(), "action": "refused_outside_root",
                    "scan_id": scan_id, "path": str(target),
                })
                continue
            if execute:
                shutil.rmtree(target)
            _write_audit(audit_file, {
                "time": _utc_now(),
                "action": "deleted" if execute else "dry_run_candidate",
                "scan_id": scan_id,
                "path": str(target),
                "max_age_days": max_age_days,
            })
            affected.append(str(target))

    return {
        "executed": execute,
        "max_age_days": max_age_days,
        "candidate_scans": [path.name for path in candidates],
        "affected_paths": affected,
        "audit_log": str(audit_file),
    }
