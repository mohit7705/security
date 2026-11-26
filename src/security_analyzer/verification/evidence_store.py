from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from security_analyzer.core.workspace import WorkspaceManager
from security_analyzer.models.evidence import EvidenceRecord


_DB_RELATIVE_PATH = "verification/evidence_index.sqlite3"
_SENSITIVE_KEYS = (
    "authorization", "proxy_authorization", "cookie", "set_cookie",
    "token", "secret", "password", "passwd", "api_key", "apikey",
    "email", "phone", "mobile", "address", "session", "refresh",
    "ssn", "credential",
)
_TOKEN_PATTERN = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9._~+/-]+=*|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
)


def sanitize_evidence_value(value: Any, *, _depth: int = 0) -> Any:
    """Bound and redact evidence telemetry before it reaches disk or SQLite."""
    if _depth > 8:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 100:
                result["_truncated"] = True
                break
            name = str(key)
            normalized = name.lower().replace("-", "_")
            if any(term in normalized for term in _SENSITIVE_KEYS):
                result[name] = "[REDACTED]"
            else:
                result[name] = sanitize_evidence_value(item, _depth=_depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [
            sanitize_evidence_value(item, _depth=_depth + 1)
            for item in list(value)[:100]
        ]
    if isinstance(value, str):
        text = _TOKEN_PATTERN.sub("[REDACTED_TOKEN]", value)
        if text.startswith(("http://", "https://")):
            try:
                parsed = urlsplit(text)
                if parsed.scheme and parsed.hostname:
                    host = parsed.hostname
                    if parsed.port:
                        host = f"{host}:{parsed.port}"
                    text = urlunsplit(
                        (parsed.scheme, host, parsed.path or "/", "", "")
                    )
            except ValueError:
                text = "[REDACTED_URL]"
        return text[:4096]
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if value is None or isinstance(value, (bool, int)):
        return value
    return str(value)[:512]


class EvidenceStore:
    """Scan-local SQLite index for immutable evidence, replay outcomes and findings."""

    RELATIVE_PATH = _DB_RELATIVE_PATH
    SCHEMA_VERSION = 2

    def __init__(self, workspace: WorkspaceManager) -> None:
        if not workspace.scan_id:
            raise ValueError("EvidenceStore requires an initialized scan workspace")
        self.workspace = workspace
        self.path = workspace.resolve_path(self.RELATIVE_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            str(self.path),
            timeout=10.0,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._initialize()
        self._secure_permissions()

    def _secure_permissions(self) -> None:
        # The private directory is the primary boundary for SQLite WAL/SHM
        # sidecars; chmod every extant database file as defense in depth.
        for candidate in (
            self.path,
            Path(str(self.path) + "-wal"),
            Path(str(self.path) + "-shm"),
        ):
            try:
                if candidate.exists():
                    os.chmod(candidate, 0o600)
            except OSError:
                pass

    def _initialize(self) -> None:
        current_version = int(
            self._connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if current_version > self.SCHEMA_VERSION:
            raise ValueError(
                f"Evidence database schema {current_version} is newer than supported "
                f"schema {self.SCHEMA_VERSION}"
            )
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS store_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evidence_records (
                    evidence_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    artifact_path TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    integrity_status TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS replay_outcomes (
                    replay_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    replayed INTEGER NOT NULL,
                    reproducible INTEGER NOT NULL,
                    identity_contrast_verified INTEGER NOT NULL,
                    evidence_integrity INTEGER NOT NULL,
                    outcome_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS finding_history (
                    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS human_review_decisions (
                    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    finding_id TEXT NOT NULL,
                    reviewer_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_finding_history_lookup
                    ON finding_history(scan_id, finding_id, history_id);
                CREATE INDEX IF NOT EXISTS idx_human_review_lookup
                    ON human_review_decisions(scan_id, finding_id, decision_id);

                CREATE TRIGGER IF NOT EXISTS finding_history_no_update
                BEFORE UPDATE ON finding_history
                BEGIN
                    SELECT RAISE(ABORT, 'finding history is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS finding_history_no_delete
                BEFORE DELETE ON finding_history
                BEGIN
                    SELECT RAISE(ABORT, 'finding history is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS human_review_no_update
                BEFORE UPDATE ON human_review_decisions
                BEGIN
                    SELECT RAISE(ABORT, 'human review decisions are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS human_review_no_delete
                BEFORE DELETE ON human_review_decisions
                BEGIN
                    SELECT RAISE(ABORT, 'human review decisions are append-only');
                END;

                CREATE TABLE IF NOT EXISTS integrity_checks (
                    check_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    artifact_path TEXT NOT NULL,
                    expected_sha256 TEXT NOT NULL,
                    observed_sha256 TEXT NOT NULL,
                    valid INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    checked_at TEXT NOT NULL
                );

                CREATE TRIGGER IF NOT EXISTS evidence_records_no_update
                BEFORE UPDATE ON evidence_records
                BEGIN
                    SELECT RAISE(ABORT, 'evidence records are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS evidence_records_no_delete
                BEFORE DELETE ON evidence_records
                BEGIN
                    SELECT RAISE(ABORT, 'evidence records are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS integrity_checks_no_update
                BEFORE UPDATE ON integrity_checks
                BEGIN
                    SELECT RAISE(ABORT, 'integrity checks are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS integrity_checks_no_delete
                BEFORE DELETE ON integrity_checks
                BEGIN
                    SELECT RAISE(ABORT, 'integrity checks are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS replay_outcomes_no_update
                BEFORE UPDATE ON replay_outcomes
                BEGIN
                    SELECT RAISE(ABORT, 'replay outcomes are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS replay_outcomes_no_delete
                BEFORE DELETE ON replay_outcomes
                BEGIN
                    SELECT RAISE(ABORT, 'replay outcomes are append-only');
                END;

                CREATE INDEX IF NOT EXISTS idx_evidence_finding
                    ON evidence_records(scan_id, finding_id);
                CREATE INDEX IF NOT EXISTS idx_replays_finding
                    ON replay_outcomes(scan_id, finding_id);
                """
            )
            # Version 1 -> 2 is additive: finding history and human-review
            # decision tables are created above without rewriting prior evidence.
            self._connection.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            stored_scan = self._connection.execute(
                "SELECT value FROM store_meta WHERE key='scan_id'"
            ).fetchone()
            if stored_scan and stored_scan["value"] != self.workspace.scan_id:
                raise ValueError("Evidence database belongs to a different scan")
            self._connection.execute(
                "INSERT OR IGNORE INTO store_meta(key, value) VALUES('scan_id', ?)",
                (self.workspace.scan_id,),
            )
            self._connection.execute(
                "INSERT OR REPLACE INTO store_meta(key, value) VALUES('schema_version', ?)",
                (str(self.SCHEMA_VERSION),),
            )

    @staticmethod
    def _safe_relative_artifact(path: str) -> bool:
        candidate = PurePosixPath(path)
        return (
            bool(path)
            and not candidate.is_absolute()
            and ".." not in candidate.parts
            and "\\" not in path
        )

    def verify_record(
        self,
        record: EvidenceRecord,
        *,
        finding_id: str,
    ) -> dict[str, Any]:
        """Verify path confinement, content digest and evidence envelope identity."""
        relative_path = str(record.artifact_path)
        if not self._safe_relative_artifact(relative_path):
            return {
                "valid": False,
                "reason": "unsafe_artifact_path",
                "observed_sha256": "",
            }

        try:
            path = self.workspace.resolve_path(relative_path)
            if not path.is_file():
                return {
                    "valid": False,
                    "reason": "artifact_missing",
                    "observed_sha256": "",
                }
            observed = self.workspace.file_sha256(relative_path)
            if not record.sha256 or observed != record.sha256:
                return {
                    "valid": False,
                    "reason": "sha256_mismatch",
                    "observed_sha256": observed,
                }
            payload = self.workspace.read_json(relative_path)
            if payload.get("scan_id") != self.workspace.scan_id:
                return {
                    "valid": False,
                    "reason": "scan_id_mismatch",
                    "observed_sha256": observed,
                }
            if payload.get("finding_id") != finding_id:
                return {
                    "valid": False,
                    "reason": "finding_id_mismatch",
                    "observed_sha256": observed,
                }
            if payload.get("evidence_id") != record.evidence_id:
                return {
                    "valid": False,
                    "reason": "evidence_id_mismatch",
                    "observed_sha256": observed,
                }
            return {
                "valid": True,
                "reason": "verified",
                "observed_sha256": observed,
            }
        except Exception as exc:
            return {
                "valid": False,
                "reason": f"verification_error:{type(exc).__name__}",
                "observed_sha256": "",
            }

    def record_evidence(
        self,
        record: EvidenceRecord,
        *,
        finding_id: str,
        integrity: dict[str, Any],
    ) -> None:
        metadata = sanitize_evidence_value(record.metadata)
        values = (
            record.evidence_id,
            self.workspace.scan_id,
            finding_id,
            record.artifact_path,
            record.evidence_type,
            record.sha256,
            str(record.summary)[:1000],
            record.created_at,
            "VERIFIED" if integrity.get("valid") else "INVALID",
            json.dumps(metadata, sort_keys=True, separators=(",", ":")),
        )
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT sha256, artifact_path, finding_id FROM evidence_records WHERE evidence_id=?",
                (record.evidence_id,),
            ).fetchone()
            if existing:
                if (
                    existing["sha256"] != record.sha256
                    or existing["artifact_path"] != record.artifact_path
                    or existing["finding_id"] != finding_id
                ):
                    raise ValueError(
                        f"Evidence ID collision with different content: {record.evidence_id}"
                    )
                return
            self._connection.execute(
                """
                INSERT INTO evidence_records (
                    evidence_id, scan_id, finding_id, artifact_path,
                    evidence_type, sha256, summary, created_at,
                    integrity_status, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            self._connection.execute(
                """
                INSERT INTO integrity_checks (
                    scan_id, evidence_id, artifact_path, expected_sha256,
                    observed_sha256, valid, reason, checked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.workspace.scan_id,
                    record.evidence_id,
                    record.artifact_path,
                    record.sha256,
                    str(integrity.get("observed_sha256", "")),
                    int(bool(integrity.get("valid"))),
                    str(integrity.get("reason", "")),
                    record.created_at,
                ),
            )

    def record_finding(
        self,
        finding: dict[str, Any],
        *,
        actor: str = "system",
        reason: str = "verification snapshot",
        event_type: str = "FINDING_UPDATED",
    ) -> None:
        """Persist the current finding projection and an immutable lifecycle event."""
        safe = sanitize_evidence_value(finding)
        finding_id = str(safe.get("finding_id", "")).strip()
        if not finding_id:
            raise ValueError("finding_id is required for evidence history")
        actor_value = str(actor or "").strip()[:128]
        reason_value = str(reason or "").strip()[:2000]
        event_value = str(event_type or "FINDING_UPDATED").strip().upper()[:64]
        if not actor_value:
            raise ValueError("actor is required")
        if not event_value:
            raise ValueError("event_type is required")

        verdict = str(safe.get("verdict", "INCONCLUSIVE")).upper()
        severity = str(safe.get("severity", "INFO")).upper()
        confidence_value = safe.get("confidence", 0.0)
        confidence = (
            float(confidence_value)
            if isinstance(confidence_value, (int, float))
            and not isinstance(confidence_value, bool)
            and math.isfinite(float(confidence_value))
            else 0.0
        )
        confidence = max(0.0, min(1.0, confidence))
        state = str(safe.get("state") or verdict).upper()
        now = datetime.now(timezone.utc).isoformat()

        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO findings (
                    finding_id, scan_id, category, severity, verdict,
                    confidence, payload_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    category=excluded.category,
                    severity=excluded.severity,
                    verdict=excluded.verdict,
                    confidence=excluded.confidence,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    finding_id,
                    self.workspace.scan_id,
                    str(safe.get("category", "")),
                    severity,
                    verdict,
                    confidence,
                    json.dumps(safe, sort_keys=True, separators=(",", ":")),
                    now,
                ),
            )
            self._connection.execute(
                """
                INSERT INTO finding_history (
                    scan_id, finding_id, event_type, state, verdict,
                    severity, confidence, actor, reason, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.workspace.scan_id,
                    finding_id,
                    event_value,
                    state,
                    verdict,
                    severity,
                    confidence,
                    actor_value,
                    reason_value,
                    json.dumps(safe, sort_keys=True, separators=(",", ":")),
                    now,
                ),
            )
            self._secure_permissions()

    def record_human_review_decision(
        self,
        *,
        finding_id: str,
        reviewer_id: str,
        decision: str,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Append a human decision; never overwrite earlier reviewer decisions."""
        finding_id = str(finding_id or "").strip()
        reviewer_id = str(reviewer_id or "").strip()[:128]
        decision = str(decision or "").strip().upper()
        reason = str(reason or "").strip()
        allowed = {
            "CONFIRM", "REJECT", "ACCEPT_RISK", "FALSE_POSITIVE",
            "NEEDS_MORE_EVIDENCE", "REOPEN",
        }
        if not finding_id or not reviewer_id or not reason:
            raise ValueError("finding_id, reviewer_id and reason are required")
        if decision not in allowed:
            raise ValueError(f"Unsupported human review decision: {decision}")
        with self._lock, self._connection:
            exists = self._connection.execute(
                "SELECT 1 FROM findings WHERE scan_id=? AND finding_id=?",
                (self.workspace.scan_id, finding_id),
            ).fetchone()
            if not exists:
                raise ValueError("Cannot review a finding not recorded in this scan")
            current = self._connection.execute(
                """
                SELECT verdict, severity, confidence, payload_json
                FROM findings WHERE scan_id=? AND finding_id=?
                """,
                (self.workspace.scan_id, finding_id),
            ).fetchone()
            current_payload = json.loads(current["payload_json"])
            verdict_updates = {
                "CONFIRM": "CONFIRMED",
                "REJECT": "FALSE_POSITIVE",
                "FALSE_POSITIVE": "FALSE_POSITIVE",
                "NEEDS_MORE_EVIDENCE": "INCONCLUSIVE",
                "REOPEN": "NEEDS_HUMAN_REVIEW",
            }
            next_verdict = verdict_updates.get(decision, str(current["verdict"]))
            current_payload["human_review"] = {
                "decision": decision,
                "reviewer_id": reviewer_id,
                "reason": reason[:4000],
                "decided_at": datetime.now(timezone.utc).isoformat(),
            }
            self._connection.execute(
                """
                UPDATE findings
                SET verdict=?, payload_json=?, updated_at=?
                WHERE scan_id=? AND finding_id=?
                """,
                (
                    next_verdict,
                    json.dumps(current_payload, sort_keys=True, separators=(",", ":")),
                    datetime.now(timezone.utc).isoformat(),
                    self.workspace.scan_id,
                    finding_id,
                ),
            )
            cursor = self._connection.execute(
                """
                INSERT INTO human_review_decisions (
                    scan_id, finding_id, reviewer_id, decision, reason,
                    metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.workspace.scan_id,
                    finding_id,
                    reviewer_id,
                    decision,
                    reason[:4000],
                    json.dumps(
                        sanitize_evidence_value(metadata or {}),
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            decision_id = int(cursor.lastrowid)
            self._connection.execute(
                """
                INSERT INTO finding_history (
                    scan_id, finding_id, event_type, state, verdict,
                    severity, confidence, actor, reason, payload_json, created_at
                )
                SELECT scan_id, finding_id, 'HUMAN_REVIEW', ?, verdict,
                       severity, confidence, ?, ?, payload_json, ?
                FROM findings WHERE scan_id=? AND finding_id=?
                """,
                (
                    decision,
                    reviewer_id,
                    reason[:4000],
                    datetime.now(timezone.utc).isoformat(),
                    self.workspace.scan_id,
                    finding_id,
                ),
            )
            self._secure_permissions()
            return decision_id

    def finding_history(self, finding_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT history_id, event_type, state, verdict, severity,
                       confidence, actor, reason, payload_json, created_at
                FROM finding_history
                WHERE scan_id=? AND finding_id=?
                ORDER BY history_id
                """,
                (self.workspace.scan_id, str(finding_id)),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            result.append(item)
        return result

    def human_review_history(self, finding_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT decision_id, reviewer_id, decision, reason,
                       metadata_json, created_at
                FROM human_review_decisions
                WHERE scan_id=? AND finding_id=?
                ORDER BY decision_id
                """,
                (self.workspace.scan_id, str(finding_id)),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json"))
            result.append(item)
        return result

    def backup_to(self, destination: str | Path) -> Path:
        """Create a consistent SQLite backup using SQLite's online backup API."""
        destination_path = Path(destination).expanduser().resolve()
        if destination_path == self.path.resolve():
            raise ValueError("Backup destination must differ from the live database")
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if destination_path.exists():
            raise FileExistsError(f"Backup destination already exists: {destination_path}")
        backup_connection = sqlite3.connect(str(destination_path))
        try:
            with self._lock:
                # Flush any completed public operation before starting the
                # online backup. Public methods commit their transactions;
                # this also safely closes a caller's read/validation txn.
                self._connection.commit()
                self._connection.backup(backup_connection)
            check = backup_connection.execute("PRAGMA integrity_check").fetchone()
            if not check or check[0] != "ok":
                raise sqlite3.DatabaseError("Evidence database backup failed integrity_check")
            backup_connection.commit()
        except Exception:
            backup_connection.close()
            try:
                destination_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        else:
            backup_connection.close()
        try:
            os.chmod(destination_path, 0o600)
        except OSError:
            pass
        return destination_path

    @staticmethod
    def restore_from_backup(
        source: str | Path,
        destination: str | Path,
        *,
        expected_scan_id: str,
    ) -> Path:
        """Restore a verified backup to a new path; never overwrite an existing DB."""
        source_path = Path(source).expanduser().resolve()
        destination_path = Path(destination).expanduser().resolve()
        if source_path == destination_path:
            raise ValueError("Restore source and destination must differ")
        if not source_path.is_file():
            raise FileNotFoundError(source_path)
        if destination_path.exists():
            raise FileExistsError(f"Restore destination already exists: {destination_path}")
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        source_connection = sqlite3.connect(
            f"file:{source_path.as_posix()}?mode=ro",
            uri=True,
        )
        destination_connection = sqlite3.connect(str(destination_path))
        try:
            check = source_connection.execute("PRAGMA integrity_check").fetchone()
            if not check or check[0] != "ok":
                raise sqlite3.DatabaseError("Evidence backup failed integrity_check")
            row = source_connection.execute(
                "SELECT value FROM store_meta WHERE key='scan_id'"
            ).fetchone()
            if not row or str(row[0]) != str(expected_scan_id):
                raise ValueError("Evidence backup scan_id does not match expected scan")
            source_connection.backup(destination_connection)
            destination_connection.commit()
            restored = destination_connection.execute("PRAGMA integrity_check").fetchone()
            if not restored or restored[0] != "ok":
                raise sqlite3.DatabaseError("Restored evidence database failed integrity_check")
        except Exception:
            destination_connection.close()
            source_connection.close()
            try:
                destination_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        else:
            destination_connection.close()
            source_connection.close()

        try:
            os.chmod(destination_path, 0o600)
        except OSError:
            pass
        return destination_path

    def record_replay(self, outcome: dict[str, Any]) -> None:
        safe = sanitize_evidence_value(outcome)
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO replay_outcomes (
                    scan_id, finding_id, verdict, replayed, reproducible,
                    identity_contrast_verified, evidence_integrity,
                    outcome_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                (
                    self.workspace.scan_id,
                    str(safe.get("finding_id", "")),
                    str(safe.get("verdict", "INCONCLUSIVE")),
                    int(bool(safe.get("replayed"))),
                    int(bool(safe.get("reproducible"))),
                    int(bool(safe.get("identity_contrast_verified"))),
                    int(bool(safe.get("evidence_integrity"))),
                    json.dumps(safe, sort_keys=True, separators=(",", ":")),
                ),
            )

    def summary(self) -> dict[str, int]:
        with self._lock:
            evidence = self._connection.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN integrity_status='VERIFIED' THEN 1 ELSE 0 END) AS verified,
                       SUM(CASE WHEN integrity_status!='VERIFIED' THEN 1 ELSE 0 END) AS invalid
                FROM evidence_records WHERE scan_id=?
                """,
                (self.workspace.scan_id,),
            ).fetchone()
            findings = self._connection.execute(
                "SELECT COUNT(*) AS total FROM findings WHERE scan_id=?",
                (self.workspace.scan_id,),
            ).fetchone()
            replays = self._connection.execute(
                "SELECT COUNT(*) AS total FROM replay_outcomes WHERE scan_id=?",
                (self.workspace.scan_id,),
            ).fetchone()
            return {
                "evidence_total": int(evidence["total"] or 0),
                "evidence_verified": int(evidence["verified"] or 0),
                "evidence_invalid": int(evidence["invalid"] or 0),
                "findings_indexed": int(findings["total"] or 0),
                "replay_outcomes": int(replays["total"] or 0),
            }

    def close(self) -> None:
        with self._lock:
            try:
                self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                self._connection.close()
                self._secure_permissions()

    def __enter__(self) -> "EvidenceStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
