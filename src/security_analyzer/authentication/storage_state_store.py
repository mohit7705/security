from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from security_analyzer.core.exceptions import ConfigurationError


class StorageStateStore:
    """Persists Playwright storage states in ./secrets/<scan_id>/ with strict 0600 file permissions."""

    def __init__(self, project_root: Path | None = None, scan_id: str = "default") -> None:
        self.project_root = (project_root or Path.cwd()).resolve()
        self.secrets_root = (self.project_root / "secrets").resolve()
        if self.secrets_root.parent != self.project_root:
            raise ConfigurationError("Secrets root must remain inside the project root")
        self._ensure_private_dir(self.secrets_root)

        if not re.match(r"^[a-zA-Z0-9._-]+$", scan_id):
            raise ConfigurationError(f"Invalid scan_id for secrets store: {scan_id!r}")
        self.scan_secrets_dir = (self.secrets_root / scan_id).resolve()
        if self.scan_secrets_dir.parent != self.secrets_root:
            raise ConfigurationError("Secrets path escaped secrets root")
        self._ensure_private_dir(self.scan_secrets_dir)

    @staticmethod
    def _ensure_private_dir(directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(directory, 0o700)

    def _resolve_secret_file(self, filename: str) -> Path:
        if not re.match(r"^[a-zA-Z0-9._-]+$", filename):
            raise ConfigurationError(f"Invalid secret filename: {filename!r}")
        target = (self.scan_secrets_dir / filename).resolve()
        if target.parent != self.scan_secrets_dir:
            raise ConfigurationError(f"Secret file escaped scan secrets dir: {target}")
        return target

    def write_secret_json(self, filename: str, payload: dict[str, Any]) -> Path:
        target = self._resolve_secret_file(filename)
        serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"

        fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
        tmp_path = Path(tmp_name)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, target)
            if os.name == "posix":
                os.chmod(target, 0o600)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise
        return target

    def save_storage_state(self, identity_id: str, storage_state: dict[str, Any]) -> Path:
        normalized = {
            "cookies": list(storage_state.get("cookies") or []),
            "origins": list(storage_state.get("origins") or []),
        }
        return self.write_secret_json(f"{identity_id}_storage_state.json", normalized)

    def load_storage_state(self, source_path: Path) -> dict[str, Any]:
        if not source_path.exists():
            raise ConfigurationError(f"Storage state file not found: {source_path}")
        raw = json.loads(source_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ConfigurationError(f"Invalid storage state JSON in {source_path}")
        return {
            "cookies": list(raw.get("cookies") or []),
            "origins": list(raw.get("origins") or []),
        }

    @staticmethod
    def audit_cookie_security(cookies: list[dict[str, Any]], is_https: bool) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        session_name_re = re.compile(r"(?i)(sess|sid|auth|token|jwt|login|csrf|xsrf)")

        for c in cookies:
            name = str(c.get("name", "")).strip()
            if not name:
                continue
            looks_sensitive = bool(session_name_re.search(name))
            http_only = bool(c.get("httpOnly", False))
            secure = bool(c.get("secure", False))
            same_site = str(c.get("sameSite", "None") or "None")

            issues: list[str] = []
            if looks_sensitive and not http_only:
                issues.append("missing_httponly")
            if is_https and not secure:
                issues.append("missing_secure_flag_on_https")
            if same_site.lower() == "none" and not secure:
                issues.append("samesite_none_without_secure")

            if issues:
                findings.append(
                    {
                        "cookie_name": name,
                        "domain": str(c.get("domain", "")),
                        "path": str(c.get("path", "/")),
                        "issues": issues,
                    }
                )
        return findings
