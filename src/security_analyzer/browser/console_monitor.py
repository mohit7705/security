from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from security_analyzer.core.workspace import WorkspaceManager
from security_analyzer.browser.network_capture import redact_url_query

SECRET_TOKEN_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._\-]+|eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+|(?:api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[^\s'\"&]+)"
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _redact_text(value: str) -> str:
    redacted = SECRET_TOKEN_RE.sub("[REDACTED_SECRET]", value)
    redacted = URL_RE.sub(lambda match: redact_url_query(match.group(0).rstrip(".,);]"))[0], redacted)
    return redacted[:1000]


@dataclass
class ConsoleEvent:
    event_type: str  # "console_error", "console_warning", "page_error"
    page_url: str
    message: str
    location: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ConsoleMonitor:
    """Records redacted browser console errors/warnings and uncaught page exceptions."""

    RELATIVE_PATH = "browser/console_events.json"

    def __init__(
        self,
        workspace: WorkspaceManager,
        max_events: int = 500,
        relative_path: str | None = None,
    ) -> None:
        self.workspace = workspace
        self.max_events = max(1, int(max_events))
        self.relative_path = relative_path or self.RELATIVE_PATH
        self._events: list[ConsoleEvent] = []

    def attach(self, page: Any) -> None:
        page.on("console", lambda msg: self._on_console(page, msg))
        page.on("pageerror", lambda err: self._on_page_error(page, err))

    def _on_console(self, page: Any, msg: Any) -> None:
        if len(self._events) >= self.max_events:
            return
        msg_type = str(msg.type or "").lower()
        if msg_type not in {"error", "warning"}:
            return
        loc = msg.location or {}
        loc_url = redact_url_query(str(loc.get("url", "")))[0]
        loc_str = f"{loc_url}:{loc.get('lineNumber', '')}".strip(":")
        self._events.append(
            ConsoleEvent(
                event_type=f"console_{msg_type}",
                page_url=redact_url_query(str(page.url or ""))[0],
                message=_redact_text(str(msg.text or "")),
                location=loc_str[:256],
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

    def _on_page_error(self, page: Any, err: Any) -> None:
        if len(self._events) >= self.max_events:
            return
        self._events.append(
            ConsoleEvent(
                event_type="page_error",
                page_url=redact_url_query(str(page.url or ""))[0],
                message=_redact_text(str(err)),
                location="",
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

    def save(self, stage_id: str = "browser_capture") -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "scan_id": self.workspace.scan_id,
            "stage_id": stage_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(self._events),
            "events": [e.to_dict() for e in self._events],
        }
        self.workspace.write_json_atomic(self.relative_path, payload)
        return payload
