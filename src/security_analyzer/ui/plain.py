"""Plain numbered progress output for non-interactive terminals."""
from __future__ import annotations

import sys
from typing import Any, TextIO

from security_analyzer.ui.events import TERMINAL_STATUSES, fmt_duration, status_symbol, supports_unicode


class PlainProgress:
    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stderr
        self._unicode = supports_unicode()
        self._index: dict[str, int] = {}
        self._titles: dict[str, str] = {}

    def _write(self, line: str) -> None:
        try:
            print(line, file=self._stream, flush=True)
        except (OSError, ValueError):
            pass

    def on_event(self, event: dict[str, Any]) -> None:
        if event.get("type") == "pipeline_start":
            for number, stage in enumerate(event.get("stages", []), start=1):
                self._index[stage["stage_id"]] = number
                self._titles[stage["stage_id"]] = stage["title"]
            return
        if event.get("type") == "stage_progress":
            percent = max(0, min(100, int(event.get("progress_percent", 0))))
            detail = str(event.get("message", ""))[:140]
            self._write(f"     {percent:>3}%  {detail}")
            return
        if event.get("type") != "stage":
            return
        stage_id = event["stage_id"]
        number = self._index.setdefault(stage_id, len(self._index) + 1)
        title = self._titles.get(stage_id, stage_id)
        status = event.get("status", "")
        if status == "RUNNING":
            self._write(f" {status_symbol(status, unicode_ok=self._unicode)} {number:>2}  {title}  (running...)")
        elif status in TERMINAL_STATUSES:
            line = f" {status_symbol(status, unicode_ok=self._unicode)} {number:>2}  {title}  {fmt_duration(event.get('duration_sec'))}"
            if status != "SUCCESS" and event.get("summary"):
                line += f"  - {str(event['summary'])[:140]}"
            if status == "FAILED" and event.get("error"):
                line += f" | reason: {str(event['error'])[:180]}"
            self._write(line)
