"""Non-clickable Nuclei/httpx-style terminal progress view for Quiver."""
from __future__ import annotations

import importlib.metadata
import sys
from pathlib import Path
from typing import Any, TextIO

from security_analyzer.ui.events import (
    TERMINAL_STATUSES,
    describe_artifacts,
    display_scan_dir,
    fmt_duration,
    format_output_location,
    render_banner,
    status_symbol,
    style_text,
    supports_color,
    supports_unicode,
)
from security_analyzer.utils.redaction import scrub_text


def _package_version() -> str:
    try:
        return importlib.metadata.version("security-analyzer")
    except importlib.metadata.PackageNotFoundError:
        return "0.1.0"


class PlainProgress:
    """Streams the startup banner and per-step status, reason, and output path without mouse/click UI."""

    def __init__(self, stream: TextIO | None = None, *, target: str = "") -> None:
        self._stream = stream or sys.stderr
        self._target = target
        self._unicode = supports_unicode(self._stream)
        self._color = supports_color(self._stream)
        try:
            self._is_tty = bool(self._stream.isatty())
        except Exception:
            self._is_tty = False

        self._index: dict[str, int] = {}
        self._titles: dict[str, str] = {}
        self._artifacts_map: dict[str, list[str]] = {}
        self._last_percent: dict[str, int] = {}
        self._total_stages = 15
        self._scan_dir = ""
        self._banner_printed = False
        self._has_inline_progress = False

    def _clear_inline_progress(self) -> None:
        if self._is_tty and self._has_inline_progress:
            try:
                self._stream.write("\r\033[2K")
                self._stream.flush()
            except (OSError, ValueError):
                pass
        self._has_inline_progress = False

    def _write(self, line: str = "") -> None:
        self._clear_inline_progress()
        try:
            print(line, file=self._stream, flush=True)
        except (OSError, ValueError):
            pass

    def _write_inline(self, line: str) -> None:
        if not self._is_tty:
            self._write(line)
            return
        try:
            self._stream.write(f"\r\033[2K{line}")
            self._stream.flush()
            self._has_inline_progress = True
        except (OSError, ValueError):
            pass

    def print_banner(
        self,
        *,
        target: str = "",
        scan_id: str = "",
        output_dir: str = "",
        total_stages: int | None = None,
    ) -> None:
        if self._banner_printed:
            return
        self._banner_printed = True
        banner = render_banner(
            version=_package_version(),
            target=target or self._target,
            scan_id=scan_id,
            output_dir=output_dir,
            total_stages=total_stages if total_stages is not None else self._total_stages,
            unicode_ok=self._unicode,
            color_ok=self._color,
        )
        self._write(banner)
        self._write("")

    def _branch(self, last: bool = False) -> str:
        if self._unicode:
            return "└─" if last else "├─"
        return "`-" if last else "|-"

    def _format_step_header(self, number: int, total: int, title: str) -> str:
        step_tag = style_text(f"[Step {number}/{total}]", "1;36", color_ok=self._color)
        title_text = style_text(title, "1", color_ok=self._color)
        return f"{step_tag} {title_text}"

    def _print_terminal_stage(
        self,
        *,
        stage_id: str,
        number: int,
        title: str,
        status: str,
        duration_sec: float | int | None,
        summary: str,
        error: str,
        artifact_paths: list[str],
        reused: bool = False,
    ) -> None:
        sym = status_symbol(status, unicode_ok=self._unicode)
        dur = fmt_duration(duration_sec)
        clean_summary = scrub_text(str(summary or "")).strip()
        clean_error = scrub_text(str(error or "")).strip()

        if status == "SUCCESS":
            pct_label = "100% (SUCCESS - reused)" if reused else f"100% (SUCCESS) · {dur}"
            status_line = style_text(f"{sym} {pct_label}", "32", color_ok=self._color)
        elif status == "PARTIAL":
            pct = self._last_percent.get(stage_id)
            pct_part = f"PARTIAL ({pct}%)" if pct and 0 < pct < 100 else "PARTIAL"
            status_line = style_text(f"{sym} {pct_part} · {dur}", "33", color_ok=self._color)
        elif status == "SKIPPED":
            status_line = style_text(f"{sym} SKIPPED", "33", color_ok=self._color)
        else:
            status_line = style_text(f"{sym} FAILED · {dur}", "1;31", color_ok=self._color)

        reason_text = ""
        if status == "FAILED":
            reason_text = clean_error or clean_summary or "Stage execution failed"
        elif status in {"SKIPPED", "PARTIAL"}:
            reason_text = clean_summary or clean_error

        existing_outputs: list[str] = []
        if self._scan_dir and artifact_paths:
            infos = describe_artifacts(Path(self._scan_dir), artifact_paths)
            for info in infos:
                if info.get("exists") or status == "SUCCESS":
                    existing_outputs.append(format_output_location(self._scan_dir, info))

        if existing_outputs:
            output_lines = existing_outputs
        elif status == "SKIPPED":
            output_lines = ["none (stage skipped)"]
        elif status == "FAILED":
            output_lines = ["none (no output file generated)"]
        else:
            output_lines = ["none"]

        has_reason = bool(reason_text)
        self._write(f"  {self._branch(False)} Status   : {status_line}")
        if has_reason:
            reason_label = "Reason" if status == "FAILED" else "Note"
            styled_reason = (
                style_text(reason_text[:220], "31", color_ok=self._color)
                if status == "FAILED"
                else reason_text[:220]
            )
            self._write(f"  {self._branch(False)} {reason_label:<8} : {styled_reason}")

        first_out = output_lines[0]
        self._write(f"  {self._branch(True)} Output   : {first_out}")
        for extra_out in output_lines[1:]:
            self._write(f"               {extra_out}")
        self._write("")

    def on_event(self, event: dict[str, Any]) -> None:
        etype = event.get("type")
        if event.get("scan_dir"):
            self._scan_dir = str(event["scan_dir"])

        if etype == "pipeline_start":
            stages = list(event.get("stages") or [])
            if stages:
                self._total_stages = len(stages)
            scan_id = Path(self._scan_dir).name if self._scan_dir else str(event.get("scan_id", ""))
            self.print_banner(
                target=str(event.get("target") or self._target),
                scan_id=scan_id,
                output_dir=display_scan_dir(self._scan_dir),
                total_stages=self._total_stages,
            )
            for number, stage in enumerate(stages, start=1):
                sid = stage["stage_id"]
                self._index[sid] = number
                self._titles[sid] = stage.get("title", sid)
                self._artifacts_map[sid] = list(stage.get("artifacts") or [])
                prior_status = str(stage.get("status") or "PENDING").upper()
                if prior_status in TERMINAL_STATUSES:
                    self._write(self._format_step_header(number, self._total_stages, self._titles[sid]))
                    self._print_terminal_stage(
                        stage_id=sid,
                        number=number,
                        title=self._titles[sid],
                        status=prior_status,
                        duration_sec=stage.get("duration_sec"),
                        summary=str(stage.get("summary") or ""),
                        error=str(stage.get("error") or ""),
                        artifact_paths=self._artifacts_map[sid],
                        reused=(prior_status == "SUCCESS"),
                    )
            return

        if etype == "stage_progress":
            sid = str(event.get("stage_id", ""))
            percent = max(0, min(100, int(event.get("progress_percent", 0))))
            self._last_percent[sid] = percent
            detail = scrub_text(str(event.get("message", ""))).strip()[:120]
            spin = status_symbol("RUNNING", frame=percent, unicode_ok=self._unicode)
            prog = style_text(f"{spin} {percent:>3}%", "36", color_ok=self._color)
            suffix = f"  {detail}" if detail else ""
            self._write_inline(f"  {self._branch(True)} Progress : {prog}{suffix}")
            return

        if etype != "stage":
            return

        stage_id = str(event["stage_id"])
        number = self._index.setdefault(stage_id, len(self._index) + 1)
        total = max(self._total_stages, number)
        title = event.get("title") or self._titles.setdefault(stage_id, stage_id)
        status = str(event.get("status", "")).upper()

        if status == "RUNNING":
            self._last_percent[stage_id] = 0
            self._write(self._format_step_header(number, total, title))
            spin = status_symbol("RUNNING", frame=0, unicode_ok=self._unicode)
            prog = style_text(f"{spin}   0%  Running...", "36", color_ok=self._color)
            self._write_inline(f"  {self._branch(True)} Progress : {prog}")
        elif status in TERMINAL_STATUSES:
            if number not in self._index.values():
                self._write(self._format_step_header(number, total, title))
            artifacts = list(event.get("artifacts") or self._artifacts_map.get(stage_id) or [])
            self._print_terminal_stage(
                stage_id=stage_id,
                number=number,
                title=title,
                status=status,
                duration_sec=event.get("duration_sec"),
                summary=str(event.get("summary") or ""),
                error=str(event.get("error") or ""),
                artifact_paths=artifacts,
            )