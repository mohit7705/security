"""Select the live TUI, plain progress lines, or no progress view."""
from __future__ import annotations

import os
import sys
from typing import Any, Callable

Start = Callable[[Callable[[Any], None] | None], tuple[int, dict[str, Any]]]
VALID_MODES = {"auto", "tui", "plain", "off"}


def _textual_available() -> bool:
    try:
        import textual  # noqa: F401
        return True
    except ImportError:
        return False


def _interactive_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty() and os.environ.get("TERM", "") not in {"", "dumb"}


def resolve_ui_mode(requested: str | None) -> str:
    mode = (requested or os.environ.get("QUIVER_UI") or "auto").strip().lower()
    if mode not in VALID_MODES:
        mode = "auto"
    if mode in {"plain", "off"}:
        return mode
    if _interactive_terminal() and _textual_available():
        return "tui"
    if mode == "tui":
        reason = "textual is not installed (pip install 'security-analyzer[ui]')" if not _textual_available() else "this is not an interactive terminal"
        print(f"[quiver] Live view unavailable: {reason}. Using plain progress.", file=sys.stderr)
    return "plain"


def run_scan_with_ui(*, mode: str, target: str, start: Start) -> tuple[int, dict[str, Any]]:
    if mode == "tui":
        from security_analyzer.ui.tui import run_tui
        return run_tui(target=target, start=start)
    if mode == "plain":
        from security_analyzer.ui.plain import PlainProgress
        progress = PlainProgress()
        return start(lambda orchestrator: orchestrator.add_listener(progress.on_event))
    return start(None)


def print_tui_summary(state: dict[str, Any], code: int, output_root: str | None) -> None:
    if "error" in state and "scan_id" not in state:
        print(f"Scan failed: {state['error']}")
        return
    root = output_root or "output"
    scan_id = state.get("scan_id", "?")
    print(f"Scan complete: {state.get('overall_status', '?')} (exit code {code})")
    print(f"Scan ID : {scan_id}\nResults : {root}/{scan_id}/\nReports : {root}/{scan_id}/reports/")
