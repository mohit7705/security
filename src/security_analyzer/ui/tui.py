"""Compatibility shim delegating TUI entrypoints to the non-clickable terminal progress view."""
from __future__ import annotations

from typing import Any, Callable

from security_analyzer.ui.plain import PlainProgress


def run_tui(
    *,
    target: str,
    start: Callable[[Callable[[Any], None] | None], tuple[int, dict[str, Any]]],
) -> tuple[int, dict[str, Any]]:
    """Run the scan using the non-clickable Nuclei/httpx-style terminal output."""
    progress = PlainProgress(target=target)
    code, state = start(lambda orchestrator: orchestrator.add_listener(progress.on_event))
    progress.print_banner(target=target)
    return code, state