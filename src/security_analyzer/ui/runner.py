"""Select the non-clickable Quiver progress display or silent mode."""
from __future__ import annotations

import os
import sys
from typing import Any, Callable

from security_analyzer.ui.events import fmt_duration, style_text, supports_color, supports_unicode

Start = Callable[[Callable[[Any], None] | None], tuple[int, dict[str, Any]]]
VALID_MODES = {"auto", "tui", "plain", "off"}


def resolve_ui_mode(requested: str | None) -> str:
    mode = (requested or os.environ.get("QUIVER_UI") or "auto").strip().lower()
    if mode not in VALID_MODES:
        mode = "auto"
    if mode == "off":
        return "off"
    # Always use the non-clickable Nuclei/httpx-style streaming progress view.
    return "plain"


def run_scan_with_ui(*, mode: str, target: str, start: Start) -> tuple[int, dict[str, Any]]:
    if mode == "off":
        return start(None)

    from security_analyzer.ui.plain import PlainProgress

    progress = PlainProgress(target=target)
    code, state = start(lambda orchestrator: orchestrator.add_listener(progress.on_event))
    # If startup failed before pipeline_start (e.g. preflight or scope error), still show the banner.
    progress.print_banner(target=target)
    return code, state


def print_tui_summary(state: dict[str, Any], code: int, output_root: str | None) -> None:
    color_ok = supports_color(sys.stdout)
    unicode_ok = supports_unicode(sys.stdout)
    rule = ("─" if unicode_ok else "-") * 62

    if "error" in state and "scan_id" not in state:
        err = style_text(f"[ERR] Scan failed: {state['error']}", "1;31", color_ok=color_ok)
        print(err)
        return

    root = output_root or "output"
    scan_id = state.get("scan_id", "?")
    overall = str(state.get("overall_status", "?")).upper()
    stages = state.get("stages") if isinstance(state.get("stages"), dict) else {}

    counts = {"SUCCESS": 0, "PARTIAL": 0, "FAILED": 0, "SKIPPED": 0}
    total_duration = 0.0
    for info in stages.values():
        if not isinstance(info, dict):
            continue
        st = str(info.get("status", "")).upper()
        if st in counts:
            counts[st] += 1
        total_duration += float(info.get("duration_sec") or 0.0)

    status_color = "32" if overall == "SUCCESS" else ("33" if overall == "PARTIAL" else "1;31")
    overall_styled = style_text(overall, status_color, color_ok=color_ok)
    inf = style_text("[INF]", "36", color_ok=color_ok)

    print(style_text(rule, "2", color_ok=color_ok))
    print(f"  {inf} Scan Status  : {overall_styled} (exit code {code}) · {fmt_duration(total_duration)}")
    if stages:
        print(
            f"  {inf} Steps Summary: "
            f"{counts['SUCCESS']}/{len(stages)} completed, "
            f"{counts['PARTIAL']} partial, "
            f"{counts['FAILED']} failed, "
            f"{counts['SKIPPED']} skipped"
        )
    print(f"  {inf} Scan ID      : {scan_id}")
    print(f"  {inf} Output Dir   : {root}/{scan_id}/")
    print(f"  {inf} Final Report : {root}/{scan_id}/reports/security_report.html")
    print(f"  {inf} JSON / MD    : {root}/{scan_id}/reports/security_report.json | .md")
    print(style_text(rule, "2", color_ok=color_ok))