"""Clickable live terminal view for a Quiver scan (optional Textual dependency)."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import Footer, Static, Tree

from security_analyzer.ui.events import (
    TERMINAL_STATUSES, artifact_line, count_output_files, describe_artifacts,
    fmt_duration, preview_file, status_symbol, supports_unicode,
)

_STYLES = {"SUCCESS": "green", "PARTIAL": "yellow", "FAILED": "bold red", "SKIPPED": "grey62", "RUNNING": "cyan", "PENDING": "grey50"}


@dataclass
class StageView:
    stage_id: str
    title: str
    phase: str
    index: int
    status: str = "PENDING"
    summary: str = ""
    error: str = ""
    duration: float = 0.0
    progress_percent: int = 0
    progress_message: str = ""
    started_mono: float | None = None
    started_clock: str = ""
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    node: Any = None


class QuiverApp(App[None]):
    TITLE = "Quiver"
    CSS = "#title { height: 2; padding: 0 1; text-style: bold; } #counts { height: 1; padding: 0 1; color: #8a8a8a; } #stages { height: 1fr; padding: 0 1; } #preview_box { height: 12; border-top: solid $primary; padding: 0 1; }"
    BINDINGS = [Binding("q", "quit_app", "Quit"), Binding("ctrl+c", "quit_app", "Quit", show=False), Binding("e", "expand_all", "Expand all"), Binding("c", "collapse_all", "Collapse all")]

    def __init__(self, *, target: str, start: Callable[[Callable[[Any], None] | None], tuple[int, dict[str, Any]]]) -> None:
        super().__init__()
        self._scan_target, self._scan_starter = target, start
        self._unicode = supports_unicode()
        self._stage_views: dict[str, StageView] = {}
        self._spinner_frame = 0
        self._began = time.monotonic()
        self._orchestrator: Any = None
        self._scan_worker: threading.Thread | None = None
        self._scan_done = False
        self._quit_requested = False
        self.scan_result: tuple[int, dict[str, Any]] | None = None

    def compose(self) -> ComposeResult:
        yield Static(Text(f"Quiver — scanning {self._scan_target}"), id="title")
        yield Static(Text(""), id="counts")
        yield Tree("Stages", id="stages")
        with VerticalScroll(id="preview_box"):
            yield Static(Text("Click a stage (or Enter) to expand / collapse.\nClick an output file to preview it.  e = expand all  c = collapse all  q = quit"), id="preview")
        yield Footer()

    def on_mount(self) -> None:
        tree = self.query_one("#stages", Tree)
        tree.show_root = False
        tree.root.expand()
        self.set_interval(0.1, self._spinner_tick)
        self._scan_worker = threading.Thread(target=self._run_scan_thread, name="quiver-scan", daemon=True)
        self._scan_worker.start()

    def _run_scan_thread(self) -> None:
        try:
            code, state = self._scan_starter(self._attach_orchestrator)
        except BaseException as exc:
            code, state = 1, {"error": f"{exc.__class__.__name__}: {exc}"}
        self.scan_result = (code, state)
        scan_dir = getattr(getattr(self._orchestrator, "workspace", None), "scan_dir", None)
        files = count_output_files(Path(scan_dir)) if scan_dir else 0
        self._post_to_ui(self._scan_finished, code, state, str(scan_dir or ""), files)

    def _attach_orchestrator(self, orchestrator: Any) -> None:
        self._orchestrator = orchestrator
        orchestrator.add_listener(self._receive_event)
        if self._quit_requested:
            orchestrator.cancel()

    def _receive_event(self, event: dict[str, Any]) -> None:
        scan_dir = Path(str(event.get("scan_dir", "")))
        enriched = dict(event)
        if event.get("type") == "pipeline_start":
            enriched["stages"] = [{**s, "artifact_info": describe_artifacts(scan_dir, list(s.get("artifacts", [])))} for s in event.get("stages", [])]
        elif event.get("type") == "stage" and event.get("status") in TERMINAL_STATUSES:
            enriched["artifact_info"] = describe_artifacts(scan_dir, list(event.get("artifacts", [])))
        self._post_to_ui(self._apply_scan_event, enriched)

    def _post_to_ui(self, fn: Callable[..., None], *args: Any) -> None:
        try:
            self.call_from_thread(fn, *args)
        except Exception:
            pass

    def _apply_scan_event(self, event: dict[str, Any]) -> None:
        self._scan_dir = event.get("scan_dir", getattr(self, "_scan_dir", ""))
        if event.get("type") == "pipeline_start":
            for number, item in enumerate(event.get("stages", []), 1):
                view = self._ensure_stage(item["stage_id"], item.get("title", item["stage_id"]), item.get("phase", ""), number)
                view.status = item.get("status", "PENDING")
                view.summary, view.error = item.get("summary", ""), item.get("error", "")
                view.duration = float(item.get("duration_sec") or 0)
                view.artifacts = list(item.get("artifact_info", []))
                self._fill_stage(view)
                self._refresh_label(view)
        elif event.get("type") == "stage_progress":
            view = self._stage_views.get(event["stage_id"])
            if view is not None:
                view.progress_percent = max(0, min(100, int(event.get("progress_percent", 0))))
                view.progress_message = str(event.get("message", ""))[:160]
                self._fill_stage(view)
        elif event.get("type") == "stage":
            existing = self._stage_views.get(event["stage_id"])
            view = self._ensure_stage(
                event["stage_id"],
                event.get("title") or (existing.title if existing else event["stage_id"]),
                event.get("phase") or (existing.phase if existing else ""),
                existing.index if existing else len(self._stage_views) + 1,
            )
            view.status = event.get("status", view.status)
            view.summary, view.error = event.get("summary", ""), event.get("error", "")
            view.duration = float(event.get("duration_sec") or 0)
            if view.status == "RUNNING":
                view.started_mono, view.started_clock = time.monotonic(), time.strftime("%H:%M:%S")
            if "artifact_info" in event:
                view.artifacts = list(event["artifact_info"])
            self._fill_stage(view)
            self._refresh_label(view)
        self._refresh_counts()

    def _ensure_stage(self, sid: str, title: str, phase: str, index: int) -> StageView:
        view = self._stage_views.get(sid)
        if view is None:
            view = StageView(sid, title, phase, index)
            view.node = self.query_one("#stages", Tree).root.add(Text(""), data={"kind": "stage", "id": sid}, expand=False)
            self._stage_views[sid] = view
        else:
            view.title, view.phase = title or view.title, phase or view.phase
        return view

    def _make_label(self, view: StageView) -> Text:
        symbol = status_symbol(view.status, self._spinner_frame, self._unicode)
        if view.status == "RUNNING":
            tail = f"{fmt_duration(time.monotonic() - (view.started_mono or time.monotonic()))}  (running…)"
        elif view.status in TERMINAL_STATUSES:
            tail = fmt_duration(view.duration)
        else:
            tail = ""
        return Text.assemble((f" {symbol} ", _STYLES.get(view.status, "grey50")), (f"{view.index:>2}  ", "bold"), (view.title.ljust(44), "grey50" if view.status == "PENDING" else ""), (tail, "grey62"))

    def _refresh_label(self, view: StageView) -> None:
        if view.node is not None:
            view.node.set_label(self._make_label(view))

    def _fill_stage(self, view: StageView) -> None:
        node = view.node
        node.remove_children()
        if view.status == "PENDING":
            node.add_leaf(Text("Not started yet", style="grey50"))
            return
        if view.status == "RUNNING":
            node.add_leaf(Text(f"Running… started {view.started_clock or 'just now'} · {view.progress_percent}%", style="cyan"))
            if view.progress_message:
                node.add_leaf(Text(f"Progress  {view.progress_message}", style="grey70"))
            return
        node.add_leaf(Text(f"Status   {view.status} · {fmt_duration(view.duration)} · phase: {view.phase or '-'}"))
        if view.summary:
            node.add_leaf(Text(f"Result   {view.summary[:200]}"))
        if view.error:
            node.add_leaf(Text(f"Error    {view.error[:200]}", style="red"))
        if view.artifacts:
            outputs = node.add(Text(f"Output files ({len(view.artifacts)})", style="bold"), expand=True)
            for info in view.artifacts:
                outputs.add_leaf(Text(artifact_line(info), style="" if info.get("exists") else "red"), data={"kind": "file", "path": info["path"]})
        else:
            node.add_leaf(Text("Output files (0)", style="grey62"))

    def _refresh_counts(self) -> None:
        counts: dict[str, int] = {}
        for view in self._stage_views.values():
            counts[view.status] = counts.get(view.status, 0) + 1
        line = (f"{status_symbol('SUCCESS', unicode_ok=self._unicode)} {counts.get('SUCCESS', 0)} done   "
                f"{status_symbol('PARTIAL', unicode_ok=self._unicode)} {counts.get('PARTIAL', 0)} partial   "
                f"{status_symbol('SKIPPED', unicode_ok=self._unicode)} {counts.get('SKIPPED', 0)} skipped   "
                f"{status_symbol('FAILED', unicode_ok=self._unicode)} {counts.get('FAILED', 0)} failed   "
                f"{counts.get('PENDING', 0)+counts.get('RUNNING', 0)} waiting   elapsed {fmt_duration(time.monotonic()-self._began)}")
        self.query_one("#counts", Static).update(Text(line))

    def _spinner_tick(self) -> None:
        self._spinner_frame += 1
        for view in self._stage_views.values():
            if view.status == "RUNNING":
                self._refresh_label(view)
        if not self._scan_done:
            self._refresh_counts()

    def _scan_finished(self, code: int, state: dict[str, Any], scan_dir: str, files: int) -> None:
        self._scan_done = True
        if "error" in state and "scan_id" not in state:
            msg = f"Quiver — scan failed: {state['error']}   (press q to quit)"
        else:
            msg = f"Quiver — scan complete: {state.get('overall_status', '?')} (exit {code}) · {files} files in {scan_dir}   (press q to quit)"
        self.query_one("#title", Static).update(Text(msg))
        self._refresh_counts()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = event.node.data
        if isinstance(data, dict) and data.get("kind") == "file" and getattr(self, "_scan_dir", ""):
            self.query_one("#preview", Static).update(Text(preview_file(Path(self._scan_dir), str(data["path"]))))

    def action_expand_all(self) -> None:
        for view in self._stage_views.values():
            view.node.expand()

    def action_collapse_all(self) -> None:
        for view in self._stage_views.values():
            view.node.collapse()

    def action_quit_app(self) -> None:
        if not self._scan_done:
            self._quit_requested = True
            if self._orchestrator is not None:
                self._orchestrator.cancel()
        self.exit()

    def wait_for_scan(self, timeout: float = 60.0) -> None:
        if self._scan_worker is not None and self._scan_worker.is_alive():
            self._scan_worker.join(timeout=timeout)


def run_tui(*, target: str, start: Callable[[Callable[[Any], None] | None], tuple[int, dict[str, Any]]]) -> tuple[int, dict[str, Any]]:
    app = QuiverApp(target=target, start=start)
    app.run(mouse=True)
    if app.scan_result is None:
        print("[quiver] Stopping running tools…")
        app.wait_for_scan()
    return app.scan_result or (130, {"cancelled": True, "overall_status": "FAILED"})