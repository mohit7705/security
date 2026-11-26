from __future__ import annotations

import io
import json
from pathlib import Path

from security_analyzer.ui.events import describe_artifact, fmt_duration, fmt_size, preview_file, status_symbol
from security_analyzer.ui.plain import PlainProgress


def test_progress_formatters() -> None:
    assert fmt_duration(1.1) == "1s"
    assert fmt_duration(61) == "1m 01s"
    assert fmt_size(1024) == "1.0 KB"
    assert status_symbol("SUCCESS", unicode_ok=False) == "+"


def test_artifact_description_and_preview_are_bounded_and_redacted(tmp_path: Path) -> None:
    (tmp_path / "artifact.json").write_text(json.dumps({"endpoints": [{"url": "https://example.test"}]}))
    info = describe_artifact(tmp_path, "artifact.json")
    assert info["exists"] and info["count"] == 1 and info["count_label"] == "endpoints"
    assert "https://example.test" in preview_file(tmp_path, "artifact.json")
    assert not describe_artifact(tmp_path, "../outside.json")["exists"]


def test_plain_progress_uses_stage_order_and_stderr_style_stream() -> None:
    output = io.StringIO()
    progress = PlainProgress(output)
    progress.on_event({"type": "pipeline_start", "stages": [
        {"stage_id": "one", "title": "One"}, {"stage_id": "two", "title": "Two"},
    ]})
    progress.on_event({"type": "stage", "stage_id": "two", "status": "RUNNING"})
    progress.on_event({"type": "stage", "stage_id": "two", "status": "PARTIAL", "duration_sec": 2, "summary": "some results"})
    lines = output.getvalue().splitlines()
    assert " 2  Two" in lines[0]
    assert " 2  Two" in lines[1] and "some results" in lines[1]
