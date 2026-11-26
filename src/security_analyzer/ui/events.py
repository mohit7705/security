"""Formatting and safe output-file helpers shared by the progress views."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from security_analyzer.utils.redaction import scrub_text

SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
ASCII_SPINNER = "|/-\\"
_UNICODE = {"SUCCESS": "✔", "PARTIAL": "⚠", "FAILED": "✖", "SKIPPED": "⊘", "PENDING": "○"}
_ASCII = {"SUCCESS": "+", "PARTIAL": "!", "FAILED": "x", "SKIPPED": "-", "PENDING": "."}
TERMINAL_STATUSES = {"SUCCESS", "PARTIAL", "FAILED", "SKIPPED"}
MAX_JSON_BYTES = 5 * 1024 * 1024
PREVIEW_READ_BYTES = 64 * 1024
COUNT_KEYS = ("endpoints", "findings", "records", "hosts", "tests", "operations", "routes", "observations", "entries", "items")


def supports_unicode() -> bool:
    return os.environ.get("QUIVER_ASCII") != "1" and "utf" in (getattr(sys.stdout, "encoding", None) or "").lower()


def status_symbol(status: str, frame: int = 0, unicode_ok: bool | None = None) -> str:
    use_unicode = supports_unicode() if unicode_ok is None else unicode_ok
    if status == "RUNNING":
        frames = SPINNER_FRAMES if use_unicode else ASCII_SPINNER
        return frames[frame % len(frames)]
    return (_UNICODE if use_unicode else _ASCII).get(status, (_UNICODE if use_unicode else _ASCII)["PENDING"])


def fmt_duration(seconds: float | int | None) -> str:
    value = float(seconds or 0)
    if value < 1:
        return f"{value:.1f}s"
    if value < 60:
        return f"{int(round(value))}s"
    minutes, rest = divmod(int(round(value)), 60)
    return f"{minutes}m {rest:02d}s"


def fmt_size(size: int | float) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{int(value)} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def _inside(scan_dir: Path, relative: str) -> Path | None:
    try:
        root = scan_dir.resolve()
        path = (root / relative).resolve()
        path.relative_to(root)
        return path
    except (ValueError, OSError):
        return None


def describe_artifact(scan_dir: Path, relative: str) -> dict[str, Any]:
    info: dict[str, Any] = {"path": relative, "exists": False, "size": 0, "count": None, "count_label": ""}
    path = _inside(scan_dir, relative)
    if path is None or not path.is_file():
        return info
    info["exists"], info["size"] = True, path.stat().st_size
    if path.suffix.lower() != ".json" or info["size"] > MAX_JSON_BYTES:
        return info
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return info
    if isinstance(data, list):
        info["count"], info["count_label"] = len(data), "items"
    elif isinstance(data, dict):
        key = next((k for k in COUNT_KEYS if isinstance(data.get(k), list)), None)
        if key is None:
            key = next((k for k, v in data.items() if isinstance(v, list)), None)
        if key is not None:
            info["count"], info["count_label"] = len(data[key]), key
    return info


def describe_artifacts(scan_dir: Path, relatives: list[str]) -> list[dict[str, Any]]:
    return [describe_artifact(scan_dir, rel) for rel in relatives]


def artifact_line(info: dict[str, Any]) -> str:
    if not info.get("exists"):
        return f"{info['path']}  (missing)"
    parts = [fmt_size(info["size"])]
    if info.get("count") is not None:
        parts.append(f"{info['count']} {info['count_label']}")
    return f"{info['path']}  " + " · ".join(parts)


def count_output_files(scan_dir: Path) -> int:
    try:
        return sum(1 for p in scan_dir.rglob("*") if p.is_file())
    except OSError:
        return 0


def preview_file(scan_dir: Path, relative: str, max_lines: int = 30) -> str:
    path = _inside(scan_dir, relative)
    if path is None or not path.is_file():
        return f"{relative}\n(file not found)"
    size = path.stat().st_size
    try:
        with path.open("rb") as handle:
            raw = handle.read(PREVIEW_READ_BYTES)
    except OSError as exc:
        return f"{relative}\n(cannot read: {exc.__class__.__name__})"
    content = raw.decode("utf-8", errors="replace")
    if path.suffix.lower() == ".json" and size <= PREVIEW_READ_BYTES:
        try:
            content = json.dumps(json.loads(content), indent=2, sort_keys=True)
        except ValueError:
            pass
    lines = scrub_text(content).splitlines()
    shown = lines[:max_lines]
    more = len(lines) - len(shown)
    header = f"{relative}  ({fmt_size(size)})"
    footer = f"… {more} more line(s)" if more else ("… (file truncated)" if size > PREVIEW_READ_BYTES else "")
    return "\n".join([header, "-" * min(len(header), 60), *shown, footer]).rstrip()
