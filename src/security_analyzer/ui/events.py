"""Formatting, banner, and safe output-file helpers shared by progress views."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, TextIO

from security_analyzer.utils.redaction import scrub_text

SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
ASCII_SPINNER = "|/-\\"
_UNICODE = {"SUCCESS": "✔", "PARTIAL": "⚠", "FAILED": "✖", "SKIPPED": "⊘", "PENDING": "○"}
_ASCII = {"SUCCESS": "+", "PARTIAL": "!", "FAILED": "x", "SKIPPED": "-", "PENDING": "."}
TERMINAL_STATUSES = {"SUCCESS", "PARTIAL", "FAILED", "SKIPPED"}
MAX_JSON_BYTES = 5 * 1024 * 1024
PREVIEW_READ_BYTES = 64 * 1024
COUNT_KEYS = ("endpoints", "findings", "records", "hosts", "tests", "operations", "routes", "observations", "entries", "items")

QUIVER_BANNER_ART = r"""
   ____        _                
  / __ \__  __(_)   _____  _____
 / / / / / / / / | / / _ \/ ___/
/ /_/ / /_/ / /| |/ /  __/ /    
\___\_\__,_/_/ |___/\___/_/     
""".strip("\n")


def supports_unicode(stream: TextIO | None = None) -> bool:
    target = stream or sys.stderr
    return os.environ.get("QUIVER_ASCII") != "1" and "utf" in (getattr(target, "encoding", None) or "").lower()


def supports_color(stream: TextIO | None = None) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("QUIVER_NO_COLOR") == "1":
        return False
    target = stream or sys.stderr
    try:
        is_tty = bool(target.isatty())
    except Exception:
        is_tty = False
    return is_tty and os.environ.get("TERM", "") not in {"", "dumb"}


def style_text(text: str, code: str, *, color_ok: bool) -> str:
    if not color_ok or not code:
        return text
    return f"\033[{code}m{text}\033[0m"


def render_banner(
    *,
    version: str = "0.1.0",
    target: str = "",
    scan_id: str = "",
    output_dir: str = "",
    total_stages: int = 15,
    unicode_ok: bool = True,
    color_ok: bool = True,
) -> str:
    rule = ("─" if unicode_ok else "-") * 62
    art = style_text(QUIVER_BANNER_ART, "1;36", color_ok=color_ok)
    ver = style_text(f"v{version}", "1;37", color_ok=color_ok)
    tagline = style_text("  Scope-Enforced Security Assessment Pipeline", "2", color_ok=color_ok)
    inf = style_text("[INF]", "36", color_ok=color_ok)

    lines = [
        f"{art}  {ver}",
        "",
        tagline,
        style_text(rule, "2", color_ok=color_ok),
    ]
    if target:
        lines.append(f"  {inf} Target   : {scrub_text(target)}")
    if scan_id:
        lines.append(f"  {inf} Scan ID  : {scan_id}")
    if output_dir:
        lines.append(f"  {inf} Output   : {output_dir}")
    if total_stages > 0:
        lines.append(f"  {inf} Pipeline : {total_stages} steps")
    lines.append(style_text(rule, "2", color_ok=color_ok))
    return "\n".join(lines)


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


def display_scan_dir(scan_dir: str | Path) -> str:
    raw = str(scan_dir or "").strip()
    if not raw:
        return ""
    path = Path(raw)
    try:
        rel = path.resolve().relative_to(Path.cwd().resolve())
        return str(rel)
    except (ValueError, OSError):
        return raw


def format_output_location(scan_dir: str | Path, info: dict[str, Any]) -> str:
    base = display_scan_dir(scan_dir)
    rel = str(info.get("path", "")).lstrip("/")
    full_path = f"{base}/{rel}" if base else rel
    if not info.get("exists"):
        return f"{full_path} (not written)"
    parts = [fmt_size(info["size"])]
    if info.get("count") is not None:
        parts.append(f"{info['count']} {info['count_label']}")
    return f"{full_path} ({' · '.join(parts)})"


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