from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def _contains_templates(directory: Path) -> bool:
    """A usable Nuclei template root must contain at least one YAML template."""
    try:
        if not directory.is_dir():
            return False
        return any(
            item.is_file() and item.suffix.lower() in {".yaml", ".yml"}
            for item in directory.rglob("*")
            if not item.is_symlink()
        )
    except OSError:
        return False


def resolve_nuclei_templates(
    nuclei_config: dict[str, Any] | None = None,
    *,
    project_root: Path | None = None,
) -> Path | None:
    """Resolve templates consistently for doctor and the Nuclei runner.

    Explicit settings take precedence over the environment and standard locations.
    Relative configured paths are interpreted relative to the project root.
    """
    config = nuclei_config or {}
    root = (project_root or Path.cwd()).expanduser().resolve()
    configured = str(config.get("templates_dir") or "").strip()
    env_configured = os.environ.get("NUCLEI_TEMPLATES_DIR", "").strip()

    if configured:
        raw = Path(configured).expanduser()
        candidate = raw if raw.is_absolute() else root / raw
        return candidate.resolve() if _contains_templates(candidate) else None

    if env_configured:
        raw = Path(env_configured).expanduser()
        candidate = raw if raw.is_absolute() else root / raw
        return candidate.resolve() if _contains_templates(candidate) else None

    home = Path.home()
    xdg_data = Path(os.environ.get("XDG_DATA_HOME", str(home / ".local" / "share"))).expanduser()
    candidates = (
        root / "config" / "nuclei-templates",
        root / "nuclei-templates",
        home / "nuclei-templates",
        home / ".local" / "nuclei-templates",
        xdg_data / "nuclei-templates",
        home / ".config" / "nuclei-templates",
        home / ".config" / "nuclei" / "templates",
        Path("/opt/nuclei-templates"),
        Path("/usr/share/nuclei-templates"),
    )

    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            if _contains_templates(resolved):
                return resolved
        except OSError:
            continue
    return None
