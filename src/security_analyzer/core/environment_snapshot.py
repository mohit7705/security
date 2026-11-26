from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _version(command: list[str], timeout: float = 4.0) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        output = (result.stdout or result.stderr or "").strip().splitlines()
        return output[0][:200] if output else f"exit={result.returncode}"
    except Exception as exc:
        return f"unavailable:{type(exc).__name__}"


def build_environment_snapshot(settings: dict[str, Any], project_root: Path | None = None) -> dict[str, Any]:
    root = project_root or Path.cwd()
    packages: dict[str, str] = {}
    for package in ("PyYAML", "requests", "urllib3", "playwright"):
        try:
            packages[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            packages[package] = "not-installed"

    installed_packages: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = str(distribution.metadata.get("Name") or "").strip()
        if name:
            installed_packages[name.lower()] = distribution.version

    tools: dict[str, dict[str, str]] = {}
    for name, args in {
        "subfinder": ["-version"], "nuclei": ["-version"],
        "ffuf": ["-V"], "dig": ["-v"],
    }.items():
        path = shutil.which(name)
        tools[name] = {"path": path or "", "version": _version([path, *args]) if path else "not-installed"}

    config_bytes = json.dumps(settings, sort_keys=True, separators=(",", ":"), default=str).encode()
    template_paths = (root / "nuclei-templates", root / ".local" / "nuclei-templates")
    template_fingerprint = "absent"
    template_root = ""
    template_file_count = 0
    template_fingerprint_complete = True
    max_template_files = 10000
    max_template_bytes = 256 * 1024 * 1024
    seen_template_roots: set[Path] = set()
    for candidate in template_paths:
        if candidate is None:
            continue
        try:
            if not candidate.is_absolute():
                candidate = root / candidate
            if candidate.is_symlink():
                continue
            candidate = candidate.resolve()
            if candidate in seen_template_roots or not candidate.is_dir():
                continue
            seen_template_roots.add(candidate)
            digest = hashlib.sha256()
            total_bytes = 0
            for template_file in sorted(candidate.rglob("*")):
                if template_file.is_symlink() or not template_file.is_file():
                    continue
                if template_file_count >= max_template_files:
                    template_fingerprint_complete = False
                    break
                size = template_file.stat().st_size
                if total_bytes + size > max_template_bytes:
                    template_fingerprint_complete = False
                    break
                relative = template_file.relative_to(candidate).as_posix()
                digest.update(relative.encode("utf-8"))
                digest.update(b"\\0")
                with template_file.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                        total_bytes += len(chunk)
                digest.update(b"\\n")
                template_file_count += 1
            template_fingerprint = digest.hexdigest()
            template_root = str(candidate)
            break
        except OSError:
            template_fingerprint = "unreadable"
            template_root = str(candidate)
            template_fingerprint_complete = False
            break

    return {
        "schema_version": "1.0",
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "packages": packages,
        "installed_packages": dict(sorted(installed_packages.items())),
        "tools": tools,
        "nuclei_templates": {
            "root": template_root,
            "file_count": template_file_count,
            "content_sha256": template_fingerprint,
            "complete": template_fingerprint_complete,
            "max_files": max_template_files,
            "max_bytes": max_template_bytes,
        },
        "settings_sha256": hashlib.sha256(config_bytes).hexdigest(),
    }
