
from __future__ import annotations

import importlib.metadata
import importlib.util
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolStatus:
    name: str
    kind: str
    required: bool
    available: bool
    path_or_module: str
    version: str


class DependencyManager:
    """
    Profile-aware dependency doctor.

    Core CLI tools remain separate from optional integrations.
    Optional tools are reported without making existing profiles
    fail merely because an optional scanner is not installed.

    Version output is normalized before identity validation so
    terminal formatting, ANSI escape sequences, and ASCII banners
    do not cause false-negative dependency checks.
    """

    CLI_COMMANDS: dict[str, list[str]] = {
        "subfinder": ["-version"],
        "nuclei": ["-version"],
        "ffuf": ["-V"],
        "dig": ["-v"],
    }

    OPTIONAL_CLI_COMMANDS: dict[str, list[str]] = {
        "katana": ["-version"],
        "testssl.sh": ["--version"],
    }

    # Each tuple contains accepted identity markers.
    # At least one marker must occur in the normalized output.
    IDENTITY_MARKERS: dict[str, tuple[str, ...]] = {
        "subfinder": ("subfinder", "projectdiscovery"),
        "nuclei": ("nuclei", "projectdiscovery"),
        "ffuf": ("ffuf",),
        "dig": ("dig",),
        "katana": ("katana", "projectdiscovery.io"),
        "testssl.sh": ("testssl.sh", "testssl"),
    }

    MODULES: dict[str, str] = {
        "yaml": "PyYAML",
        "requests": "requests",
        "urllib3": "urllib3",
        "playwright": "playwright",
    }

    PROFILES = {
        "core-only": {
            "modules": {
                "yaml",
                "requests",
                "urllib3",
            },
            "cli": set(),
        },
        "browser-enabled": {
            "modules": {
                "yaml",
                "requests",
                "urllib3",
                "playwright",
            },
            "cli": set(),
        },
        "full-scanner": {
            "modules": {
                "yaml",
                "requests",
                "urllib3",
                "playwright",
            },
            "cli": {
                "subfinder",
                "nuclei",
                "ffuf",
                "dig",
            },
        },
    }

    # Remove terminal color and formatting escape sequences.
    ANSI_ESCAPE_RE = re.compile(
        r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
    )

    @classmethod
    def _normalize_output(cls, output: str) -> str:
        """Remove ANSI escapes and terminal control characters."""
        output = cls.ANSI_ESCAPE_RE.sub("", output)

        # Remove remaining non-printable control characters,
        # preserving normal whitespace.
        output = "".join(
            char
            for char in output
            if char in "\n\r\t" or char.isprintable()
        )

        return output.strip()

    @staticmethod
    def _extract_version_line(output: str) -> str:
        """
        Extract the most useful version line.

        Prefer lines explicitly containing version information.
        This avoids returning ASCII banners or decorative headers.
        """
        lines = [
            line.strip()
            for line in output.splitlines()
            if line.strip()
        ]

        if not lines:
            return "version_unknown"

        for line in lines:
            normalized = line.strip()

            # Ignore decorative banner separators.
            if not re.search(r"[A-Za-z0-9]", normalized):
                continue

            if re.search(r"\bversion\b", normalized, re.IGNORECASE):
                return normalized[:200]

        for line in lines:
            if re.search(r"[A-Za-z0-9]", line):
                return line[:200]

        return "version_unknown"

    def check_cli_tool(
        self,
        name: str,
        required: bool,
        version_args: list[str] | None = None,
    ) -> ToolStatus:
        binary = shutil.which(name)

        if not binary:
            return ToolStatus(
                name=name,
                kind="cli",
                required=required,
                available=False,
                path_or_module="",
                version="not_installed",
            )

        version = "version_check_failed"
        verified = False

        try:
            proc = subprocess.run(
                [
                    binary,
                    *(version_args or ["--version"]),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                errors="replace",
            )

            raw_output = "\n".join(
                part
                for part in (
                    proc.stdout,
                    proc.stderr,
                )
                if part
            )

            output = self._normalize_output(raw_output)

            if proc.returncode == 0 and output:
                version = self._extract_version_line(output)

                markers = self.IDENTITY_MARKERS.get(name, ())

                if markers and not any(
                    marker.casefold() in output.casefold()
                    for marker in markers
                ):
                    version = f"identity_mismatch: {version}"
                else:
                    verified = True

            else:
                version = (
                    f"version_check_failed_exit_{proc.returncode}"
                )

        except subprocess.TimeoutExpired:
            version = "version_check_timeout"

        except OSError as exc:
            version = (
                f"version_check_error:{type(exc).__name__}"
            )

        return ToolStatus(
            name=name,
            kind="cli",
            required=required,
            available=verified,
            path_or_module=binary,
            version=version,
        )

    def check_python_module(
        self,
        module_name: str,
        required: bool,
    ) -> ToolStatus:
        try:
            spec = importlib.util.find_spec(module_name)

        except (ImportError, ValueError, ModuleNotFoundError):
            spec = None

        if spec is None:
            return ToolStatus(
                name=module_name,
                kind="python",
                required=required,
                available=False,
                path_or_module="",
                version="not_installed",
            )

        package = self.MODULES.get(
            module_name,
            module_name,
        )

        try:
            version = importlib.metadata.version(package)

        except importlib.metadata.PackageNotFoundError:
            version = "available (version unknown)"

        return ToolStatus(
            name=module_name,
            kind="python",
            required=required,
            available=True,
            path_or_module=spec.origin or "built-in",
            version=version,
        )

    def check_browser_runtime(
        self,
        required: bool,
    ) -> ToolStatus:
        """Verify that Playwright can launch its installed Chromium binary."""
        try:
            from playwright.sync_api import sync_playwright

        except Exception:
            return ToolStatus(
                name="chromium",
                kind="browser",
                required=required,
                available=False,
                path_or_module="",
                version="playwright_not_installed",
            )

        browser = None
        executable = ""
        version = "launch_failed"

        try:
            with sync_playwright() as playwright:
                executable = str(
                    playwright.chromium.executable_path
                )

                if (
                    not executable
                    or not Path(executable).is_file()
                ):
                    return ToolStatus(
                        name="chromium",
                        kind="browser",
                        required=required,
                        available=False,
                        path_or_module=executable,
                        version="browser_binary_not_installed",
                    )

                browser = playwright.chromium.launch(
                    headless=True
                )

                version = str(
                    browser.version or "version_unknown"
                )

                browser.close()
                browser = None

            return ToolStatus(
                name="chromium",
                kind="browser",
                required=required,
                available=True,
                path_or_module=executable,
                version=version,
            )

        except Exception as exc:
            return ToolStatus(
                name="chromium",
                kind="browser",
                required=required,
                available=False,
                path_or_module=executable,
                version=f"launch_failed:{type(exc).__name__}",
            )

        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass

    def inspect_all(
        self,
        profile: str = "core-only",
    ) -> dict[str, Any]:
        if profile not in self.PROFILES:
            raise ValueError(
                f"Unknown dependency profile {profile!r}; "
                f"choose from {sorted(self.PROFILES)}"
            )

        required_modules = self.PROFILES[profile]["modules"]
        required_cli = self.PROFILES[profile]["cli"]

        results: list[ToolStatus] = []

        # Core CLI dependencies.
        for name, args in self.CLI_COMMANDS.items():
            results.append(
                self.check_cli_tool(
                    name=name,
                    required=name in required_cli,
                    version_args=args,
                )
            )

        # Optional CLI integrations.
        # testssl.sh is the canonical executable name.
        for name, args in self.OPTIONAL_CLI_COMMANDS.items():
            results.append(
                self.check_cli_tool(
                    name=name,
                    required=name in required_cli,
                    version_args=args,
                )
            )

        # Python module dependencies.
        for name in self.MODULES:
            results.append(
                self.check_python_module(
                    module_name=name,
                    required=name in required_modules,
                )
            )

        # Browser runtime.
        if profile in {"browser-enabled", "full-scanner"}:
            results.append(
                self.check_browser_runtime(required=True)
            )

        missing_required = [
            result.name
            for result in results
            if result.required and not result.available
        ]

        missing_optional = [
            result.name
            for result in results
            if not result.required and not result.available
        ]

        return {
            "profile": profile,
            "ready": not missing_required,
            "missing_required": missing_required,
            "missing_optional": missing_optional,
            "settings_valid": True,
            "tools": [
                asdict(result)
                for result in results
            ],
        }
