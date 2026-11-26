
from __future__ import annotations

import importlib.metadata
import importlib.util
import shutil
import subprocess
from dataclasses import asdict, dataclass
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
    """

    # Existing core scanner dependencies.
    CLI_COMMANDS: dict[str, list[str]] = {
        "subfinder": ["-version"],
        "nuclei": ["-version"],
        "ffuf": ["-V"],
        "dig": ["-v"],
    }

    # Optional scanner integrations.
    # These are checked and reported but are not required by existing
    # profiles unless a future profile explicitly requires them.
    OPTIONAL_CLI_COMMANDS: dict[str, list[str]] = {
        "katana": ["-version"],
        "testssl.sh": ["--version"],
        "testssl": ["--version"],
    }

    IDENTITY_MARKERS: dict[str, tuple[str, ...]] = {
        "subfinder": ("subfinder", "projectdiscovery"),
        "nuclei": ("nuclei", "projectdiscovery"),
        "ffuf": ("ffuf",),
        "dig": ("dig",),
        "katana": ("katana",),
        "testssl.sh": ("testssl",),
        "testssl": ("testssl",),
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

    def check_cli_tool(
        self,
        name: str,
        required: bool,
        version_args: list[str] | None = None,
    ) -> ToolStatus:
        binary = shutil.which(name)

        if not binary:
            return ToolStatus(
                name,
                "cli",
                required,
                False,
                "",
                "not_installed",
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
                timeout=5,
                check=False,
            )

            output = "\n".join(
                part
                for part in (
                    proc.stdout,
                    proc.stderr,
                )
                if part
            ).strip()

            lines = output.splitlines()

            if proc.returncode == 0 and lines:
                version = lines[0][:200]

                markers = self.IDENTITY_MARKERS.get(
                    name,
                    (),
                )

                if markers and not any(
                    marker in output.lower()
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

        except (ImportError, ValueError):
            spec = None

        if spec is None:
            return ToolStatus(
                module_name,
                "python",
                required,
                False,
                "",
                "not_installed",
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

    def check_browser_runtime(self, required: bool) -> ToolStatus:
        """Verify that Playwright can launch its installed Chromium binary."""
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return ToolStatus(
                "chromium", "browser", required, False, "", "playwright_not_installed"
            )

        browser = None
        executable = ""
        version = "launch_failed"
        try:
            from pathlib import Path

            with sync_playwright() as playwright:
                executable = str(playwright.chromium.executable_path)
                if not executable or not Path(executable).is_file():
                    return ToolStatus(
                        "chromium", "browser", required, False, executable, "browser_binary_not_installed"
                    )
                browser = playwright.chromium.launch(headless=True)
                version = str(browser.version or "version_unknown")
                browser.close()
                browser = None
            return ToolStatus("chromium", "browser", required, True, executable, version)
        except Exception as exc:
            return ToolStatus(
                "chromium", "browser", required, False, executable,
                f"launch_failed:{type(exc).__name__}",
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
                    name,
                    name in required_cli,
                    args,
                )
            )

        # Optional CLI integrations, including Katana.
        for name, args in self.OPTIONAL_CLI_COMMANDS.items():
            results.append(
                self.check_cli_tool(
                    name,
                    name in required_cli,
                    args,
                )
            )

        # Python module dependencies.
        for name in self.MODULES:
            results.append(
                self.check_python_module(
                    name,
                    name in required_modules,
                )
            )

        if profile in {"browser-enabled", "full-scanner"}:
            results.append(self.check_browser_runtime(required=True))

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
            "tools": [
                asdict(result)
                for result in results
            ],
        }
