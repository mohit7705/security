from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from security_analyzer.authentication.session_storage_bridge import SessionStorageBridge
from security_analyzer.core.coverage_tracker import CoverageTracker
from security_analyzer.core.egress import is_trusted_scope_proxy, policy_is_lab_only
from security_analyzer.core.resource_governor import ResourceGovernor, ResourceLimitExceeded
from security_analyzer.core.scope_engine import ScopeEngine
from security_analyzer.utils.redaction import scrub_text


def is_playwright_installed() -> bool:
    return importlib.util.find_spec("playwright") is not None


def _origin(url: str) -> str:
    parsed = urlsplit(str(url or "").strip())
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return ""
    host = parsed.hostname.lower().rstrip(".")
    rendered_host = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except ValueError:
        return ""
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    netloc = rendered_host if port in (None, default_port) else f"{rendered_host}:{port}"
    return f"{parsed.scheme.lower()}://{netloc}"


class ScopedBrowserManager:
    """Playwright context with scope enforcement and origin-bound identity credentials."""

    def __init__(
        self,
        scope_engine: ScopeEngine,
        *,
        coverage: CoverageTracker | None = None,
        stage_id: str = "browser_capture",
        headless: bool = True,
        har_path: Path | None = None,
        har_mode: str = "minimal",
        storage_state_path: Path | None = None,
        storage_state: dict[str, Any] | None = None,
        session_storage_by_origin: dict[str, dict[str, str]] | None = None,
        auth_headers: dict[str, str] | None = None,
        auth_origins: set[str] | list[str] | tuple[str, ...] | None = None,
        resource_governor: ResourceGovernor | None = None,
        viewport_width: int = 1366,
        viewport_height: int = 768,
        user_agent: str = "SecurityAnalyzer/0.1.0",
        lab_mode: bool = False,
        check_dns: bool = True,
    ) -> None:
        self.scope_engine = scope_engine
        self.coverage = coverage
        self.stage_id = stage_id
        self.headless = headless
        self.har_path = har_path
        self.har_mode = har_mode if har_mode in {"full", "minimal"} else "minimal"
        self.storage_state_path = storage_state_path
        self.storage_state = storage_state
        if storage_state is not None and (
            not isinstance(storage_state, dict)
            or not isinstance(storage_state.get("cookies", []), list)
            or not isinstance(storage_state.get("origins", []), list)
        ):
            raise ValueError("storage_state must contain cookies and origins arrays")
        self.session_storage_by_origin = session_storage_by_origin or {}
        forbidden_headers = {
            "host", "content-length", "cookie", "set-cookie",
            "proxy-authorization", "connection", "transfer-encoding",
        }
        self.auth_headers = {}
        for raw_name, raw_value in (auth_headers or {}).items():
            name = str(raw_name).strip()
            value = str(raw_value)
            if (
                not name
                or name.lower() in forbidden_headers
                or any(ch in name for ch in "\r\n:")
                or any(ch in value for ch in "\r\n")
            ):
                continue
            self.auth_headers[name] = value
        self.auth_origins = {
            normalized
            for raw in (auth_origins or [])
            if (normalized := _origin(str(raw)))
        }
        self.resource_governor = resource_governor
        self.viewport = {"width": viewport_width, "height": viewport_height}
        self.user_agent = user_agent
        self.check_dns = bool(check_dns)
        self.lab_mode = bool(lab_mode)

        self._pw_cm: Any = None
        self._playwright: Any = None
        self.browser: Any = None
        self.context: Any = None
        self.blocked_requests: list[dict[str, str]] = []
        self.budget_blocked_requests = 0

    def __enter__(self) -> "ScopedBrowserManager":
        if self.lab_mode and not policy_is_lab_only(self.scope_engine.policy):
            raise RuntimeError(
                "Browser lab mode requires a private-only scope with allow_private_ips enabled"
            )
        if self.storage_state_path is not None and not self.storage_state_path.is_file():
            raise FileNotFoundError(
                f"Browser storage state does not exist or is not a regular file: {self.storage_state_path}"
            )

        from playwright.sync_api import sync_playwright

        try:
            self._pw_cm = sync_playwright()
            self._playwright = self._pw_cm.__enter__()

            proxy_url = os.environ.get("SECURITY_ANALYZER_PROXY", "").strip()
            proxy_enforced = (
                os.environ.get("SECURITY_ANALYZER_EGRESS_ENFORCED") == "1"
                and is_trusted_scope_proxy(proxy_url)
            )
            if not proxy_enforced and not self.lab_mode:
                raise RuntimeError(
                    "An enforced SECURITY_ANALYZER_PROXY or validated browser lab mode is required"
                )

            launch_options: dict[str, Any] = {
                "headless": self.headless,
                "args": ["--disable-dev-shm-usage", "--no-first-run"],
            }
            if proxy_enforced:
                launch_options["proxy"] = {"server": proxy_url}
            self.browser = self._playwright.chromium.launch(**launch_options)

            context_kwargs: dict[str, Any] = {
                "ignore_https_errors": False,
                "viewport": self.viewport,
                "user_agent": self.user_agent,
                "service_workers": "block",
            }
            if self.storage_state is not None:
                context_kwargs["storage_state"] = self.storage_state
            elif self.storage_state_path is not None:
                context_kwargs["storage_state"] = str(self.storage_state_path)
            if self.har_path is not None:
                self.har_path.parent.mkdir(parents=True, exist_ok=True)
                context_kwargs["record_har_path"] = str(self.har_path)
                context_kwargs["record_har_mode"] = self.har_mode

            self.context = self.browser.new_context(**context_kwargs)
            if self.session_storage_by_origin:
                SessionStorageBridge.apply_to_browser_context(
                    self.context,
                    self.session_storage_by_origin,
                )
            self.context.route("**/*", self._intercept_route)
            return self
        except Exception as exc:
            try:
                self.__exit__(type(exc), exc, exc.__traceback__)
            except Exception:
                pass
            raise

    def _intercept_route(self, route: Any) -> None:
        request = route.request
        url = str(request.url)

        # Browser-internal resources never reach the network.
        if url.startswith(("data:", "blob:", "about:")):
            route.continue_()
            return

        decision = self.scope_engine.evaluate_url(
            url,
            check_dns=self.check_dns,
        )
        if not decision.allowed:
            self.blocked_requests.append(
                {
                    "url": CoverageTracker._safe_target(url),
                    "reason": decision.reason[:512],
                }
            )
            if self.coverage is not None:
                self.coverage.record_out_of_scope(
                    self.stage_id,
                    url[:2048],
                    decision.reason,
                )
            route.abort("blockedbyclient")
            return

        acquired_budget = False
        try:
            if self.resource_governor is not None:
                self.resource_governor.acquire_request(url)
                acquired_budget = True

            all_headers = getattr(request, "all_headers", None)
            try:
                original_headers = dict(all_headers()) if callable(all_headers) else dict(request.headers or {})
            except Exception:
                original_headers = dict(request.headers or {})
            request_headers = dict(original_headers)
            request_origin = _origin(url)

            # Strip configured identity headers from every non-authorized origin.
            # This also protects against an Authorization header copied onto a
            # cross-origin redirect by the browser.
            if self.auth_origins:
                if request_origin in self.auth_origins:
                    for name, value in self.auth_headers.items():
                        for existing in list(request_headers):
                            if existing.lower() == name.lower():
                                request_headers.pop(existing, None)
                        request_headers[name] = value
                else:
                    protected_names = {
                        name.lower() for name in self.auth_headers
                    }
                    protected_names.add("cookie")
                    for existing in list(request_headers):
                        if existing.lower() in protected_names:
                            request_headers.pop(existing, None)

            if request_headers != original_headers:
                route.continue_(headers=request_headers)
            else:
                route.continue_()

        except ResourceLimitExceeded as exc:
            self.budget_blocked_requests += 1
            self.blocked_requests.append(
                {
                    "url": CoverageTracker._safe_target(url),
                    "reason": f"resource_limit:{scrub_text(str(exc)[:300])}",
                }
            )
            if self.coverage is not None:
                self.coverage.record_skipped_check(
                    self.stage_id,
                    "browser_request_budget",
                    scrub_text(str(exc)[:300]),
                )
            route.abort("blockedbyclient")
        except Exception:
            # Never retry a failed route operation without knowing its state.
            try:
                route.abort("failed")
            except Exception:
                pass
            raise
        finally:
            if acquired_budget and self.resource_governor is not None:
                self.resource_governor.release_request()

    def new_page(self, timeout_ms: int = 15000) -> Any:
        if self.context is None:
            raise RuntimeError(
                "ScopedBrowserManager context is not initialized."
            )
        page = self.context.new_page()
        page.set_default_navigation_timeout(timeout_ms)
        page.set_default_timeout(timeout_ms)
        return page

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            if self.context is not None:
                self.context.close()
        finally:
            try:
                if self.browser is not None:
                    self.browser.close()
            finally:
                if self._pw_cm is not None:
                    self._pw_cm.__exit__(exc_type, exc_val, exc_tb)
