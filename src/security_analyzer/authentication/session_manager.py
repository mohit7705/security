from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests

from security_analyzer.authentication.identity_context import (
    AuthMethod,
    IdentityContext,
    IdentityProfile,
)
from security_analyzer.authentication.session_storage_bridge import SessionStorageBridge
from security_analyzer.authentication.storage_state_store import StorageStateStore
from security_analyzer.authentication.token_refresher import TokenRefresher, _extract_json_path
from security_analyzer.core.coverage_tracker import CoverageTracker
from security_analyzer.core.exceptions import ConfigurationError, ScopeViolationError
from security_analyzer.core.scope_engine import ScopeEngine
from security_analyzer.core.resource_governor import ResourceGovernor


class SessionManager:
    """Establishes, validates, refreshes, and audits isolated identity sessions."""

    def __init__(
        self,
        scope_engine: ScopeEngine,
        store: StorageStateStore,
        *,
        coverage: CoverageTracker | None = None,
        default_target_url: str = "",
        resource_governor: ResourceGovernor | None = None,
    ) -> None:
        self.scope_engine = scope_engine
        self.store = store
        self.coverage = coverage
        self.default_target_url = default_target_url
        self.resource_governor = resource_governor
        self.session_storage_bridge = SessionStorageBridge(store)
        self.refresher = TokenRefresher(scope_engine, store, coverage=coverage)

    def establish_context(
        self,
        profile: IdentityProfile,
        *,
        stage_id: str = "auth_session_lifecycle",
    ) -> IdentityContext:
        ctx = IdentityContext(
            identity_id=profile.identity_id,
            role=profile.role,
            auth_method=profile.auth_method,
            session_storage_by_origin=dict(profile.session_storage),
            resource_governor=self.resource_governor,
        )
        # IdentityContext(profile=...) copies these, but this manager constructs
        # the context with explicit fields. Preserve the profile's custom headers.
        ctx.headers.update(
            {
                str(name): str(value)
                for name, value in profile.extra_headers.items()
                if str(name).strip()
            }
        )

        if profile.auth_method == AuthMethod.ANONYMOUS:
            ctx.authenticated = False
            ctx.session_valid = True
            return ctx

        default_host = (urlsplit(self.default_target_url).hostname or "").lower()
        is_https = self.default_target_url.lower().startswith("https://")

        if profile.auth_method == AuthMethod.BEARER_TOKEN:
            if not profile.token:
                raise ConfigurationError(f"Identity {profile.identity_id!r} requires a non-empty token")
            ctx.access_token = profile.token
            ctx.refresh_token = profile.refresh_token
            prefix = f"{profile.header_prefix} " if profile.header_prefix else ""
            ctx.headers[profile.header_name] = f"{prefix}{profile.token}"
            ctx.authenticated = True
            ctx.session_valid = True

        elif profile.auth_method == AuthMethod.COOKIE_SESSION:
            if not profile.cookies:
                raise ConfigurationError(f"Identity {profile.identity_id!r} requires at least one session cookie")
            for name, val in profile.cookies.items():
                ctx.cookies.append(
                    {
                        "name": name,
                        "value": val,
                        "domain": default_host,
                        "path": "/",
                        "secure": is_https,
                        "httpOnly": True,
                        "sameSite": "Lax",
                    }
                )
            ctx.authenticated = True
            ctx.session_valid = True

        elif profile.auth_method == AuthMethod.STORAGE_STATE:
            if not profile.storage_state_file:
                raise ConfigurationError(f"Identity {profile.identity_id!r} requires storage_state_file")
            loaded = self.store.load_storage_state(Path(profile.storage_state_file))
            ctx.cookies = loaded["cookies"]
            for origin_entry in loaded["origins"]:
                origin = str(origin_entry.get("origin", "")).strip()
                kv = {
                    str(item["name"]): str(item["value"])
                    for item in origin_entry.get("localStorage", [])
                    if "name" in item
                }
                if origin:
                    ctx.local_storage_by_origin[origin] = kv
            ctx.authenticated = True
            ctx.session_valid = True

        elif profile.auth_method == AuthMethod.API_LOGIN:
            self._perform_api_login(profile, ctx, stage_id=stage_id)

        # Persist isolated storage state & sessionStorage inside ./secrets/<scan_id>/ with 0600 permissions
        ctx.storage_state_path = self.store.save_storage_state(
            ctx.identity_id,
            ctx.to_playwright_storage_state(self.default_target_url),
        )
        if ctx.session_storage_by_origin:
            ctx.session_storage_path = self.session_storage_bridge.save_for_identity(
                ctx.identity_id,
                ctx.session_storage_by_origin,
            )

        return ctx

    def _perform_api_login(
        self,
        profile: IdentityProfile,
        ctx: IdentityContext,
        *,
        stage_id: str,
    ) -> None:
        if not profile.login_url:
            raise ConfigurationError(f"Identity {profile.identity_id!r} requires login_url for api_login")
        if not profile.credentials or not any(profile.credentials.values()):
            raise ConfigurationError(f"Identity {profile.identity_id!r} requires login credentials")
        login_url = self.scope_engine.enforce_url(profile.login_url, check_dns=True)
        client = ctx.create_http_client(self.scope_engine, coverage=self.coverage)

        try:
            resp = client.request("POST", login_url, stage_id=stage_id, json_body=profile.credentials)
        except (ScopeViolationError, requests.RequestException) as exc:
            ctx.authenticated = False
            ctx.session_valid = False
            ctx.notes.append(f"Login request failed: {type(exc).__name__}")
            return

        if resp.status_code not in {200, 201, 204}:
            ctx.authenticated = False
            ctx.session_valid = False
            ctx.notes.append(f"Login failed with HTTP {resp.status_code}")
            return

        try:
            payload = resp.json()
            access = _extract_json_path(payload, profile.token_json_path)
            refresh = _extract_json_path(payload, profile.refresh_token_json_path)
            if access:
                ctx.access_token = access
                prefix = f"{profile.header_prefix} " if profile.header_prefix else ""
                ctx.headers[profile.header_name] = f"{prefix}{access}"
            if refresh:
                ctx.refresh_token = refresh
        except ValueError:
            pass

        for cookie in client.session.cookies:
            ctx.cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value or "",
                    "domain": cookie.domain or (urlsplit(login_url).hostname or ""),
                    "path": cookie.path or "/",
                    "secure": bool(cookie.secure),
                    "httpOnly": bool(cookie.has_nonstandard_attr("HttpOnly")),
                    "sameSite": "Lax",
                }
            )

        ctx.authenticated = bool(ctx.access_token or ctx.cookies)
        ctx.session_valid = ctx.authenticated
        if not ctx.authenticated:
            ctx.notes.append("Login returned 2xx but yielded neither token nor session cookie")

    def validate_session(
        self,
        profile: IdentityProfile,
        ctx: IdentityContext,
        *,
        stage_id: str = "auth_session_lifecycle",
        auto_refresh: bool = True,
    ) -> dict[str, Any]:
        """Distinguish active session, expired session (401/login redirect), and authorization denial (403)."""
        if profile.auth_method == AuthMethod.ANONYMOUS or not profile.whoami_url:
            return {
                "identity_id": ctx.identity_id,
                "checked": False,
                "state": "not_configured" if profile.auth_method != AuthMethod.ANONYMOUS else "anonymous",
                "session_valid": ctx.session_valid,
            }

        whoami_url = self.scope_engine.enforce_url(profile.whoami_url, check_dns=True)
        client = ctx.create_http_client(self.scope_engine, coverage=self.coverage, max_redirects=0)

        try:
            resp = client.get(whoami_url, stage_id=stage_id)
        except (ScopeViolationError, requests.RequestException) as exc:
            ctx.session_valid = False
            return {
                "identity_id": ctx.identity_id,
                "checked": True,
                "state": "request_error",
                "error": type(exc).__name__,
                "session_valid": False,
            }

        ctx.last_checked_at = datetime.now(timezone.utc).isoformat()
        location = resp.headers.get("Location", "").lower()
        is_login_redirect = resp.status_code in {301, 302, 303, 307, 308} and any(
            k in location for k in ("login", "signin", "auth")
        )

        if resp.status_code == 401 or is_login_redirect:
            ctx.expired_detected = True
            ctx.session_valid = False
            refresh_info = None
            if auto_refresh and profile.refresh_url:
                outcome = self.refresher.refresh(profile, ctx, stage_id=stage_id)
                refresh_info = {
                    "attempted": outcome.attempted,
                    "refreshed": outcome.refreshed,
                    "token_rotated": outcome.token_rotated,
                    "reason": outcome.reason,
                }
            return {
                "identity_id": ctx.identity_id,
                "checked": True,
                "state": "expired_recovered" if (refresh_info and refresh_info["refreshed"]) else "expired",
                "status_code": resp.status_code,
                "session_valid": bool(ctx.session_valid),
                "refresh": refresh_info,
            }

        if resp.status_code == 403:
            # 403 indicates authenticated identity lacking permission on whoami_url, distinct from 401 expiry
            ctx.session_valid = True
            ctx.expired_detected = False
            return {
                "identity_id": ctx.identity_id,
                "checked": True,
                "state": "authenticated_forbidden",
                "status_code": 403,
                "session_valid": True,
            }

        if 200 <= resp.status_code < 300:
            ctx.session_valid = True
            ctx.expired_detected = False
            return {
                "identity_id": ctx.identity_id,
                "checked": True,
                "state": "active",
                "status_code": resp.status_code,
                "session_valid": True,
            }

        ctx.session_valid = False
        return {
            "identity_id": ctx.identity_id,
            "checked": True,
            "state": "unexpected_status",
            "status_code": resp.status_code,
            "session_valid": False,
        }

    def verify_logout_invalidation(
        self,
        profile: IdentityProfile,
        ctx: IdentityContext,
        *,
        stage_id: str = "auth_session_lifecycle",
    ) -> dict[str, Any]:
        """Optionally verify whether server invalidates session tokens/cookies upon logout."""
        if not profile.logout_url or not profile.whoami_url or not ctx.authenticated:
            return {"tested": False, "reason": "logout_url or whoami_url not configured"}

        logout_decision = self.scope_engine.evaluate_url(profile.logout_url, check_dns=True)
        whoami_decision = self.scope_engine.evaluate_url(profile.whoami_url, check_dns=True)
        if not logout_decision.allowed or not whoami_decision.allowed:
            reasons = []
            if not logout_decision.allowed:
                reasons.append(f"logout_url: {logout_decision.reason}")
            if not whoami_decision.allowed:
                reasons.append(f"whoami_url: {whoami_decision.reason}")
            reason = "; ".join(reasons)
            if self.coverage is not None:
                self.coverage.record_skipped_check(stage_id, "logout_invalidation", reason)
            return {"tested": False, "skipped": True, "reason": reason}

        logout_url = logout_decision.normalized_url
        whoami_url = whoami_decision.normalized_url
        client = ctx.create_http_client(self.scope_engine, coverage=self.coverage, max_redirects=0)

        try:
            logout_resp = client.request("POST", logout_url, stage_id=stage_id)
            post_logout_check = client.get(whoami_url, stage_id=stage_id)
        except (ScopeViolationError, requests.RequestException) as exc:
            return {"tested": True, "error": type(exc).__name__}

        invalidated = post_logout_check.status_code in {401, 302, 303}
        return {
            "tested": True,
            "logout_status": logout_resp.status_code,
            "post_logout_whoami_status": post_logout_check.status_code,
            "server_invalidated_session": invalidated,
        }
