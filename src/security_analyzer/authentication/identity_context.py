from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
import yaml

from security_analyzer.core.coverage_tracker import CoverageTracker
from security_analyzer.core.exceptions import ConfigurationError
from security_analyzer.core.scope_engine import ScopeEngine
from security_analyzer.core.resource_governor import ResourceGovernor
from security_analyzer.utils.http_client import ScopedHttpClient

_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")


class AuthMethod(str, Enum):
    ANONYMOUS = "anonymous"
    API_LOGIN = "api_login"
    BEARER_TOKEN = "bearer_token"
    COOKIE_SESSION = "cookie_session"
    STORAGE_STATE = "storage_state"

    @classmethod
    def normalize(cls, value: Any) -> "AuthMethod":
        raw = str(value.value if isinstance(value, cls) else value).strip().lower()
        aliases = {"none": cls.ANONYMOUS, "anonymous": cls.ANONYMOUS}
        try:
            return aliases.get(raw) or cls(raw)
        except ValueError as exc:
            raise ConfigurationError(f"Unsupported auth_method: {raw!r}") from exc


def _expand_env_vars(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, list):
        return [_expand_env_vars(item) for item in value]
    if isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}
    return value


@dataclass
class IdentityProfile:
    identity_id: str
    role: str = "anonymous"
    auth_method: AuthMethod | str = AuthMethod.ANONYMOUS
    login_url: str = ""
    whoami_url: str = ""
    refresh_url: str = ""
    logout_url: str = ""
    credentials: dict[str, str] = field(default_factory=dict)
    token: str = ""
    refresh_token: str = ""
    token_json_path: str = "access_token"
    refresh_token_json_path: str = "refresh_token"
    header_name: str = "Authorization"
    header_prefix: str = "Bearer"
    cookies: dict[str, str] = field(default_factory=dict)
    extra_headers: dict[str, str] = field(default_factory=dict)
    storage_state_file: str = ""
    session_storage: dict[str, dict[str, str]] = field(default_factory=dict)
    browser_auth_origins: list[str] = field(default_factory=list)
    owned_resource_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.auth_method = AuthMethod.normalize(self.auth_method)


class IdentityContext:
    """Isolated authentication state for one actor; never share across identities."""

    def __init__(self, profile: IdentityProfile | None = None, **kwargs: Any) -> None:
        if profile is not None:
            self.profile = profile
            self.identity_id = profile.identity_id
            self.role = profile.role
            self.auth_method = AuthMethod.normalize(profile.auth_method)
            self.headers = dict(profile.extra_headers)
            self.access_token = profile.token
            self.refresh_token = profile.refresh_token
            self.cookies: list[dict[str, Any]] = []
            self.session_storage_by_origin = copy.deepcopy(profile.session_storage)
        else:
            self.profile = IdentityProfile(
                identity_id=str(kwargs.pop("identity_id")),
                role=str(kwargs.pop("role", "anonymous")),
                auth_method=kwargs.pop("auth_method", AuthMethod.ANONYMOUS),
                session_storage=copy.deepcopy(kwargs.get("session_storage_by_origin", {})),
            )
            self.identity_id = self.profile.identity_id
            self.role = self.profile.role
            self.auth_method = self.profile.auth_method
            self.headers = {}
            self.access_token = ""
            self.refresh_token = ""
            self.cookies = []
            self.session_storage_by_origin = copy.deepcopy(kwargs.get("session_storage_by_origin", {}))
        self.authenticated = bool(kwargs.get("authenticated", self.auth_method == AuthMethod.ANONYMOUS))
        self.session_valid = bool(kwargs.get("session_valid", self.authenticated))
        self.status = "anonymous" if self.auth_method == AuthMethod.ANONYMOUS else "uninitialized"
        self.notes: list[str] = list(kwargs.get("notes", []))
        self.local_storage_by_origin: dict[str, dict[str, str]] = {}
        self.storage_state_path: Path | None = None
        self.session_storage_path: Path | None = None
        self.resource_governor: ResourceGovernor | None = kwargs.get("resource_governor")
        self.expired_detected = False
        self.last_checked_at = ""
        self.refresh_count = 0
        self.last_error = ""
        if profile is not None:
            for name, value in profile.cookies.items():
                if value:
                    self.cookies.append({"name": name, "value": value, "domain": "", "path": "/", "secure": False, "httpOnly": False, "sameSite": "Lax"})
            if self.access_token and profile.header_name:
                prefix = f"{profile.header_prefix} " if profile.header_prefix else ""
                self.headers[profile.header_name] = f"{prefix}{self.access_token}".strip()

    def create_http_client(self, scope_engine: ScopeEngine, coverage: CoverageTracker | None = None, *, connect_timeout: float = 10.0, read_timeout: float = 20.0, max_redirects: int = 5, verify_tls: bool = True, check_dns: bool = True, user_agent: str = "SecurityAnalyzer/0.1.0", governor: ResourceGovernor | None = None) -> ScopedHttpClient:
        session = requests.Session()
        session.headers.update(self.headers)
        for cookie in self.cookies:
            session.cookies.set(
                cookie.get("name", ""), cookie.get("value", ""),
                domain=cookie.get("domain") or None, path=cookie.get("path", "/"),
                secure=bool(cookie.get("secure", False)),
            )
        return ScopedHttpClient(scope_engine, coverage, connect_timeout=connect_timeout, read_timeout=read_timeout, max_redirects=max_redirects, verify_tls=verify_tls, check_dns=check_dns, user_agent=user_agent, session=session, governor=governor or self.resource_governor)

    def to_playwright_storage_state(self, default_origin: str = "") -> dict[str, Any]:
        parsed = urlsplit(default_origin)
        host = (parsed.hostname or "").lower()
        secure_default = parsed.scheme.lower() == "https"
        cookies = []
        for c in self.cookies:
            cookies.append({
                "name": str(c.get("name", "")), "value": str(c.get("value", "")),
                "domain": str(c.get("domain") or host), "path": str(c.get("path") or "/"),
                "expires": float(c.get("expires", -1)), "httpOnly": bool(c.get("httpOnly", False)),
                "secure": bool(c.get("secure", secure_default)), "sameSite": str(c.get("sameSite") or "Lax"),
            })
        origins = [{"origin": origin, "localStorage": [{"name": k, "value": str(v)} for k, v in values.items()]}
                   for origin, values in self.local_storage_by_origin.items()]
        return {"cookies": cookies, "origins": origins}

    def redacted_summary(self) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id, "role": self.role,
            "auth_method": self.auth_method.value, "authenticated": self.authenticated,
            "session_valid": self.session_valid, "status": self.status,
            "header_names": sorted(self.headers),
            "cookie_names": sorted({str(c.get("name", "")) for c in self.cookies}),
            "has_access_token": bool(self.access_token), "has_refresh_token": bool(self.refresh_token),
            "refresh_count": self.refresh_count, "last_error": self.last_error,
            "notes": list(self.notes),
        }


def load_auth_profiles(auth_profiles_path: Path | None) -> tuple[dict[str, IdentityProfile], bool]:
    profiles = {"anonymous": IdentityProfile(identity_id="anonymous", role="anonymous", auth_method=AuthMethod.ANONYMOUS)}
    if auth_profiles_path is None or not auth_profiles_path.exists():
        return profiles, False
    try:
        raw = yaml.safe_load(auth_profiles_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"Invalid auth profiles YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("Auth profiles file must define a YAML mapping")
    expanded = _expand_env_vars(raw)
    identities = expanded.get("identities") or {}
    if not isinstance(identities, dict):
        raise ConfigurationError("identities in auth_profiles must be a mapping")
    for ident_id, spec in identities.items():
        if not isinstance(spec, dict) or str(ident_id) == "anonymous":
            raise ConfigurationError(f"Invalid identity profile for {ident_id!r}")
        identity_id = str(ident_id)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", identity_id):
            raise ConfigurationError(
                f"Invalid identity ID {identity_id!r}; use 1-64 letters, digits, dots, underscores or hyphens"
            )
        raw_browser_origins = spec.get("browser_auth_origins") or []
        if not isinstance(raw_browser_origins, list):
            raise ConfigurationError(
                f"browser_auth_origins for identity {identity_id!r} must be a YAML list"
            )
        raw_session_storage = spec.get("session_storage") or {}
        if not isinstance(raw_session_storage, dict):
            raise ConfigurationError(
                f"session_storage for identity {identity_id!r} must be a YAML mapping"
            )
        try:
            profiles[identity_id] = IdentityProfile(
                identity_id=str(ident_id), role=str(spec.get("role", "standard_user")),
                auth_method=spec.get("auth_method", AuthMethod.BEARER_TOKEN),
                login_url=str(spec.get("login_url", "")), whoami_url=str(spec.get("whoami_url", "")),
                refresh_url=str(spec.get("refresh_url", "")), logout_url=str(spec.get("logout_url", "")),
                credentials={str(k): str(v) for k, v in (spec.get("credentials") or {}).items()},
                token=str(spec.get("token", "")), refresh_token=str(spec.get("refresh_token", "")),
                token_json_path=str(spec.get("token_json_path", "access_token")),
                refresh_token_json_path=str(spec.get("refresh_token_json_path", "refresh_token")),
                header_name=str(spec.get("header_name", "Authorization")),
                header_prefix=str(spec.get("header_prefix", "Bearer")),
                cookies={str(k): str(v) for k, v in (spec.get("cookies") or {}).items()},
                extra_headers={str(k): str(v) for k, v in (spec.get("extra_headers") or {}).items()},
                storage_state_file=str(spec.get("storage_state_file", "")),
                session_storage=dict(raw_session_storage),
                browser_auth_origins=[
                    str(x).strip()
                    for x in raw_browser_origins
                    if str(x).strip()
                ],
                owned_resource_ids=[str(x) for x in (spec.get("owned_resource_ids") or [])],
            )
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"Invalid identity profile {ident_id!r}: {exc}") from exc
    return profiles, bool(expanded.get("verify_logout_invalidation", False))


# Backwards-compatible loader name used by earlier stage code.
def load_identity_profiles(auth_profiles_path: Path | None) -> tuple[bool, list[IdentityProfile]]:
    profiles, verify_logout = load_auth_profiles(auth_profiles_path)
    return verify_logout, list(profiles.values())
