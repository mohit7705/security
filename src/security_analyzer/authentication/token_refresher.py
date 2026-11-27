from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import requests

from security_analyzer.authentication.identity_context import IdentityContext, IdentityProfile
from security_analyzer.authentication.storage_state_store import StorageStateStore
from security_analyzer.core.coverage_tracker import CoverageTracker
from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.scope_engine import ScopeEngine
from security_analyzer.models.asset import make_asset_id
from security_analyzer.models.finding import FindingRecord, Severity, Verdict

_JWT_CANDIDATE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b")
_SENSITIVE_JWT_CLAIM_RE = re.compile(
    r"(?i)^(?:password|passwd|pwd|secret|client_secret|private_key|api_key|apikey|"
    r"ssn|social_security|credit_card|card_number|cvv|pin|refresh_token)$"
)


def _extract_json_path(data: Any, dotted_path: str) -> str:
    current = data
    for segment in dotted_path.split("."):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            return ""
    return str(current).strip() if current is not None else ""


def _cookie_http_only(cookie: Any) -> bool:
    """Case-insensitive HttpOnly detection for a cookiejar cookie."""
    return any(str(k).lower() == "httponly" for k in getattr(cookie, "_rest", {}))


def _cookie_same_site(cookie: Any) -> str:
    """Observed SameSite value, or "" when the server did not send one."""
    for key, value in getattr(cookie, "_rest", {}).items():
        if str(key).lower() == "samesite":
            normalized = str(value or "").strip().lower()
            return {"strict": "Strict", "lax": "Lax", "none": "None"}.get(normalized, "")
    return ""


def _b64url_decode_json(segment: str) -> dict[str, Any] | None:
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def decode_jwt_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    """Safely decode a JWT header, payload, and signature segment without executing cryptographic verification."""
    cleaned = (token or "").strip()
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()
    parts = cleaned.split(".")
    if len(parts) != 3:
        return None
    header = _b64url_decode_json(parts[0])
    payload = _b64url_decode_json(parts[1])
    if header is None or payload is None:
        return None
    return header, payload, parts[2]


def audit_jwt_token(
    token: str,
    *,
    identity_id: str = "anonymous",
    location: str = "",
    token_source: str = "authorization_header",
) -> list[dict[str, Any]]:
    """Audit a JWT for insecure algorithm, missing/expired exp, long lifetime, or sensitive payload claims."""
    decoded = decode_jwt_unverified(token)
    if decoded is None:
        return []

    header, payload, signature = decoded
    parsed_loc = urlsplit(location) if "://" in location else None
    host = (parsed_loc.hostname if parsed_loc and parsed_loc.hostname else "target").lower()
    asset_id = make_asset_id(host)
    endpoint_id = f"jwt_{identity_id}_{token_source}"
    now_ts = int(datetime.now(timezone.utc).timestamp())
    findings: list[dict[str, Any]] = []

    alg = str(header.get("alg") or "").strip()
    if alg.lower() == "none" or not signature.strip():
        findings.append(
            FindingRecord(
                title=f"Insecure JWT unsigned or 'none' algorithm ({token_source})",
                category="jwt_alg_none",
                severity=Severity.CRITICAL,
                verdict=Verdict.CONFIRMED,
                confidence=0.98,
                asset_id=asset_id,
                endpoint_id=endpoint_id,
                identity_id=identity_id,
                description=(
                    f"A JWT observed in {token_source} for identity {identity_id!r} specifies "
                    f"alg={alg!r} or lacks a cryptographic signature segment."
                ),
                remediation=(
                    "Reject 'none' and unsigned JWTs server-side, enforce an explicit asymmetric "
                    "algorithm allow-list (e.g. RS256/ES256), and verify signatures on every request."
                ),
                scanner_source="jwt_token_auditor",
                metadata={
                    "url": location or f"https://{host}/",
                    "token_source": token_source,
                    "alg": alg,
                },
            ).to_dict()
        )

    exp_raw = payload.get("exp")
    iat_raw = payload.get("iat")
    if exp_raw is None:
        findings.append(
            FindingRecord(
                title=f"JWT lacks expiration ('exp') claim ({token_source})",
                category="jwt_missing_expiration",
                severity=Severity.MEDIUM,
                verdict=Verdict.CONFIRMED,
                confidence=0.90,
                asset_id=asset_id,
                endpoint_id=endpoint_id,
                identity_id=identity_id,
                description=(
                    f"A JWT observed in {token_source} for identity {identity_id!r} omits the 'exp' "
                    "expiration claim, allowing indefinite replay if intercepted."
                ),
                remediation=(
                    "Include a short-lived 'exp' claim in all issued JWTs and enforce expiration validation."
                ),
                scanner_source="jwt_token_auditor",
                metadata={
                    "url": location or f"https://{host}/",
                    "token_source": token_source,
                    "alg": alg,
                },
            ).to_dict()
        )
    elif isinstance(exp_raw, (int, float, str)) and str(exp_raw).replace(".", "", 1).isdigit():
        exp_ts = int(float(exp_raw))
        if exp_ts < now_ts:
            findings.append(
                FindingRecord(
                    title=f"Expired JWT still present in active session ({token_source})",
                    category="jwt_expired_token_in_use",
                    severity=Severity.LOW,
                    verdict=Verdict.NEEDS_HUMAN_REVIEW,
                    confidence=0.85,
                    asset_id=asset_id,
                    endpoint_id=endpoint_id,
                    identity_id=identity_id,
                    description=(
                        f"A JWT in {token_source} for identity {identity_id!r} has an 'exp' timestamp "
                        f"({exp_ts}) earlier than current UTC time ({now_ts}). Verify whether the backend "
                        "still accepts expired tokens."
                    ),
                    remediation="Ensure backend token verification strictly rejects tokens where exp <= current_time.",
                    scanner_source="jwt_token_auditor",
                    metadata={
                        "url": location or f"https://{host}/",
                        "token_source": token_source,
                        "exp": exp_ts,
                    },
                ).to_dict()
            )
        elif (
            not token_source.startswith("refresh")  # long-lived refresh tokens are normal
            and isinstance(iat_raw, (int, float))
            and (exp_ts - int(iat_raw)) > 30 * 86400
        ):
            lifetime_days = round((exp_ts - int(iat_raw)) / 86400.0, 1)
            findings.append(
                FindingRecord(
                    title=f"Excessive JWT lifetime ({lifetime_days} days) in {token_source}",
                    category="jwt_excessive_lifetime",
                    severity=Severity.LOW,
                    verdict=Verdict.NEEDS_HUMAN_REVIEW,
                    confidence=0.80,
                    asset_id=asset_id,
                    endpoint_id=endpoint_id,
                    identity_id=identity_id,
                    description=(
                        f"A JWT in {token_source} for identity {identity_id!r} has a validity window of "
                        f"{lifetime_days} days, increasing replay impact upon token compromise."
                    ),
                    remediation="Reduce access token TTL (e.g., 15–60 minutes) and use rotating refresh tokens.",
                    scanner_source="jwt_token_auditor",
                    metadata={
                        "url": location or f"https://{host}/",
                        "token_source": token_source,
                        "lifetime_days": lifetime_days,
                    },
                ).to_dict()
            )

    sensitive_keys = sorted(
        {
            str(key)
            for key in payload.keys()
            if _SENSITIVE_JWT_CLAIM_RE.fullmatch(str(key))
        }
    )
    if sensitive_keys:
        findings.append(
            FindingRecord(
                title=f"Sensitive claims exposed in unencrypted JWT payload ({token_source})",
                category="jwt_sensitive_payload_claims",
                severity=Severity.LOW,
                verdict=Verdict.NEEDS_HUMAN_REVIEW,
                confidence=0.82,
                asset_id=asset_id,
                endpoint_id=endpoint_id,
                identity_id=identity_id,
                description=(
                    f"A Base64URL-encoded (unencrypted) JWT in {token_source} contains sensitive claim "
                    f"keys {sensitive_keys}. Any client or intermediary can decode JWT payloads."
                ),
                remediation="Remove secrets and sensitive credentials from JWT claims or encrypt payloads with JWE.",
                scanner_source="jwt_token_auditor",
                metadata={
                    "url": location or f"https://{host}/",
                    "token_source": token_source,
                    "sensitive_claim_keys": sensitive_keys,
                },
            ).to_dict()
        )

    return findings


def audit_identity_tokens(
    context: IdentityContext,
    *,
    target_url: str = "",
) -> list[dict[str, Any]]:
    """Inspect all tokens, headers, and cookies attached to an IdentityContext."""
    candidates: list[tuple[str, str]] = []
    if context.access_token:
        candidates.append(("access_token", context.access_token))
    if context.refresh_token:
        candidates.append(("refresh_token", context.refresh_token))
    for hdr_name, hdr_val in (context.headers or {}).items():
        for match in _JWT_CANDIDATE_RE.findall(str(hdr_val or "")):
            candidates.append((f"header:{hdr_name}", match))
    for cookie in context.cookies or []:
        c_name = str(cookie.get("name") or "cookie")
        c_val = str(cookie.get("value") or "")
        for match in _JWT_CANDIDATE_RE.findall(c_val):
            candidates.append((f"cookie:{c_name}", match))

    seen_tokens: set[str] = set()
    findings: list[dict[str, Any]] = []
    for source_label, raw_token in candidates:
        normalized = raw_token.strip()
        if normalized.lower().startswith("bearer "):
            normalized = normalized[7:].strip()
        if not normalized or normalized in seen_tokens:
            continue
        seen_tokens.add(normalized)
        findings.extend(
            audit_jwt_token(
                normalized,
                identity_id=context.identity_id,
                location=target_url,
                token_source=source_label,
            )
        )
    return findings


@dataclass(frozen=True)
class RefreshOutcome:
    attempted: bool
    refreshed: bool
    token_rotated: bool
    status_code: int | None
    reason: str


class TokenRefresher:
    """Performs scope-checked token/session refresh and detects token rotation."""

    def __init__(
        self,
        scope_engine: ScopeEngine,
        store: StorageStateStore,
        *,
        coverage: CoverageTracker | None = None,
    ) -> None:
        self.scope_engine = scope_engine
        self.store = store
        self.coverage = coverage

    def refresh(
        self,
        profile: IdentityProfile,
        context: IdentityContext,
        *,
        stage_id: str = "auth_session_lifecycle",
    ) -> RefreshOutcome:
        if not profile.refresh_url:
            return RefreshOutcome(False, False, False, None, "No refresh_url configured")

        if not context.refresh_token and not context.cookies:
            return RefreshOutcome(False, False, False, None, "No refresh_token or session cookie available")

        try:
            refresh_url = self.scope_engine.enforce_url(profile.refresh_url, check_dns=True)
        except ScopeViolationError as exc:
            return RefreshOutcome(True, False, False, None, type(exc).__name__)

        previous_token = context.access_token
        client = context.create_http_client(self.scope_engine, coverage=self.coverage)
        body = {"refresh_token": context.refresh_token} if context.refresh_token else {}

        try:
            resp = client.request("POST", refresh_url, stage_id=stage_id, json_body=body)
        except (ScopeViolationError, requests.RequestException) as exc:
            return RefreshOutcome(True, False, False, None, f"Refresh request failed: {type(exc).__name__}")

        if resp.status_code not in {200, 201, 204}:
            return RefreshOutcome(
                True,
                False,
                False,
                resp.status_code,
                f"Refresh endpoint returned HTTP {resp.status_code}",
            )

        new_access = ""
        new_refresh = ""
        try:
            payload = resp.json()
            new_access = _extract_json_path(payload, profile.token_json_path)
            new_refresh = _extract_json_path(payload, profile.refresh_token_json_path)
        except ValueError:
            payload = {}

        before_cookies = {
            (str(c.get("name", "")), str(c.get("domain", "")), str(c.get("path", "/"))): str(c.get("value", ""))
            for c in context.cookies
        }
        for cookie in client.session.cookies:
            self._upsert_cookie(
                context,
                {
                    "name": cookie.name,
                    "value": cookie.value or "",
                    "domain": cookie.domain or "",
                    "path": cookie.path or "/",
                    "secure": bool(cookie.secure),
                    "httpOnly": _cookie_http_only(cookie),
                    "sameSite": _cookie_same_site(cookie),
                },
            )
        after_cookies = {
            (str(c.get("name", "")), str(c.get("domain", "")), str(c.get("path", "/"))): str(c.get("value", ""))
            for c in context.cookies
        }
        updated_cookies = before_cookies != after_cookies

        if new_access:
            context.access_token = new_access
            prefix = f"{profile.header_prefix} " if profile.header_prefix else ""
            context.headers[profile.header_name] = f"{prefix}{new_access}"
        if new_refresh:
            context.refresh_token = new_refresh

        if not new_access and not updated_cookies:
            return RefreshOutcome(
                True,
                False,
                False,
                resp.status_code,
                "Refresh response contained neither a new access token nor updated cookies",
            )

        context.refresh_count += 1
        context.expired_detected = False
        context.session_valid = True
        context.authenticated = True
        context.last_checked_at = datetime.now(timezone.utc).isoformat()
        context.storage_state_path = self.store.save_storage_state(
            context.identity_id,
            context.to_playwright_storage_state(refresh_url),
        )

        rotated = bool(new_access and new_access != previous_token) or updated_cookies
        return RefreshOutcome(
            True,
            True,
            rotated,
            resp.status_code,
            "Session refreshed successfully" + (" (token rotated)" if rotated else " (token unchanged)"),
        )

    @staticmethod
    def _upsert_cookie(context: IdentityContext, new_cookie: dict[str, Any]) -> None:
        for idx, existing in enumerate(context.cookies):
            if existing.get("name") == new_cookie["name"] and existing.get("domain") == new_cookie["domain"]:
                context.cookies[idx] = new_cookie
                return
        context.cookies.append(new_cookie)