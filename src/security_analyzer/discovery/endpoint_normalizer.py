from __future__ import annotations

import hashlib
import re
from urllib.parse import (
    parse_qsl,
    quote,
    unquote,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

from security_analyzer.core.scope_engine import ScopeEngine
from security_analyzer.models.endpoint import EndpointRecord


# Explicit names prevent harmless parameters such as "monkey" from being
# incorrectly redacted by broad substring matching.
SENSITIVE_PARAM_NAMES = {
    "token",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "secret",
    "clientsecret",
    "password",
    "passwd",
    "pwd",
    "apikey",
    "api_key",
    "authorization",
    "auth",
    "jwt",
    "session",
    "sessionid",
    "sid",
    "code",
    "email",
    "e_mail",
    "mail",
    "phone",
    "mobile",
    "msisdn",
    "tel",
    "telephone",
    "address",
    "street",
    "zipcode",
    "postcode",
    "postalcode",
    "dob",
    "birthdate",
    "ssn",
    "first_name",
    "last_name",
    "full_name",
    "userid",
    "user_id",
    "uid",
    "accountid",
    "account_id",
    "customerid",
    "customer_id",
    "memberid",
    "member_id",
    "profileid",
    "profile_id",
}

SENSITIVE_SUFFIXES = (
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "sessionid",
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9\-\s().]{6,}[0-9]$")
_JWT_RE = re.compile(
    r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$"
)

_METHOD_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$")
_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")

MAX_URL_LENGTH = 8192
MAX_QUERY_FIELDS = 256
MAX_PARAM_NAME_LENGTH = 256
MAX_SAMPLE_VALUE_LENGTH = 120


def _normalized_param_name(name: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", name.strip().lower())


def _is_sensitive_param(name: str, value: str) -> bool:
    normalized = _normalized_param_name(name)

    if (
        normalized in SENSITIVE_PARAM_NAMES
        or normalized.endswith(SENSITIVE_SUFFIXES)
    ):
        return True

    candidate = value.strip()

    return bool(
        candidate
        and (
            _EMAIL_RE.fullmatch(candidate)
            or _PHONE_RE.fullmatch(candidate)
            or _JWT_RE.fullmatch(candidate)
        )
    )


def _redact_path_segments(path: str) -> str:
    """Remove obvious personal identifiers and bearer tokens in path segments."""

    redacted_segments: list[str] = []

    for segment in path.split("/"):
        decoded = unquote(segment)

        if (
            _EMAIL_RE.fullmatch(decoded)
            or _PHONE_RE.fullmatch(decoded)
            or _JWT_RE.fullmatch(decoded)
        ):
            redacted_segments.append(
                quote("[REDACTED]", safe="")
            )
        else:
            redacted_segments.append(segment)

    return "/".join(redacted_segments)


def _safe_method(method: str) -> str:
    candidate = str(method or "GET").strip().upper()

    if not _METHOD_RE.fullmatch(candidate):
        raise ValueError(
            "HTTP method must be a valid token of at most 32 characters"
        )

    return candidate


def normalize_endpoint(
    raw_url: str,
    *,
    scope_engine: ScopeEngine,
    method: str = "GET",
    source: str = "unknown",
    auth_context: str = "anonymous",
    status_code: int | None = None,
    content_type: str = "",
    request_content_type: str = "",
    request_headers: dict[str, str] | None = None,
    request_body_schema: dict[str, object] | None = None,
    title: str = "",
    check_dns: bool = False,
) -> EndpointRecord | None:
    """
    Create a deterministic, scope-checked endpoint record.

    The function does not persist raw query values when they appear sensitive.
    Out-of-scope or malformed URLs return None.
    """

    if not isinstance(raw_url, str):
        return None

    candidate = raw_url.strip()

    if (
        not candidate
        or len(candidate) > MAX_URL_LENGTH
        or _CONTROL_RE.search(candidate)
    ):
        return None

    try:
        normalized_method = _safe_method(method)

        decision = scope_engine.evaluate_url(
            candidate,
            check_dns=check_dns,
        )

        if not decision.allowed:
            return None

        parsed = urlsplit(decision.normalized_url)

        # Accessing .port can raise for malformed authorities.
        port = parsed.port or (
            443 if parsed.scheme.lower() == "https" else 80
        )

    except (TypeError, ValueError):
        return None

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")

    if not host:
        return None

    try:
        safe_status = (
            int(status_code)
            if status_code is not None
            else None
        )
    except (TypeError, ValueError):
        safe_status = None

    if safe_status is not None and not 100 <= safe_status <= 599:
        safe_status = None

    path = parsed.path or "/"

    if len(path) > 1:
        path = path.rstrip("/") or "/"

    path = _redact_path_segments(path)

    try:
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=MAX_QUERY_FIELDS,
        )
    except ValueError:
        return None

    names = sorted(
        {
            name[:MAX_PARAM_NAME_LENGTH]
            for name, _ in pairs
            if name
        }
    )

    samples: dict[str, str] = {}
    safe_pairs: list[tuple[str, str]] = []

    for name, value in pairs:
        safe_name = name[:MAX_PARAM_NAME_LENGTH]

        redacted = _is_sensitive_param(
            safe_name,
            value,
        )

        safe_value = (
            "[REDACTED]"
            if redacted
            else value[:MAX_SAMPLE_VALUE_LENGTH]
        )

        samples[safe_name] = safe_value
        safe_pairs.append((safe_name, safe_value))

    netloc_host = (
        f"[{host}]"
        if ":" in host
        else host
    )

    if (
        (scheme == "http" and port != 80)
        or (scheme == "https" and port != 443)
    ):
        netloc_host += f":{port}"

    safe_url = urlunsplit(
        (
            scheme,
            netloc_host,
            path,
            urlencode(safe_pairs),
            "",
        )
    )

    # Query values intentionally do not participate in identity.
    # Different discovery sources observing different values for the
    # same operation must merge into one endpoint record.
    identity_material = "|".join(
        (
            normalized_method,
            scheme,
            host,
            str(port),
            path,
            ",".join(names),
        )
    )

    endpoint_id = hashlib.sha256(
        identity_material.encode("utf-8")
    ).hexdigest()[:20]

    return EndpointRecord(
        endpoint_id=endpoint_id,
        url=safe_url,
        canonical_url=safe_url,
        method=normalized_method,
        scheme=scheme,
        hostname=host,
        port=port,
        path=path,
        query_param_names=names,
        sample_query_params=samples,
        content_type=str(content_type or "")[:256],
        request_content_type=str(request_content_type or "")[:128],
        request_headers={
            str(key).lower(): str(value)[:256]
            for key, value in (request_headers or {}).items()
            if str(key).lower() in {"accept", "content-type", "accept-language", "x-requested-with"}
        },
        request_body_schema=dict(request_body_schema or {}),
        title=str(title or "")[:200],
        status_codes=(
            [safe_status]
            if safe_status is not None
            else []
        ),
        discovery_sources=[
            str(source or "unknown")[:128]
        ],
        auth_contexts=[
            str(auth_context or "anonymous")[:128]
        ],
        authenticated=(
            str(auth_context or "anonymous") != "anonymous"
        ),
        # None means discovery found the URL but no probe has tested it yet.
        reachable=True if safe_status is not None else None,
        scope_status="in_scope",
    )


class EndpointNormalizer:
    """Shared scope-aware normalization facade for all pipeline stages."""

    def __init__(
        self,
        scope_engine: ScopeEngine,
        coverage=None,
        *,
        check_dns: bool = False,
    ) -> None:
        self.scope_engine = scope_engine
        self.coverage = coverage
        self.check_dns = check_dns

    def normalize(
        self,
        raw_url: str,
        *,
        base_url: str | None = None,
        method: str = "GET",
        source: str = "unknown",
        stage_id: str = "endpoint_normalizer",
        status_code: int | None = None,
        content_type: str = "",
        request_content_type: str = "",
        request_headers: dict[str, str] | None = None,
        request_body_schema: dict[str, object] | None = None,
        title: str = "",
        reachable: bool | None = None,
        evidence_ref: str = "",
        auth_context: str = "anonymous",
        tags: list[str] | None = None,
        check_dns: bool | None = None,
    ) -> EndpointRecord | None:

        check_dns = self.check_dns if check_dns is None else check_dns

        try:
            if not isinstance(raw_url, str):
                return None

            candidate = (
                urljoin(base_url, raw_url)
                if base_url
                else raw_url
            )

        except (TypeError, ValueError):
            return None

        record = normalize_endpoint(
            candidate,
            scope_engine=self.scope_engine,
            method=method,
            source=source,
            auth_context=auth_context,
            status_code=status_code,
            content_type=content_type,
            request_content_type=request_content_type,
            request_headers=request_headers,
            request_body_schema=request_body_schema,
            title=title,
            check_dns=check_dns,
        )

        if record is None:
            if (
                self.coverage is not None
                and isinstance(candidate, str)
                and candidate
            ):
                decision = self.scope_engine.evaluate_url(
                    candidate,
                    check_dns=check_dns,
                )

                if not decision.allowed:
                    self.coverage.record_out_of_scope(
                        stage_id,
                        candidate[:MAX_URL_LENGTH],
                        decision.reason,
                    )

            return None

        if reachable is not None:
            record.reachable = bool(reachable)

        if evidence_ref:
            record.evidence_refs.append(
                str(evidence_ref)[:512]
            )

        if tags:
            record.tags.extend(
                tag
                for tag in tags
                if (
                    isinstance(tag, str)
                    and tag
                    and tag not in record.tags
                )
            )

        return record
