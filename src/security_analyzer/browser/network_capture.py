from __future__ import annotations

import re
import json
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}

SENSITIVE_PARAM_RE = re.compile(
    r"(?i)(token|secret|password|passwd|pwd|api[-_]?key|auth|jwt|session|sid|cookie|code|otp|pin)"
)


def _is_sensitive_header_name(name: str) -> bool:
    normalized = name.strip().lower().replace("_", "-")
    sensitive_tokens = (
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "api-key", "apikey", "auth-token", "x-auth", "access-token", "refresh-token",
        "session", "secret", "password", "passwd", "csrf", "xsrf", "jwt", "otp",
    )
    return normalized in SENSITIVE_HEADER_NAMES or any(
        token in normalized for token in sensitive_tokens
    )


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    clean: dict[str, str] = {}
    for key, value in headers.items():
        if _is_sensitive_header_name(key):
            clean[key] = "[REDACTED]"
        else:
            clean[key] = str(value)[:256]
    return clean


def redact_url_query(url: str) -> tuple[str, list[str]]:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    param_names = sorted({k for k, _ in pairs if k})
    if not pairs:
        return url, []

    safe_parts: list[tuple[str, str]] = []
    for k, v in pairs:
        safe_val = "[REDACTED]" if SENSITIVE_PARAM_RE.search(k) else v[:64]
        safe_parts.append((k, safe_val))
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    return f"{base}?{urlencode(safe_parts)}", param_names


@dataclass
class CapturedExchange:
    exchange_id: str
    method: str
    url: str
    sanitized_url: str
    resource_type: str
    query_param_names: list[str] = field(default_factory=list)
    request_headers: dict[str, str] = field(default_factory=dict)
    has_request_body: bool = False
    request_content_type: str = ""
    request_body_schema: dict[str, Any] = field(default_factory=dict)
    status_code: int | None = None
    response_content_type: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    is_api_candidate: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _body_schema(raw_body: str | None, content_type: str) -> dict[str, Any]:
    """Return field names and primitive types only; never retain request values."""
    if not raw_body:
        return {}
    if len(raw_body) > 16_384:
        return {"format": "omitted", "reason": "body_over_limit"}

    def shape(value: Any, depth: int = 0) -> Any:
        if depth >= 4:
            return "object"
        if isinstance(value, dict):
            return {str(key)[:128]: shape(item, depth + 1) for key, item in list(value.items())[:128]}
        if isinstance(value, list):
            return {"type": "array", "items": shape(value[0], depth + 1) if value else "unknown"}
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
            return "number"
        return "string"

    try:
        parsed = json.loads(raw_body)
        return {"format": "json", "schema": shape(parsed)}
    except (TypeError, ValueError):
        if "application/x-www-form-urlencoded" in (content_type or "").lower():
            names = sorted({key[:128] for key, _ in parse_qsl(raw_body, keep_blank_values=True) if key})
            return {"format": "form", "fields": names[:128]}
        return {"format": "opaque", "present": True}


class NetworkCapture:
    """Correlates Playwright request and response events without duplicate entries."""

    API_RESOURCE_TYPES = {"xhr", "fetch"}

    def __init__(self) -> None:
        self._by_request_key: dict[int, CapturedExchange] = {}
        self._ordered: list[CapturedExchange] = []
        self._counter = 0

    def attach(self, page: Any) -> None:
        page.on("request", self._on_request)
        page.on("response", self._on_response)

    @staticmethod
    def _request_key(request: Any) -> str | int:
        impl = getattr(request, "_impl_obj", None)
        guid = getattr(impl, "_guid", None)
        return str(guid) if guid is not None else id(request)

    def _on_request(self, request: Any) -> None:
        url = str(request.url)
        if not url.startswith(("http://", "https://")):
            return

        req_key = self._request_key(request)
        if req_key in self._by_request_key:
            return

        self._counter += 1
        sanitized_url, param_names = redact_url_query(url)
        raw_headers = dict(request.headers or {})
        res_type = str(request.resource_type or "").lower()
        req_ctype = raw_headers.get("content-type", "")
        path_lower = urlsplit(url).path.lower()

        is_api = (
            res_type in self.API_RESOURCE_TYPES
            or "/api/" in path_lower
            or path_lower.endswith(("/graphql", ".json"))
            or "application/json" in req_ctype.lower()
        )

        exchange = CapturedExchange(
            exchange_id=f"net_{self._counter:05d}",
            method=str(request.method or "GET").upper(),
            # Persist only the redacted URL; raw credentials must not enter crawl artifacts.
            url=sanitized_url,
            sanitized_url=sanitized_url,
            resource_type=res_type,
            query_param_names=param_names,
            request_headers=sanitize_headers(raw_headers),
            has_request_body=request.post_data is not None,
            request_content_type=req_ctype,
            request_body_schema=_body_schema(request.post_data, req_ctype),
            is_api_candidate=is_api,
        )
        self._by_request_key[req_key] = exchange
        self._ordered.append(exchange)

    def _on_response(self, response: Any) -> None:
        req = response.request
        req_key = self._request_key(req)
        exchange = self._by_request_key.get(req_key)
        if exchange is None:
            self._on_request(req)
            exchange = self._by_request_key.get(req_key)
        if exchange is None:
            return

        resp_headers = dict(response.headers or {})
        resp_ctype = resp_headers.get("content-type", "")
        exchange.status_code = int(response.status)
        exchange.response_content_type = resp_ctype
        exchange.response_headers = sanitize_headers(resp_headers)
        if "application/json" in resp_ctype.lower() or "graphql" in resp_ctype.lower():
            exchange.is_api_candidate = True

    def exchanges(self) -> list[CapturedExchange]:
        return list(self._ordered)
