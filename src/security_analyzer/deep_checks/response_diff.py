from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

VOLATILE_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
VOLATILE_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
SENSITIVE_QUERY_RE = re.compile(r"(?i)(token|secret|password|passwd|api[-_]?key|auth|jwt|session|cookie|code)")


def _redact_url(url: str) -> str:
    parsed = urlsplit(url)
    query = [
        (key, "[REDACTED]" if SENSITIVE_QUERY_RE.search(key) else value[:64])
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def _extract_json_shape(obj: Any, prefix: str = "", depth: int = 0) -> list[str]:
    if depth > 4:
        return [f"{prefix}:<max_depth>"] if prefix else []
    keys: list[str] = []
    if isinstance(obj, dict):
        for k in sorted(obj.keys()):
            child_prefix = f"{prefix}.{k}" if prefix else str(k)
            keys.append(child_prefix)
            keys.extend(_extract_json_shape(obj[k], child_prefix, depth + 1))
    elif isinstance(obj, list):
        list_prefix = f"{prefix}[]" if prefix else "[]"
        keys.append(list_prefix)
        if obj:
            keys.extend(_extract_json_shape(obj[0], list_prefix, depth + 1))
    return sorted(set(keys))


@dataclass(frozen=True)
class ResponseFingerprint:
    identity_id: str
    url: str
    method: str
    status_code: int
    content_type: str
    content_length: int
    redirect_location: str
    normalized_body_sha256: str
    json_keys: list[str] = field(default_factory=list)
    is_json: bool = False
    looks_like_login_page: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_response(
        cls,
        *,
        identity_id: str,
        url: str,
        method: str,
        response: requests.Response,
    ) -> "ResponseFingerprint":
        ctype = response.headers.get("Content-Type", "")
        raw_bytes = response.content or b""
        text_sample = response.text[:65536] if raw_bytes else ""

        json_keys: list[str] = []
        is_json = False
        try:
            parsed = response.json()
            is_json = True
            json_keys = _extract_json_shape(parsed)
        except Exception:
            is_json = False

        scrubbed = VOLATILE_TIMESTAMP_RE.sub("<TS>", text_sample)
        scrubbed = VOLATILE_UUID_RE.sub("<UUID>", scrubbed)
        scrubbed = re.sub(r"\s+", " ", scrubbed).strip()
        norm_hash = hashlib.sha256(scrubbed.encode("utf-8", errors="replace")).hexdigest()

        location = _redact_url(response.headers.get("Location", "").strip())
        lower_sample = text_sample[:4096].lower()
        login_page = (
            response.status_code in {301, 302, 303, 307, 308}
            and any(tok in location.lower() for tok in ("login", "signin", "auth"))
        ) or (
            "html" in ctype.lower()
            and ("type=\"password\"" in lower_sample or "type='password'" in lower_sample)
        )

        return cls(
            identity_id=identity_id,
            url=url,
            method=method.upper(),
            status_code=int(response.status_code),
            content_type=ctype,
            content_length=len(raw_bytes),
            redirect_location=location,
            normalized_body_sha256=norm_hash,
            json_keys=json_keys,
            is_json=is_json,
            looks_like_login_page=login_page,
        )


def json_shape_similarity(fp_a: ResponseFingerprint, fp_b: ResponseFingerprint) -> float:
    if not fp_a.json_keys and not fp_b.json_keys:
        return 1.0 if fp_a.normalized_body_sha256 == fp_b.normalized_body_sha256 else 0.0
    set_a = set(fp_a.json_keys)
    set_b = set(fp_b.json_keys)
    union = set_a | set_b
    if not union:
        return 0.0
    return round(len(set_a & set_b) / len(union), 3)


def is_substantive_success(fp: ResponseFingerprint) -> bool:
    if fp.status_code not in {200, 201, 206}:
        return False
    if fp.looks_like_login_page:
        return False
    if fp.content_length == 0:
        return False
    return True
