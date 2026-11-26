# src/security_analyzer/browser/har_recorder.py
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from security_analyzer.core.workspace import WorkspaceManager

_SENSITIVE_HEADER_TOKENS = (
    "authorization", "cookie", "set-cookie", "token", "secret", "api-key",
    "apikey", "session", "x-auth", "csrf", "xsrf", "password", "passwd", "jwt", "otp",
)
_SENSITIVE_PARAM_TOKENS = (
    "token", "secret", "password", "passwd", "pwd", "key", "auth", "jwt", "session", "sid",
    "email", "mail", "phone", "mobile", "tel", "address", "addr", "zip", "postal", "ssn",
    "user_id", "userid", "uid", "account_id", "customer_id", "member_id",
)
_PII_BODY_RE = re.compile(
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|\+?[0-9][0-9\-\s().]{7,}[0-9]|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"
)
_SECRET_BODY_RE = re.compile(
    r"(?i)(\b(?:authorization|cookie|set-cookie|access_token|refresh_token|token|api[_-]?key|secret|password|passwd|client_secret)\b\s*[:=]\s*)([^\s&,;]+)"
)


def _scrub_redirect_value(value: str) -> str:
    """Redact credentials and PII embedded in a redirect URL or nested value."""
    cleaned = _SECRET_BODY_RE.sub(r"\\1[REDACTED]", str(value))
    cleaned = re.sub(
        r"(?i)\\bBearer\\s+[A-Za-z0-9._~+/=-]{8,}",
        "[REDACTED_TOKEN]",
        cleaned,
    )
    return _PII_BODY_RE.sub("[REDACTED_PII]", cleaned)


def _scrub_url(raw_url: str) -> str:
    """Redact sensitive query values in absolute and relative redirect URLs."""
    try:
        parsed = urlsplit(str(raw_url))
        if not parsed.scheme and not parsed.netloc and not parsed.path and not parsed.query:
            return raw_url
        if parsed.scheme and not parsed.hostname:
            return "[INVALID_URL]"
        if parsed.hostname:
            host = parsed.hostname
            netloc = f"[{host}]" if ":" in host else host
            if parsed.port is not None:
                netloc += f":{parsed.port}"
        else:
            netloc = parsed.netloc
        safe_path = _scrub_redirect_value(parsed.path)
        redacted_q = urlencode(
            [
                (k, "[REDACTED]" if _is_sensitive_name(k) else _scrub_redirect_value(v))
                for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            ],
            safe="[]",
        )
        return urlunsplit((parsed.scheme, netloc, safe_path, redacted_q, ""))
    except ValueError:
        return "[INVALID_URL]"


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower().replace("-", "_")
    return any(token in lowered for token in _SENSITIVE_PARAM_TOKENS)


def _scrub_headers(headers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for item in headers:
        name = str(item.get("name", ""))
        lowered = name.lower()
        raw_value = str(item.get("value", ""))
        if any(tok in lowered for tok in _SENSITIVE_HEADER_TOKENS):
            safe_value = "[REDACTED]"
        elif lowered == "location":
            safe_value = _scrub_url(raw_value)
        else:
            safe_value = item.get("value", "")
        cleaned.append({"name": name, "value": safe_value})
    return cleaned


def _scrub_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            lowered = str(key).lower().replace("-", "_")
            if any(token in lowered for token in _SENSITIVE_PARAM_TOKENS):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = _scrub_json_value(item)
        return cleaned
    if isinstance(value, list):
        return [_scrub_json_value(item) for item in value]
    if isinstance(value, str):
        return _PII_BODY_RE.sub("[REDACTED_PII]", value)[:4096]
    return value


def _scrub_body_text(text: str, mime_type: str = "") -> str:
    if not text:
        return ""
    if "json" in mime_type.lower():
        try:
            return json.dumps(_scrub_json_value(json.loads(text)), ensure_ascii=False)
        except (json.JSONDecodeError, TypeError):
            pass
    cleaned = _SECRET_BODY_RE.sub(r"\1[REDACTED]", text)
    return _PII_BODY_RE.sub("[REDACTED_PII]", cleaned)[:4096]


class HarRecorder:
    """Manages workspace-local HAR capture and scrubs secrets and PII from requests and responses."""

    def __init__(self, workspace: WorkspaceManager, relative_path: str = "browser/traffic.har") -> None:
        self.workspace = workspace
        self.relative_path = relative_path
        self.har_path: Path = workspace.resolve_path(relative_path)
        self.har_path.parent.mkdir(parents=True, exist_ok=True)

    def prepare_path(self) -> Path:
        self.har_path.parent.mkdir(parents=True, exist_ok=True)
        return self.har_path

    def redact_sensitive_data(self) -> dict[str, Any]:
        return self.sanitize_and_summarize()

    def summarize(self) -> dict[str, Any]:
        """Sanitize the completed HAR and return its artifact summary."""
        return self.sanitize_and_summarize()

    def sanitize_and_summarize(self) -> dict[str, Any]:
        if not self.har_path.exists() or self.har_path.stat().st_size == 0:
            return {"recorded": False, "relative_path": self.relative_path, "entries": 0, "sha256": ""}

        raw = json.loads(self.har_path.read_text(encoding="utf-8"))
        entries = raw.get("log", {}).get("entries", [])
        for entry in entries:
            req = entry.get("request", {})
            if isinstance(req, dict):
                if "url" in req:
                    req["url"] = _scrub_url(str(req["url"]))
                if isinstance(req.get("headers"), list):
                    req["headers"] = _scrub_headers(req["headers"])
                if isinstance(req.get("cookies"), list):
                    req["cookies"] = [{"name": c.get("name", ""), "value": "[REDACTED]"} for c in req["cookies"]]
                if isinstance(req.get("queryString"), list):
                    req["queryString"] = [
                        {
                            "name": q.get("name", ""),
                            "value": "[REDACTED]"
                            if _is_sensitive_name(str(q.get("name", "")))
                            else q.get("value", ""),
                        }
                        for q in req["queryString"]
                    ]
                post_data = req.get("postData")
                if isinstance(post_data, dict):
                    mime = str(post_data.get("mimeType", ""))
                    if post_data.get("encoding") == "base64" or not (mime.startswith("text/") or "json" in mime or "xml" in mime or "x-www-form-urlencoded" in mime):
                        if "text" in post_data:
                            post_data["text"] = "[REDACTED_UNSUPPORTED_BODY]"
                    else:
                        post_data["text"] = _scrub_body_text(
                            str(post_data.get("text", "")), mime
                        )
                    if isinstance(post_data.get("params"), list):
                        post_data["params"] = [
                            {"name": p.get("name", ""), "value": "[REDACTED]"} for p in post_data["params"]
                        ]

            resp = entry.get("response", {})
            if isinstance(resp, dict):
                if resp.get("redirectURL"):
                    resp["redirectURL"] = _scrub_url(str(resp["redirectURL"]))
                if isinstance(resp.get("headers"), list):
                    resp["headers"] = _scrub_headers(resp["headers"])
                if isinstance(resp.get("cookies"), list):
                    resp["cookies"] = [{"name": c.get("name", ""), "value": "[REDACTED]"} for c in resp["cookies"]]
                content = resp.get("content")
                if isinstance(content, dict) and "text" in content:
                    mime = str(content.get("mimeType", ""))
                    if content.get("encoding") == "base64" or not (mime.startswith("text/") or "json" in mime or "xml" in mime or "javascript" in mime):
                        content["text"] = "[REDACTED_UNSUPPORTED_BODY]"
                    else:
                        content["text"] = _scrub_body_text(str(content.get("text", "")), mime)

        self.workspace.write_json_atomic(self.relative_path, raw)
        return {
            "recorded": True,
            "relative_path": self.relative_path,
            "entries": len(entries),
            "sha256": self.workspace.file_sha256(self.relative_path),
        }