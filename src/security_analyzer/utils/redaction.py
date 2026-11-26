from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Require a leading "+" or visible separators so plain digit runs (IDs, timestamps) are kept.
_PHONE_RE = re.compile(
    r"(?<![\w.])(?:\+\d{1,3}[\s().-]*\d(?:[\s().-]*\d){7,13}"
    r"|\(?\d{2,4}\)?[\s.-]\d{3,4}[\s.-]\d{3,5})(?![\w.])"
)
_HEADER_SECRET_RE = re.compile(
    r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie)(\s*[:=]\s*)[^\r\n]+"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(token|"
    r"access_token|refresh_token|api[_-]?key|client_secret|secret|password|passwd)"
    r"(\s*[:=]\s*)([^\s&,;]+)"
)

EMAIL_MASK = "[REDACTED_EMAIL]"
PHONE_MASK = "[REDACTED_PHONE]"
TOKEN_MASK = "[REDACTED_TOKEN]"


def scrub_text(value: str) -> str:
    """Mask common personal data and credentials in user-visible free text."""
    if not isinstance(value, str) or not value:
        return value
    value = _HEADER_SECRET_RE.sub(r"\1\2[REDACTED]", value)  # whole header line first
    value = _SECRET_ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", value)
    value = _JWT_RE.sub(TOKEN_MASK, value)
    value = _BEARER_RE.sub(TOKEN_MASK, value)
    value = _EMAIL_RE.sub(EMAIL_MASK, value)
    value = _PHONE_RE.sub(PHONE_MASK, value)
    return value
