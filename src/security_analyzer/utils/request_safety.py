from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

# Match action words as complete path/label tokens. This avoids treating
# unrelated words such as "repayment-history" as destructive actions.
_TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)
_DESTRUCTIVE_SINGLE_TOKENS = frozenset({
    "logout", "signout", "delete", "remove", "destroy", "drop",
    "pay", "checkout", "purchase", "transfer", "cancel", "unsubscribe",
    "submit", "deactivate", "approve", "revoke", "invite",
})
_DESTRUCTIVE_SEQUENCES = (
    ("log", "out"),
    ("sign", "out"),
    ("reset", "password"),
    ("confirm", "payment"),
    ("change", "password"),
    ("send", "money"),
)
_SAFE_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Compatibility for legacy consumers; new discovery paths should call
# is_destructive_request() so URL decoding and method checks are consistent.
DESTRUCTIVE_PATH_RE = re.compile(
    r"(?i)(?:^|[/_-])(?:logout|signout|delete|remove|destroy|drop|pay|checkout|"
    r"purchase|transfer|cancel|unsubscribe|submit|confirm[-_]?payment|"
    r"deactivate|approve|revoke|invite|reset[-_]?password)(?:$|[/_-])"
)


def _decoded_path(url: str) -> str:
    """Return a normalized, repeatedly decoded URL path for policy matching."""
    try:
        path = urlsplit(str(url or "").strip()).path or "/"
    except ValueError:
        return "/"
    for _ in range(3):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    return path.replace("\\\\", "/")


def _contains_action(value: str) -> bool:
    tokens = [token.lower() for token in _TOKEN_RE.findall(value or "")]
    if any(token in _DESTRUCTIVE_SINGLE_TOKENS for token in tokens):
        return True
    return any(
        any(tuple(tokens[index:index + len(sequence)]) == sequence
            for index in range(len(tokens) - len(sequence) + 1))
        for sequence in _DESTRUCTIVE_SEQUENCES
    )


def is_destructive_request(
    url: str,
    method: str = "GET",
    label_hint: str = "",
) -> bool:
    """Fail closed for non-read methods and known state-changing URL actions.

    This is a conservative discovery policy, not an authorization control.
    Actual requests must still pass ScopeEngine and the egress boundary.
    """
    normalized_method = str(method or "GET").strip().upper()
    if normalized_method not in _SAFE_READ_METHODS:
        return True
    return _contains_action(_decoded_path(url)) or _contains_action(label_hint)


def is_safe_read_method(method: str) -> bool:
    return str(method or "").strip().upper() in _SAFE_READ_METHODS
