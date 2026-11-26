from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.utils.http_client import ScopedHttpClient

SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.IGNORECASE)
SOURCE_MAP_RE = re.compile(r"""(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s*]+)""")
MAX_SOURCE_MAP_BYTES = 5_000_000

API_PATH_RE = re.compile(
    r"""["']((?:https?://[a-zA-Z0-9.-]+(?::\d+)?)?/(?:api|v[1-9]|graphql|auth|oauth|users|account|orders|payments|admin)[a-zA-Z0-9_./{}?=&%,:-]{1,200})["']"""
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe_live_secret", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("jwt_literal", re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)
SENSITIVE_QUERY_RE = re.compile(
    r"(?i)(token|secret|password|passwd|api[-_]?key|auth|jwt|session|cookie|code|"
    r"email|mail|phone|mobile|address|postal|zip|dob|birth|user[-_]?id|account[-_]?id)"
)
_EMAIL_VALUE_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_VALUE_RE = re.compile(r"^\+?[0-9][0-9\-\s().]{6,}[0-9]$")
_JWT_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")


def _redact_url(url: str) -> str:
    parsed = urlsplit(url)
    query = [
        (
            key,
            "[REDACTED]"
            if (
                SENSITIVE_QUERY_RE.search(key)
                or _EMAIL_VALUE_RE.fullmatch(value)
                or _PHONE_VALUE_RE.fullmatch(value)
                or _JWT_VALUE_RE.fullmatch(value)
            )
            else value[:64],
        )
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


class JsBundleAnalyzer:
    """Inspects in-scope JavaScript bundles for hidden API routes, exposed source maps, and hardcoded secrets."""

    def __init__(
        self,
        client: ScopedHttpClient,
        *,
        stage_id: str = "api_js_intelligence",
        max_bundles: int = 30,
        max_bundle_bytes: int = 2_000_000,
    ) -> None:
        self.client = client
        self.stage_id = stage_id
        self.max_bundles = max(1, min(int(max_bundles), 200))
        self.max_bundle_bytes = max(1024, min(int(max_bundle_bytes), 10_000_000))

    @staticmethod
    def _has_unresolved_template(url: str) -> bool:
        path = urlsplit(url).path
        return "{" in path or "}" in path

    def _allowed(self, url: str) -> bool:
        if self._has_unresolved_template(url):
            return False
        try:
            return self.client.scope_engine.evaluate_url(url, check_dns=True).allowed
        except (TypeError, ValueError):
            return False

    def discover_bundle_urls(self, html_page_urls: list[str], known_urls: list[str]) -> list[str]:
        bundles: list[str] = []
        seen: set[str] = set()

        for u in known_urls:
            path_lower = urlsplit(u).path.lower()
            if path_lower.endswith(".js") and not self._has_unresolved_template(u) and self._allowed(u) and u not in seen:
                seen.add(u)
                bundles.append(u)

        for page_url in html_page_urls[:15]:
            if self._has_unresolved_template(page_url) or not self._allowed(page_url):
                continue
            try:
                resp = self.client.get(page_url, stage_id=self.stage_id)
            except (ScopeViolationError, requests.RequestException):
                continue
            if resp.status_code != 200 or "html" not in resp.headers.get("Content-Type", "").lower():
                continue
            for match in SCRIPT_SRC_RE.findall(resp.text[:300_000]):
                resolved = urljoin(page_url, match.strip()).split("#", 1)[0]
                if self._allowed(resolved) and urlsplit(resolved).path.lower().endswith((".js", ".mjs")) and resolved not in seen:
                    seen.add(resolved)
                    bundles.append(resolved)

        return bundles[: self.max_bundles]

    def analyze_bundles(
        self,
        bundle_urls: list[str],
    ) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
        bundle_records: list[dict[str, Any]] = []
        extracted_endpoints: list[str] = []
        seen_endpoints: set[str] = set()
        findings: list[dict[str, Any]] = []

        for js_url in bundle_urls[: self.max_bundles]:
            if self._has_unresolved_template(js_url) or not self._allowed(js_url):
                continue
            try:
                resp = self.client.get(js_url, stage_id=self.stage_id)
            except (ScopeViolationError, requests.RequestException):
                continue

            if resp.status_code != 200:
                continue

            if len(resp.content or b"") > self.max_bundle_bytes:
                continue
            raw_bytes = resp.content or b""
            code = raw_bytes.decode("utf-8", errors="replace")
            bundle_sha256 = hashlib.sha256(raw_bytes).hexdigest()

            origin = f"{urlsplit(js_url).scheme}://{urlsplit(js_url).netloc}"
            local_routes: list[str] = []
            for rel_or_abs in API_PATH_RE.findall(code):
                candidate = rel_or_abs if rel_or_abs.startswith(("http://", "https://")) else urljoin(origin, rel_or_abs)
                if not self.client.scope_engine.evaluate_url(candidate, check_dns=True).allowed:
                    continue
                if not self._allowed(candidate):
                    continue
                if candidate not in local_routes:
                    local_routes.append(candidate)
                if candidate not in seen_endpoints:
                    seen_endpoints.add(candidate)
                    extracted_endpoints.append(candidate)

            # Redacted secret indicators (never store raw secret values in output artifacts)
            secret_matches: list[dict[str, Any]] = []
            for label, pattern in SECRET_PATTERNS:
                hits = pattern.findall(code)
                if hits:
                    secret_matches.append(
                        {
                            "indicator_type": label,
                            "match_count": len(hits),
                            "redacted_preview": "[REDACTED]",
                        }
                    )
                    findings.append(
                        {
                            "category": "hardcoded_secret_in_js",
                            "severity": "INFO",
                            "url": _redact_url(js_url),
                            "title": f"Unverified secret-like pattern ({label}) in JavaScript bundle",
                            "details": f"Matched {len(hits)} occurrence(s) of {label}; value redacted. Validity and impact not established.",
                        }
                    )

            # Fetch and inspect the actual source map. A successful HEAD/GET alone
            # is not a vulnerability: embedded source content is the meaningful exposure.
            source_map_url = ""
            map_match = SOURCE_MAP_RE.search(code[-200_000:])
            if map_match:
                map_ref = map_match.group(1).strip().strip("\\\"'`")
                if not map_ref.startswith("data:"):
                    source_map_url = urljoin(js_url, map_ref)
            if not source_map_url:
                js_parts = urlsplit(js_url)
                source_map_url = urlunsplit((
                    js_parts.scheme, js_parts.netloc, js_parts.path + ".map", "", ""
                ))

            source_map_exposed = False
            source_map_content_exposed = False
            source_map_metadata: dict[str, Any] = {}
            try:
                if not self._allowed(source_map_url):
                    raise ScopeViolationError("Out-of-scope source map")
                map_resp = self.client.get(source_map_url, stage_id=self.stage_id)
                map_bytes = map_resp.content or b""
                if (
                    map_resp.status_code == 200
                    and len(map_bytes) <= MAX_SOURCE_MAP_BYTES
                    and (
                        "json" in map_resp.headers.get("Content-Type", "").lower()
                        or map_bytes.lstrip().startswith(b"{")
                    )
                ):
                    import json
                    parsed_map = json.loads(map_bytes.decode("utf-8", errors="replace"))
                    if isinstance(parsed_map, dict) and isinstance(parsed_map.get("sources"), list):
                        source_map_exposed = True
                        sources = [
                            str(item)[:256]
                            for item in parsed_map["sources"][:500]
                            if isinstance(item, str)
                        ]
                        embedded = parsed_map.get("sourcesContent")
                        embedded_count = (
                            sum(1 for item in embedded[:500] if isinstance(item, str) and item)
                            if isinstance(embedded, list)
                            else 0
                        )
                        source_map_content_exposed = embedded_count > 0
                        source_map_metadata = {
                            "sources_count": len(parsed_map["sources"]),
                            "embedded_sources_count": embedded_count,
                            "sources_preview": [item.rsplit("/", 1)[-1] for item in sources[:20]],
                            "source_root_present": bool(parsed_map.get("sourceRoot")),
                        }
                        if source_map_content_exposed:
                            findings.append({
                                "category": "source_map_source_content_exposed",
                                "severity": "LOW",
                                "url": _redact_url(source_map_url),
                                "title": "JavaScript source map contains embedded source code",
                                "details": (
                                    f"The source map embeds source content for {embedded_count} source file(s). "
                                    "No source contents are copied into the finding; review the files for "
                                    "sensitive implementation details or secrets."
                                ),
                            })
            except (ScopeViolationError, requests.RequestException, ValueError, UnicodeError):
                source_map_exposed = False
                source_map_content_exposed = False

            bundle_records.append(
                {
                    "url": _redact_url(js_url),
                    "sha256": bundle_sha256,
                    "size_bytes": len(raw_bytes),
                    "source_map_url": _redact_url(source_map_url) if source_map_url else "",
                    "source_map_exposed": source_map_exposed,
                    "source_map_content_exposed": source_map_content_exposed,
                    "source_map_metadata": source_map_metadata,
                    "extracted_routes_count": len(local_routes),
                    "extracted_routes": [_redact_url(route) for route in local_routes[:100]],
                    "secret_indicators": secret_matches,
                }
            )

        return bundle_records, extracted_endpoints, findings
