from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import requests

from security_analyzer.core.exceptions import ConfigurationError
from security_analyzer.models.finding import FindingRecord, Verdict


_TOKEN_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._~+/-]+=*|"
    r"eyJ[a-z0-9_-]{8,}\.eyJ[a-z0-9_-]{8,}\.[a-z0-9_-]{8,})"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)"
    r"\s*[:=]\s*['\"]?[^'\"&\s,}]+"
)
_ALLOWED_AI_HOSTS = {
    "openrouter.ai",
    "api.openrouter.ai",
    "api.groq.com",
    "generativelanguage.googleapis.com",
    "api.llama.com",
    "api.openai.com",
    "localhost",
    "127.0.0.1",
    "::1",
}


def _sanitize_text(text: str, max_len: int = 400) -> str:
    cleaned = _TOKEN_RE.sub("[REDACTED_TOKEN]", str(text or ""))
    cleaned = _SECRET_ASSIGNMENT_RE.sub(r"\1=[REDACTED]", cleaned)
    return cleaned[:max_len]


def _sanitize_location(url: str) -> str:
    try:
        parsed = urlsplit(str(url))
        if not parsed.scheme or not parsed.hostname:
            return "[REDACTED_LOCATION]"
        host = parsed.hostname
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path or "/", "", ""))
    except (TypeError, ValueError):
        return "[REDACTED_LOCATION]"


def _validate_ai_endpoint(
    endpoint_url: str,
    extra_allowed_hosts: list[str] | None = None,
) -> str:
    """Only known provider hosts or loopback endpoints may receive triage data."""
    try:
        parsed = urlsplit(endpoint_url.strip())
        port = parsed.port
    except (AttributeError, ValueError) as exc:
        raise ConfigurationError(
            f"Malformed AI triage endpoint_url: {type(exc).__name__}"
        ) from exc

    host = (parsed.hostname or "").lower().rstrip(".")
    # Configuration cannot expand this trust boundary to arbitrary internet hosts.
    requested_extras = {
        str(item).strip().lower().rstrip(".")
        for item in (extra_allowed_hosts or [])
        if str(item).strip()
    }
    if not requested_extras.issubset(_ALLOWED_AI_HOSTS):
        raise ConfigurationError(
            "AI triage allowed_hosts may only contain built-in trusted provider hosts"
        )

    if (
        parsed.scheme.lower() not in {"https", "http"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ConfigurationError(
            "AI triage endpoint must be an absolute HTTP(S) URL without embedded credentials"
        )
    if parsed.fragment or parsed.query:
        raise ConfigurationError(
            "AI triage endpoint_url must not contain a query string or fragment"
        )
    if host not in _ALLOWED_AI_HOSTS:
        raise ConfigurationError(
            f"AI triage endpoint host {host!r} is not trusted"
        )

    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if host in local_hosts:
        if parsed.scheme.lower() != "http":
            raise ConfigurationError("Loopback AI endpoints must use HTTP")
        if port is not None and not 1 <= port <= 65535:
            raise ConfigurationError("Invalid local AI endpoint port")
    else:
        if parsed.scheme.lower() != "https":
            raise ConfigurationError("Remote AI triage endpoints must use HTTPS")
        if port not in (None, 443):
            raise ConfigurationError("Remote AI triage endpoint must use standard HTTPS port 443")
    return endpoint_url.strip()


def sanitize_for_llm(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact secrets/PII and bound data before optional external triage."""
    if _depth > 7:
        return "[TRUNCATED]"
    sensitive = (
        "authorization", "cookie", "token", "secret", "password", "api_key",
        "apikey", "email", "phone", "mobile", "address", "ssn", "session",
        "refresh", "credential",
    )
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 50:
                cleaned["_truncated"] = True
                break
            name = str(key).lower().replace("-", "_")
            cleaned[str(key)] = (
                "[REDACTED]"
                if any(term in name for term in sensitive)
                else sanitize_for_llm(item, _depth=_depth + 1)
            )
        return cleaned
    if isinstance(value, (list, tuple)):
        return [
            sanitize_for_llm(item, _depth=_depth + 1)
            for item in list(value)[:50]
        ]
    if isinstance(value, str):
        return _sanitize_location(value) if value.startswith(("http://", "https://")) else _sanitize_text(value, 1000)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _sanitize_text(str(value), 500)


class OptionalAiTriage:
    """Optional advisory-only LLM triage; it cannot change verdict or severity."""

    PROVIDER_ENV_KEYS = {
        "openrouter": "OPENROUTER_API_KEY",
        "groq": "GROQ_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "meta": "META_API_KEY",
        "openai": "OPENAI_API_KEY",
    }

    DEFAULT_ENDPOINTS = {
        "openrouter": "https://openrouter.ai/api/v1/chat/completions",
        "groq": "https://api.groq.com/openai/v1/chat/completions",
        "gemini": "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
        "meta": "https://api.llama.com/compat/v1/chat/completions",
        "openai": "https://api.openai.com/v1/chat/completions",
    }

    def __init__(self, config: dict[str, Any]) -> None:
        ai_cfg = config.get("ai_triage", {})
        if not isinstance(ai_cfg, dict):
            raise ConfigurationError("ai_triage must be a mapping")
        self.enabled = bool(ai_cfg.get("enabled", False))
        self.provider = str(ai_cfg.get("provider", "openrouter")).strip().lower()
        self.model = str(ai_cfg.get("model", "")).strip()[:128]
        self.endpoint_url = str(ai_cfg.get("endpoint_url", "")).strip()
        self.allowed_hosts = list(ai_cfg.get("allowed_hosts") or [])
        self.timeout_sec = float(ai_cfg.get("timeout_sec", 20.0))
        self.max_findings = int(ai_cfg.get("max_findings", 25))
        if not 1 <= self.timeout_sec <= 120:
            raise ConfigurationError("ai_triage.timeout_sec must be between 1 and 120")
        if not 0 <= self.max_findings <= 100:
            raise ConfigurationError("ai_triage.max_findings must be between 0 and 100")
        if self.provider not in {*self.PROVIDER_ENV_KEYS, "local"}:
            raise ConfigurationError(f"Unsupported AI triage provider: {self.provider!r}")

    def _resolve_api_key(self) -> str:
        env_var = self.PROVIDER_ENV_KEYS.get(self.provider, "")
        return os.environ.get(env_var, "").strip() if env_var else ""

    def _endpoint(self) -> str:
        if self.provider == "local":
            endpoint = self.endpoint_url or "http://127.0.0.1:11434/v1/chat/completions"
        elif self.provider == "gemini":
            endpoint = self.endpoint_url or (
                "https://generativelanguage.googleapis.com/v1beta/models/"
                f"{quote(self.model or 'gemini-2.5-flash')}:generateContent"
            )
        else:
            endpoint = self.endpoint_url or self.DEFAULT_ENDPOINTS.get(self.provider, "")
        if not endpoint:
            raise ConfigurationError(
                f"No endpoint configured for AI provider {self.provider!r}"
            )
        validated = _validate_ai_endpoint(endpoint, self.allowed_hosts)
        parsed = urlsplit(validated)
        if self.provider == "local":
            if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise ConfigurationError("Local AI provider must use a loopback endpoint")
        elif parsed.hostname not in {
            urlsplit(self.DEFAULT_ENDPOINTS[self.provider]).hostname
        }:
            raise ConfigurationError(
                "Configured AI endpoint host does not match the selected provider"
            )
        return validated

    def _build_prompt(self, finding: FindingRecord) -> str:
        safe_metadata = {
            key: finding.metadata.get(key)
            for key in (
                "verification",
                "corroborating_sources",
                "parameter_location",
                "template_id",
                "source_artifact",
            )
            if key in finding.metadata
        }
        payload = sanitize_for_llm(
            {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "category": finding.category,
                "severity": finding.severity.value,
                "verdict": finding.verdict.value,
                "confidence": finding.confidence,
                "asset_id": finding.asset_id,
                "endpoint_id": finding.endpoint_id,
                "identity_id": finding.identity_id,
                "description": finding.description,
                "existing_remediation": finding.remediation,
                "evidence_count": len(finding.evidence_ids),
                "metadata": safe_metadata,
            }
        )
        return (
            "You are an advisory security triage assistant. Analyze only the supplied "
            "sanitized finding. Do not claim that an exploit is confirmed unless the "
            "provided verification verdict says CONFIRMED. Do not change severity or "
            "verdict. Return only JSON with exactly these keys: rationale (string, "
            "maximum 500 characters), remediation (string, maximum 500 characters), "
            "recommend_human_review (boolean).\n"
            f"Finding: {json.dumps(payload, sort_keys=True, separators=(',', ':'))}"
        )

    @staticmethod
    def _parse_json_response(raw_text: str) -> dict[str, Any]:
        cleaned = str(raw_text or "").strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(
                r"^```(?:json)?\s*|\s*```$",
                "",
                cleaned,
                flags=re.DOTALL,
            ).strip()
        parsed = json.loads(cleaned)
        if not isinstance(parsed, dict):
            raise ValueError("AI triage response must be a JSON object")
        required = {"rationale", "remediation", "recommend_human_review"}
        if set(parsed) != required:
            raise ValueError("AI triage response has an invalid schema")
        if not isinstance(parsed["rationale"], str):
            raise ValueError("AI triage rationale must be a string")
        if not isinstance(parsed["remediation"], str):
            raise ValueError("AI triage remediation must be a string")
        if not isinstance(parsed["recommend_human_review"], bool):
            raise ValueError("AI triage recommendation must be a boolean")
        return {
            "rationale": _sanitize_text(parsed["rationale"], 500),
            "remediation": _sanitize_text(parsed["remediation"], 500),
            "recommend_human_review": parsed["recommend_human_review"],
        }

    def _post_json(self, endpoint: str, headers: dict[str, str], payload: dict[str, Any]) -> dict[str, Any]:
        response = requests.post(
            endpoint,
            headers=headers,
            json=payload,
            timeout=(min(10.0, self.timeout_sec), self.timeout_sec),
            stream=True,
        )
        response.raise_for_status()
        # Stream and cap provider output; never parse an unbounded response body.
        if hasattr(response, "iter_content"):
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                total += len(chunk)
                if total > 512 * 1024:
                    response.close()
                    raise ValueError("AI triage response exceeds 512 KiB")
                chunks.append(chunk)
            return json.loads(b"".join(chunks).decode("utf-8"))
        content = getattr(response, "content", None)
        if isinstance(content, bytes):
            if len(content) > 512 * 1024:
                raise ValueError("AI triage response exceeds 512 KiB")
            return json.loads(content.decode("utf-8"))
        return response.json()

    def _call_openai_compatible(self, api_key: str, prompt: str) -> dict[str, Any]:
        endpoint = self._endpoint()
        model = self.model or ("llama3" if self.provider == "local" else "openai/gpt-4o-mini")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        data = self._post_json(
            endpoint,
            headers,
            {
                "model": model,
                "temperature": 0.1,
                "max_tokens": 700,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        content = data["choices"][0]["message"]["content"]
        return self._parse_json_response(content)

    def _call_gemini(self, api_key: str, prompt: str) -> dict[str, Any]:
        endpoint = self._endpoint()
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["x-goog-api-key"] = api_key
        data = self._post_json(
            endpoint,
            headers,
            {
                "generationConfig": {
                    "temperature": 0.1,
                    "maxOutputTokens": 700,
                    "responseMimeType": "application/json",
                },
                "contents": [{"parts": [{"text": prompt}]}],
            },
        )
        content = data["candidates"][0]["content"]["parts"][0]["text"]
        return self._parse_json_response(content)

    def triage_findings(
        self,
        findings: list[FindingRecord],
    ) -> tuple[list[FindingRecord], dict[str, Any]]:
        if not self.enabled:
            return findings, {
                "enabled": False,
                "provider": self.provider,
                "processed": 0,
                "reason": "disabled",
            }

        if self.provider != "local":
            api_key = self._resolve_api_key()
            if not api_key:
                return findings, {
                    "enabled": True,
                    "provider": self.provider,
                    "processed": 0,
                    "reason": "missing_api_key_env",
                }
        else:
            api_key = ""

        processed = 0
        errors: list[str] = []
        eligible = [
            finding
            for finding in findings
            if finding.verdict != Verdict.FALSE_POSITIVE
        ][: self.max_findings]

        for finding in eligible:
            original_verdict = finding.verdict
            original_severity = finding.severity
            try:
                prompt = self._build_prompt(finding)
                if self.provider == "gemini":
                    advice = self._call_gemini(api_key, prompt)
                else:
                    advice = self._call_openai_compatible(api_key, prompt)

                # Advisory only: AI output must never promote/downgrade a finding.
                finding.metadata["ai_triage"] = {
                    "provider": self.provider,
                    "rationale": advice["rationale"],
                    "remediation_suggestion": advice["remediation"],
                    "recommend_human_review": advice["recommend_human_review"],
                }
                finding.verdict = original_verdict
                finding.severity = original_severity
                processed += 1
            except Exception as exc:
                errors.append(
                    f"{finding.finding_id}: {type(exc).__name__}"
                )

        return findings, {
            "enabled": True,
            "provider": self.provider,
            "processed": processed,
            "eligible": len(eligible),
            "errors": errors[:10],
        }
