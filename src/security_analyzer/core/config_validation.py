from __future__ import annotations

import math

import copy
from typing import Any

from security_analyzer.core.exceptions import ConfigurationError


DEFAULT_SETTINGS: dict[str, Any] = {
    "output_root": "output",
    "scope": {"check_dns": True},
    "timeouts": {
        "http_connect_sec": 10, "http_read_sec": 20, "max_redirects": 5,
        "subfinder_sec": 120, "directory_scan_sec": 180, "nuclei_sec": 300, "tls_sec": 10, "dns_sec": 8,
    },
    "limits": {
        "max_urls_per_stage": 2500, "max_directory_words": 250, "max_header_review_endpoints": 50,
        "max_concurrent_requests": 10, "max_total_requests": 10000,
        "max_external_processes": 1000, "max_concurrent_processes": 3,
        "max_response_bytes": 5242880, "max_process_output_bytes": 2097152,
        "max_scan_duration_sec": 14400, "requests_per_host_per_sec": 5,
    },
    "wordlists": {"directories": ""},
    "tls": {"verify_certificates": True},
    "browser": {
        "headless": True,
        "lab_mode": False,
        "max_pages": 25,
        "max_depth": 2,
        "max_identities": 5,
        "navigation_timeout_ms": 15000,
        "settle_wait_ms": 1200,
        "max_screenshots": 15,
        "max_console_events": 500,
        "record_har": True,
        "capture_screenshots": True,
        "har_mode": "minimal",
        "viewport": {"width": 1366, "height": 768},
    },
    "nuclei": {
        "max_targets": 100, "rate_limit": 25, "concurrency": 10,
        "bulk_size": 10, "severities": "low,medium,high,critical",
        "templates_dir": "", "inactivity_timeout_sec": 180,
    },
    "deep_checks": {
        "max_authz_endpoints": 60,
        "max_logic_endpoints": 60,
        "allow_state_changing_probes": False,
        "enable_rewrite_header_probes": False,
        "max_pagination_probe_value": 1000,
    },
    "ai_triage": {
        "enabled": False,
        "provider": "openrouter",
        "model": "",
        "endpoint_url": "",
        "allowed_hosts": [],
        "timeout_sec": 20,
        "max_findings": 25,
    },
}


def _merge(default: dict[str, Any], supplied: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(default)
    for key, value in supplied.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def validate_settings(settings: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(settings, dict):
        raise ConfigurationError("Settings must be a YAML mapping")
    cfg = _merge(DEFAULT_SETTINGS, settings)
    if not isinstance(cfg.get("output_root"), str) or not cfg["output_root"].strip():
        raise ConfigurationError("output_root must be a non-empty string")

    for section in ("scope", "timeouts", "limits", "wordlists", "tls", "browser", "nuclei", "deep_checks", "ai_triage"):
        if not isinstance(cfg.get(section), dict):
            raise ConfigurationError(f"settings.{section} must be a mapping")

    for key in ("http_connect_sec", "http_read_sec", "subfinder_sec", "directory_scan_sec", "tls_sec", "dns_sec"):
        value = cfg["timeouts"].get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ConfigurationError(f"timeouts.{key} must be a positive number")
    redirects = cfg["timeouts"].get("max_redirects")
    if isinstance(redirects, bool) or not isinstance(redirects, int) or not 0 <= redirects <= 20:
        raise ConfigurationError("timeouts.max_redirects must be an integer from 0 to 20")

    positive_int_limits = (
        "max_urls_per_stage", "max_directory_words", "max_header_review_endpoints", "max_concurrent_requests",
        "max_total_requests", "max_external_processes", "max_concurrent_processes",
        "max_response_bytes", "max_process_output_bytes",
    )
    for key in positive_int_limits:
        value = cfg["limits"].get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ConfigurationError(f"limits.{key} must be a positive integer")
    for key in ("max_scan_duration_sec", "requests_per_host_per_sec"):
        value = cfg["limits"].get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ConfigurationError(f"limits.{key} must be a positive number")
    if cfg["limits"]["max_concurrent_processes"] > cfg["limits"]["max_external_processes"]:
        raise ConfigurationError("limits.max_concurrent_processes cannot exceed max_external_processes")

    if not isinstance(cfg["scope"].get("check_dns"), bool):
        raise ConfigurationError("scope.check_dns must be a boolean")
    if not isinstance(cfg["tls"].get("verify_certificates"), bool):
        raise ConfigurationError("tls.verify_certificates must be a boolean")
    if not isinstance(cfg["wordlists"].get("directories", ""), str):
        raise ConfigurationError("wordlists.directories must be a string")
    nuclei_timeout = cfg["timeouts"].get("nuclei_sec", 300)
    if isinstance(nuclei_timeout, bool) or not isinstance(nuclei_timeout, (int, float)) or nuclei_timeout <= 0:
        raise ConfigurationError("timeouts.nuclei_sec must be a positive number")
    for key in ("max_targets", "rate_limit", "concurrency", "bulk_size"):
        value = cfg["nuclei"].get(key, 1)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ConfigurationError(f"nuclei.{key} must be a positive integer")
    if cfg["nuclei"]["concurrency"] > cfg["nuclei"]["rate_limit"]:
        raise ConfigurationError("nuclei.concurrency cannot exceed nuclei.rate_limit")
    if not isinstance(cfg["nuclei"].get("templates_dir", ""), str):
        raise ConfigurationError("nuclei.templates_dir must be a string")
    inactivity_timeout = cfg["nuclei"].get("inactivity_timeout_sec", 180)
    if (
        isinstance(inactivity_timeout, bool)
        or not isinstance(inactivity_timeout, (int, float))
        or not math.isfinite(float(inactivity_timeout))
        or inactivity_timeout <= 0
    ):
        raise ConfigurationError("nuclei.inactivity_timeout_sec must be a finite positive number")
    severity_values = {
        item.strip().lower()
        for item in str(cfg["nuclei"].get("severities", "")).split(",")
        if item.strip()
    }
    if not severity_values or not severity_values.issubset(
        {"info", "low", "medium", "high", "critical"}
    ):
        raise ConfigurationError(
            "nuclei.severities must be a comma-separated subset of info,low,medium,high,critical"
        )

    deep_checks = cfg["deep_checks"]
    for key in ("max_authz_endpoints", "max_logic_endpoints"):
        value = deep_checks.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 500:
            raise ConfigurationError(f"deep_checks.{key} must be an integer from 1 to 500")
    for key in ("allow_state_changing_probes", "enable_rewrite_header_probes"):
        if not isinstance(deep_checks.get(key), bool):
            raise ConfigurationError(f"deep_checks.{key} must be a boolean")
    if deep_checks["allow_state_changing_probes"]:
        raise ConfigurationError(
            "Step 7 is read-only; deep_checks.allow_state_changing_probes must remain false"
        )
    pagination_limit = deep_checks.get("max_pagination_probe_value")
    if (
        isinstance(pagination_limit, bool)
        or not isinstance(pagination_limit, int)
        or not 10 <= pagination_limit <= 1000
    ):
        raise ConfigurationError(
            "deep_checks.max_pagination_probe_value must be an integer from 10 to 1000"
        )

    browser = cfg["browser"]
    for key in ("headless", "record_har", "capture_screenshots", "lab_mode"):
        if not isinstance(browser.get(key), bool):
            raise ConfigurationError(f"browser.{key} must be a boolean")
    for key in ("max_pages", "max_identities", "navigation_timeout_ms", "max_console_events"):
        value = browser.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ConfigurationError(f"browser.{key} must be a positive integer")
    for key in ("max_depth", "settle_wait_ms", "max_screenshots"):
        value = browser.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ConfigurationError(f"browser.{key} must be a non-negative integer")
    if browser.get("har_mode") not in {"full", "minimal"}:
        raise ConfigurationError("browser.har_mode must be 'full' or 'minimal'")

    ai_cfg = cfg["ai_triage"]
    if not isinstance(ai_cfg.get("enabled"), bool):
        raise ConfigurationError("ai_triage.enabled must be a boolean")
    if ai_cfg.get("provider") not in {"openrouter", "groq", "gemini", "meta", "openai", "local"}:
        raise ConfigurationError("ai_triage.provider is not supported")
    for key in ("model", "endpoint_url"):
        if not isinstance(ai_cfg.get(key), str):
            raise ConfigurationError(f"ai_triage.{key} must be a string")
    if not isinstance(ai_cfg.get("allowed_hosts"), list) or any(
        not isinstance(host, str) for host in ai_cfg["allowed_hosts"]
    ):
        raise ConfigurationError("ai_triage.allowed_hosts must be a list of strings")
    timeout = ai_cfg.get("timeout_sec")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 120:
        raise ConfigurationError("ai_triage.timeout_sec must be between 1 and 120")
    max_findings = ai_cfg.get("max_findings")
    if isinstance(max_findings, bool) or not isinstance(max_findings, int) or not 0 <= max_findings <= 100:
        raise ConfigurationError("ai_triage.max_findings must be an integer from 0 to 100")
    viewport = browser.get("viewport")
    if not isinstance(viewport, dict):
        raise ConfigurationError("browser.viewport must be a mapping")
    for dimension in ("width", "height"):
        value = viewport.get(dimension)
        if isinstance(value, bool) or not isinstance(value, int) or not 320 <= value <= 7680:
            raise ConfigurationError(f"browser.viewport.{dimension} must be an integer from 320 to 7680")
    return cfg
