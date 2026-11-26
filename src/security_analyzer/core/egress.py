from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from security_analyzer.core.scope_engine import ScopePolicy

_LAB_SUFFIXES = (".localhost", ".test", ".local", ".internal")
_DOCKER_PROXY_HOST = "egress-proxy"
_DOCKER_PROXY_PORT = 3128


def scope_proxy_parts(proxy_url: str) -> tuple[str, int] | None:
    """Return the trusted scope-aware proxy authority, or None.

    Host execution is restricted to loopback proxies. The Docker deployment
    additionally permits exactly the Compose service DNS name on its fixed
    internal port. Arbitrary hostnames, credentials, paths, query strings,
    fragments, non-HTTP schemes, and invalid ports are rejected.
    """
    raw = str(proxy_url or "").strip()
    if not raw:
        return None
    try:
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        return None

    if (
        parsed.scheme.lower() != "http"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not host
        or port is None
        or not 1 <= port <= 65535
    ):
        return None

    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host == "localhost"

    if is_loopback:
        return host, port
    if (
        host == _DOCKER_PROXY_HOST
        and port == _DOCKER_PROXY_PORT
        and os.environ.get("SECURITY_ANALYZER_PROXY_TRANSPORT") == "docker"
    ):
        return host, port
    return None


def is_trusted_scope_proxy(proxy_url: str) -> bool:
    """Whether a proxy URL points only to an approved local proxy endpoint."""
    return scope_proxy_parts(proxy_url) is not None


@dataclass(frozen=True)
class BrowserEgress:
    mode: str  # "proxy", "lab" or "blocked"
    proxy_url: str = ""
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.mode in {"proxy", "lab"}


def _is_lab_domain(domain: str) -> bool:
    host = domain.strip().lower().strip(".")
    if host == "localhost" or host.endswith(_LAB_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        not ip.is_multicast
        and not ip.is_unspecified
        and not ip.is_reserved
        and not ip.is_link_local
        and (ip.is_loopback or ip.is_private)
    )


def policy_is_lab_only(policy: ScopePolicy) -> bool:
    """True only when scope contains private/loopback/lab names and permits private IPs."""
    if not policy.allow_private_ips:
        return False
    if not policy.allowed_domains and not policy.allowed_cidrs:
        return False
    if not all(_is_lab_domain(domain) for domain in policy.allowed_domains):
        return False
    for cidr in policy.allowed_cidrs:
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            return False
        if (
            network.is_multicast
            or network.is_unspecified
            or network.is_reserved
            or network.is_link_local
            or not (network.is_private or network.is_loopback)
        ):
            return False
    return True


def resolve_browser_egress(config: dict[str, Any], policy: ScopePolicy) -> BrowserEgress:
    """Choose enforced proxy mode, narrowly scoped lab mode, or block browser egress."""
    proxy_url = os.environ.get("SECURITY_ANALYZER_PROXY", "").strip()
    enforced = os.environ.get("SECURITY_ANALYZER_EGRESS_ENFORCED") == "1"
    if enforced and is_trusted_scope_proxy(proxy_url):
        return BrowserEgress("proxy", proxy_url)
    if enforced and proxy_url:
        return BrowserEgress(
            "blocked",
            "",
            "SECURITY_ANALYZER_PROXY is not an approved loopback or Docker scope-aware proxy endpoint",
        )
    if (config.get("browser") or {}).get("lab_mode", False) is True:
        if policy_is_lab_only(policy):
            return BrowserEgress("lab", "", "lab mode: scope is loopback/private only")
        return BrowserEgress(
            "blocked",
            "",
            "browser.lab_mode is on but the scope contains non-lab hosts; use the enforced egress proxy",
        )
    return BrowserEgress(
        "blocked", "", "Browser capture skipped: enforced egress proxy is not configured"
    )
