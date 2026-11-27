from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import posixpath
import socket
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import yaml

from security_analyzer.core.exceptions import ConfigurationError, ScopeViolationError


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    normalized_url: str
    reason: str
    resolved_ips: tuple[str, ...] = ()


def _dns_delegated_to_proxy() -> bool:
    """True only in the Docker scanner container (all three variables must be set)."""
    return (
        os.environ.get("SECURITY_ANALYZER_DNS_DELEGATED_TO_PROXY") == "1"
        and os.environ.get("SECURITY_ANALYZER_EGRESS_ENFORCED") == "1"
        and os.environ.get("SECURITY_ANALYZER_PROXY_TRANSPORT") == "docker"
    )


@dataclass
class ScopePolicy:
    allowed_domains: list[str]
    include_subdomains: bool = True
    allowed_schemes: list[str] = field(default_factory=lambda: ["http", "https"])
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443])
    excluded_paths: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    allow_private_ips: bool = False

    def __post_init__(self) -> None:
        self.allowed_domains = [d.strip().lower().strip(".") for d in self.allowed_domains if d.strip()]
        if not self.allowed_domains and not self.allowed_cidrs:
            raise ConfigurationError("ScopePolicy requires at least one allowed_domain or allowed_cidr.")
        self.allowed_schemes = [s.strip().lower() for s in self.allowed_schemes if s.strip()]
        if not self.allowed_schemes or any(s not in {"http", "https"} for s in self.allowed_schemes):
            raise ConfigurationError("allowed_schemes may contain only http and https.")
        self.allowed_ports = [int(p) for p in self.allowed_ports]
        if any(port < 1 or port > 65535 for port in self.allowed_ports):
            raise ConfigurationError("allowed_ports must be between 1 and 65535.")
        self.excluded_paths = [self._normalize_path_rule(p) for p in self.excluded_paths if p.strip()]

    @staticmethod
    def _normalize_path_rule(raw_path: str) -> str:
        cleaned = "/" + raw_path.strip().lower().lstrip("/")
        if len(cleaned) > 1:
            cleaned = cleaned.rstrip("/")
        return cleaned

    def fingerprint(self) -> str:
        canonical = json.dumps(asdict(self), sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint()
        return data

    @classmethod
    def from_yaml(cls, path: Path, target_url: str | None = None) -> "ScopePolicy":
        if not path.exists():
            raise ConfigurationError(f"Scope file not found: {path}")
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ConfigurationError(f"Scope file must define a YAML mapping: {path}")

        domains = list(raw.get("allowed_domains") or [])
        ports = list(raw.get("allowed_ports") or [80, 443])

        return cls(
            allowed_domains=domains,
            include_subdomains=bool(raw.get("include_subdomains", True)),
            allowed_schemes=list(raw.get("allowed_schemes") or ["http", "https"]),
            allowed_ports=ports,
            excluded_paths=list(raw.get("excluded_paths") or []),
            allowed_cidrs=list(raw.get("allowed_cidrs") or []),
            allow_private_ips=bool(raw.get("allow_private_ips", False)),
        )


class ScopeEngine:
    """Authoritative scope gatekeeper for URLs, hosts, paths, ports, DNS IPs, and Host headers."""

    def __init__(self, policy: ScopePolicy) -> None:
        self.policy = policy
        try:
            self._networks = [ipaddress.ip_network(cidr, strict=False) for cidr in policy.allowed_cidrs]
        except ValueError as exc:
            raise ConfigurationError(f"Invalid allowed CIDR in scope policy: {exc}") from exc

    def _is_ip_permitted(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            return self._is_ip_permitted(ip_obj.ipv4_mapped)
        if any(ip_obj in net for net in self._networks):
            return True, ""
        # Always block multicast, unspecified, and reserved ranges unless explicitly in allowed_cidrs
        if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
            return False, f"IP {ip_obj} is multicast/unspecified/reserved and disallowed by policy"
        if ip_obj.is_link_local:
            return False, f"IP {ip_obj} is link-local and disallowed by policy"
        if not self.policy.allow_private_ips and (
            ip_obj.is_private or ip_obj.is_loopback or not ip_obj.is_global
        ):
            return False, f"IP {ip_obj} is non-public and disallowed by policy"
        return True, ""

    def _is_host_allowed(self, hostname: str) -> bool:
        host = hostname.strip().lower().rstrip(".")
        if not host:
            return False

        try:
            ip_obj = ipaddress.ip_address(host)
            allowed, _ = self._is_ip_permitted(ip_obj)
            if not allowed:
                return False
            if any(ip_obj in net for net in self._networks):
                return True
            return self.policy.allow_private_ips and (
                ip_obj.is_private or ip_obj.is_loopback or not ip_obj.is_global
            )
        except ValueError:
            pass

        for domain in self.policy.allowed_domains:
            if host == domain:
                return True
            if self.policy.include_subdomains and host.endswith(f".{domain}"):
                return True
        return False

    def _is_path_excluded(self, request_path: str) -> str | None:
        normalized = request_path or "/"
        for _ in range(3):
            decoded = unquote(normalized)
            if decoded == normalized:
                break
            normalized = decoded
        normalized = normalized.replace("\\", "/").lower()
        # Drop path parameters (for example, ;jsessionid=...) that servers ignore when routing.
        normalized = "/".join(segment.split(";", 1)[0] for segment in normalized.split("/"))
        normalized = posixpath.normpath("/" + normalized.lstrip("/"))
        if len(normalized) > 1:
            normalized = normalized.rstrip("/")

        for rule in self.policy.excluded_paths:
            if rule == "/":
                return rule
            if normalized == rule or normalized.startswith(f"{rule}/"):
                return rule
        return None

    def _validate_resolved_ips(self, hostname: str, port: int) -> tuple[bool, str, tuple[str, ...]]:
        try:
            ip_obj = ipaddress.ip_address(hostname)
            ips = [ip_obj]
        except ValueError:
            try:
                infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            except OSError as exc:
                if _dns_delegated_to_proxy():
                    # Docker internal network: this container has no DNS. The egress proxy
                    # resolves the name, validates every IP against the scope and connects
                    # to that exact IP, so the check is not skipped, only moved to the proxy.
                    return True, "", ()
                return False, f"DNS resolution failed for {hostname}: {type(exc).__name__}", ()
            ips = []
            for info in infos:
                addr_str = info[4][0]
                try:
                    ips.append(ipaddress.ip_address(addr_str))
                except ValueError:
                    continue

        if not ips:
            return False, f"No valid IP addresses resolved for {hostname}", ()

        ordered_unique: list[str] = []
        for ip_obj in ips:
            permitted, deny_reason = self._is_ip_permitted(ip_obj)
            if not permitted:
                return False, f"Resolved {deny_reason} (host {hostname})", ()
            ip_str = str(ip_obj)
            if ip_str not in ordered_unique:
                ordered_unique.append(ip_str)

        return True, "DNS resolution within authorized network bounds", tuple(ordered_unique)

    def evaluate_url(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        check_dns: bool = False,
    ) -> ScopeDecision:
        raw = url.strip()
        if not raw:
            return ScopeDecision(False, raw, "Empty URL")

        try:
            parsed = urlsplit(raw)
            port_value = parsed.port
        except ValueError as exc:
            return ScopeDecision(False, raw, f"Malformed URL authority: {exc}")
        scheme = parsed.scheme.lower()
        if scheme not in self.policy.allowed_schemes:
            return ScopeDecision(False, raw, f"Disallowed scheme: {scheme!r}")

        if parsed.username is not None or parsed.password is not None:
            return ScopeDecision(False, raw, "Embedded credentials in URL are forbidden")

        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            return ScopeDecision(False, raw, "Missing hostname")

        port = port_value or (443 if scheme == "https" else 80)
        if self.policy.allowed_ports and port not in self.policy.allowed_ports:
            return ScopeDecision(False, raw, f"Port {port} is not in allowed_ports {self.policy.allowed_ports}")

        if not self._is_host_allowed(hostname):
            return ScopeDecision(False, raw, f"Hostname {hostname!r} is outside allowed_domains")

        if headers:
            for k, v in headers.items():
                if k.lower() == "host" and v.strip():
                    try:
                        parsed_header = urlsplit(f"//{v.strip()}")
                        header_host = (parsed_header.hostname or "").lower().rstrip(".")
                        header_port = parsed_header.port
                    except ValueError:
                        header_host = ""
                        header_port = None
                    if (
                        header_host != hostname
                        or not self._is_host_allowed(header_host)
                        or (header_port is not None and header_port != port)
                    ):
                        return ScopeDecision(
                            False,
                            raw,
                            f"Host header {header_host!r} mismatches destination hostname {hostname!r}",
                        )

        excluded_rule = self._is_path_excluded(parsed.path or "/")
        if excluded_rule is not None:
            return ScopeDecision(False, raw, f"Path {parsed.path!r} matches excluded path rule {excluded_rule!r}")

        resolved_ips: tuple[str, ...] = ()
        if check_dns:
            dns_ok, dns_reason, resolved_ips = self._validate_resolved_ips(hostname, port)
            if not dns_ok:
                return ScopeDecision(False, raw, dns_reason)

        path_part = parsed.path or "/"
        netloc_host = f"[{hostname}]" if ":" in hostname else hostname
        normalized = f"{scheme}://{netloc_host}"
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            normalized += f":{port}"
        normalized += path_part
        if parsed.query:
            normalized += f"?{parsed.query}"

        return ScopeDecision(True, normalized, "In scope", resolved_ips=resolved_ips)

    def enforce_url(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        check_dns: bool = True,
    ) -> str:
        decision = self.evaluate_url(url, headers=headers, check_dns=check_dns)
        if not decision.allowed:
            raise ScopeViolationError(f"Scope violation for {url!r}: {decision.reason}")
        return decision.normalized_url
