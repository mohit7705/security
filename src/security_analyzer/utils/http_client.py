from __future__ import annotations

import threading
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.poolmanager import PoolManager
from urllib3.util import connection as urllib3_connection

from security_analyzer.core.coverage_tracker import CoverageTracker
from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.scope_engine import ScopeEngine
from security_analyzer.core.resource_governor import ResourceGovernor, ResourceLimitExceeded


_PINNED_IP_LOCAL = threading.local()


def _get_pinned_ip(host: str) -> str | None:
    mapping: dict[str, str] | None = getattr(_PINNED_IP_LOCAL, "host_to_ip", None)
    if not mapping:
        return None
    return mapping.get(host.lower().rstrip("."))


class _PinnedHTTPConnection(HTTPConnection):
    def _new_conn(self):
        pinned = _get_pinned_ip(self.host)
        target_host = pinned if pinned else self.host
        extra_kw: dict[str, Any] = {}
        if self.source_address:
            extra_kw["source_address"] = self.source_address
        if self.socket_options:
            extra_kw["socket_options"] = self.socket_options
        return urllib3_connection.create_connection(
            (target_host, self.port),
            self.timeout,
            **extra_kw,
        )


class _PinnedHTTPSConnection(HTTPSConnection):
    def _new_conn(self):
        pinned = _get_pinned_ip(self.host)
        target_host = pinned if pinned else self.host
        extra_kw: dict[str, Any] = {}
        if self.source_address:
            extra_kw["source_address"] = self.source_address
        if self.socket_options:
            extra_kw["socket_options"] = self.socket_options
        return urllib3_connection.create_connection(
            (target_host, self.port),
            self.timeout,
            **extra_kw,
        )


class _PinnedPoolManager(PoolManager):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = {
            "http": self.pool_classes_by_scheme["http"],
            "https": self.pool_classes_by_scheme["https"],
        }
        # Bind custom connection classes onto pool classes
        http_pool_cls = type(
            "_PinnedHTTPConnectionPool",
            (self.pool_classes_by_scheme["http"],),
            {"ConnectionCls": _PinnedHTTPConnection},
        )
        https_pool_cls = type(
            "_PinnedHTTPSConnectionPool",
            (self.pool_classes_by_scheme["https"],),
            {"ConnectionCls": _PinnedHTTPSConnection},
        )
        self.pool_classes_by_scheme = {
            "http": http_pool_cls,
            "https": https_pool_cls,
        }


class PinnedIPAdapter(HTTPAdapter):
    """HTTPAdapter that connects sockets to the ScopeEngine-validated IP to prevent DNS rebinding."""

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = _PinnedPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


class ScopedHttpClient:
    """HTTP wrapper that enforces ScopeEngine on every request and redirect hop with IP pinning."""

    SENSITIVE_REDIRECT_HEADERS = {"authorization", "proxy-authorization", "cookie"}
    SENSITIVE_COOKIE_TOKENS = ("session", "sess", "auth", "token", "jwt", "sid", "csrf", "xsrf")

    def __init__(
        self,
        scope_engine: ScopeEngine,
        coverage: CoverageTracker | None = None,
        *,
        connect_timeout: float = 10.0,
        read_timeout: float = 20.0,
        max_redirects: int = 5,
        verify_tls: bool = True,
        check_dns: bool = True,
        user_agent: str = "SecurityAnalyzer/0.1.0",
        session: requests.Session | None = None,
        governor: ResourceGovernor | None = None,
        max_response_bytes: int = 5 * 1024 * 1024,
    ) -> None:
        self.scope_engine = scope_engine
        self.coverage = coverage
        self.timeout = (connect_timeout, read_timeout)
        self.max_redirects = max_redirects
        self.verify_tls = verify_tls
        self.check_dns = check_dns
        self.governor = governor
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or max_response_bytes < 1:
            raise ValueError("max_response_bytes must be a positive integer")
        self.max_response_bytes = (
            governor.max_response_bytes if governor is not None else max_response_bytes
        )
        self.session = session or requests.Session()
        # The deployment wrapper installs the network restriction and proxy.
        # Keep environment proxy settings enabled so requests uses that proxy.
        self.session.trust_env = True
        adapter = PinnedIPAdapter()
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.setdefault("User-Agent", user_agent)

    @staticmethod
    def _origin(url: str) -> tuple[str, str, int]:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, host, port

    @classmethod
    def _strip_cross_origin_credentials(
        cls,
        headers: dict[str, str],
        cookie_jar: requests.cookies.RequestsCookieJar,
    ) -> None:
        for key in list(headers.keys()):
            if key.lower() in cls.SENSITIVE_REDIRECT_HEADERS:
                headers.pop(key, None)
        for cookie in list(cookie_jar):
            lowered = cookie.name.lower()
            if any(tok in lowered for tok in cls.SENSITIVE_COOKIE_TOKENS):
                cookie_jar.clear(domain=cookie.domain, path=cookie.path, name=cookie.name)

    def _evaluate_and_pin(self, url: str, headers: dict[str, str], stage_id: str) -> str:
        _PINNED_IP_LOCAL.host_to_ip = {}
        decision = self.scope_engine.evaluate_url(
            url,
            headers=headers,
            check_dns=True,
        )
        if not decision.allowed:
            if self.coverage:
                self.coverage.record_out_of_scope(stage_id, url, decision.reason)
            raise ScopeViolationError(f"Scope violation for {url!r}: {decision.reason}")

        parsed = urlsplit(decision.normalized_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if host and decision.resolved_ips:
            mapping: dict[str, str] = getattr(_PINNED_IP_LOCAL, "host_to_ip", None) or {}
            mapping[host] = decision.resolved_ips[0]
            _PINNED_IP_LOCAL.host_to_ip = mapping
        return decision.normalized_url

    def request(
        self,
        method: str,
        url: str,
        *,
        stage_id: str = "http_client",
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
        json_body: Any = None,
        allow_redirects: bool = True,
    ) -> requests.Response:
        req_headers = dict(headers or {})
        current_url = self._evaluate_and_pin(url, req_headers, stage_id)

        current_method = method.upper()
        current_params = params
        current_data = data
        current_json = json_body
        redirects_followed = 0

        while True:
            req = requests.Request(
                method=current_method,
                url=current_url,
                headers=req_headers,
                params=current_params,
                data=current_data,
                json=current_json,
            )
            prepared = self.session.prepare_request(req)
            final_url = self._evaluate_and_pin(prepared.url, dict(prepared.headers), stage_id)
            if final_url != prepared.url:
                prepared.url = final_url

            request_slot = False
            try:
                if self.governor is not None:
                    self.governor.acquire_request(current_url, timeout=max(self.timeout))
                    request_slot = True
                effective_timeout = self.timeout
                if self.governor is not None:
                    remaining = self.governor.remaining_sec()
                    effective_timeout = (min(self.timeout[0], remaining), min(self.timeout[1], remaining))
                response = self.session.send(
                    prepared,
                    timeout=effective_timeout,
                    verify=self.verify_tls,
                    allow_redirects=False,
                    # Always stream so the body limit applies even when a caller
                    # constructs a client without a shared ResourceGovernor.
                    stream=True,
                )
                body = bytearray()
                max_response_bytes = self.max_response_bytes
                try:
                    for chunk in response.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        if len(body) + len(chunk) > max_response_bytes:
                            response.close()
                            raise ResourceLimitExceeded(
                                f"Response body exceeded configured limit ({max_response_bytes} bytes)"
                            )
                        body.extend(chunk)
                    response._content = bytes(body)
                    response._content_consumed = True
                except Exception:
                    response.close()
                    raise
            finally:
                if request_slot:
                    self.governor.release_request()
                # The adapter only needs the pin while opening the socket. Clear it to
                # prevent a later request on this worker thread inheriting stale state.
                _PINNED_IP_LOCAL.host_to_ip = {}

            if not allow_redirects or response.status_code not in {301, 302, 303, 307, 308}:
                return response

            location = response.headers.get("Location")
            if not location:
                return response

            redirects_followed += 1
            if redirects_followed > self.max_redirects:
                response.close()
                raise ScopeViolationError(f"Exceeded max_redirects ({self.max_redirects}) starting from {url}")

            next_url = urljoin(current_url, location)
            prev_origin = self._origin(current_url)
            next_origin = self._origin(next_url)
            response.close()

            if prev_origin != next_origin:
                self._strip_cross_origin_credentials(req_headers, self.session.cookies)
                req_headers.pop("Host", None)

            current_url = self._evaluate_and_pin(next_url, req_headers, stage_id)

            if response.status_code in {301, 302, 303} and current_method not in {"GET", "HEAD"}:
                current_method = "GET"
                current_data = None
                current_json = None
            current_params = None

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)