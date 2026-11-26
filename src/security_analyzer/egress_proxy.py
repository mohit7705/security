
from __future__ import annotations

import argparse
import select
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from security_analyzer.core.scope_engine import ScopeEngine, ScopePolicy


MAX_REQUEST_BODY = 10 * 1024 * 1024
CONNECT_TIMEOUT = 10
TUNNEL_IDLE_TIMEOUT = 120


def load_scope_engine(scope_path: Path) -> ScopeEngine:
    policy = ScopePolicy.from_yaml(scope_path)
    return ScopeEngine(policy)


class ScopedProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ScopedEgressProxy"
    sys_version = ""

    scope_engine: ScopeEngine
    connect_timeout = CONNECT_TIMEOUT

    def log_message(self, fmt: str, *args) -> None:
        # Do not log full URLs, query parameters, cookies or credentials.
        return

    def _deny(self, status: int, message: str) -> None:
        body = (message + "\n").encode("utf-8", errors="replace")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _validated_destination(self, url: str):
        decision = self.scope_engine.evaluate_url(url, check_dns=True)
        if not decision.allowed:
            return None, decision.reason

        parsed = urlsplit(decision.normalized_url)
        if parsed.scheme not in {"http", "https"}:
            return None, "Unsupported URL scheme"

        if not decision.resolved_ips:
            return None, "Destination has no validated IP addresses"

        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # ScopeEngine validates every returned DNS address. Connect to one
        # of those exact addresses; do not resolve the hostname a second time.
        return (parsed, decision.resolved_ips[0], port), ""

    def do_CONNECT(self) -> None:
        try:
            authority = urlsplit("//" + self.path)
            host = authority.hostname
            explicit_port = authority.port
            port = 443 if explicit_port is None else explicit_port

            # CONNECT uses authority-form only (host[:port]). Reject ignored
            # path/query/fragment components so validation cannot be applied
            # to a different destination than the one actually connected.
            if (
                not host
                or authority.username is not None
                or authority.password is not None
                or authority.path not in {"", "/"}
                or authority.query
                or authority.fragment
                or not 1 <= port <= 65535
            ):
                self._deny(400, "Invalid CONNECT authority")
                return

            authority_host = f"[{host}]" if ":" in host else host
            destination, reason = self._validated_destination(
                f"https://{authority_host}:{port}/"
            )
            if destination is None:
                self._deny(403, f"Destination denied: {reason}")
                return

            parsed, pinned_ip, validated_port = destination
            upstream = socket.create_connection(
                (pinned_ip, validated_port),
                timeout=self.connect_timeout,
            )
        except (OSError, ValueError) as exc:
            self._deny(502, f"CONNECT failed: {type(exc).__name__}")
            return

        # From here on the tunnel is open: never write an HTTP error into it.
        try:
            self.send_response(200, "Connection Established")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            self.wfile.flush()
            self.close_connection = True

            # Forward bytes the client sent early that http.server already buffered.
            self.connection.setblocking(False)
            try:
                pending = self.rfile.peek(65536)
                if pending:
                    upstream.sendall(self.rfile.read(len(pending)))
            except (BlockingIOError, OSError):
                pass
            self._tunnel(self.connection, upstream)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def _tunnel(self, client: socket.socket, upstream: socket.socket) -> None:
        # Blocking sockets: sendall() completes fully instead of raising
        # BlockingIOError when a send buffer fills (large transfers).
        client.settimeout(TUNNEL_IDLE_TIMEOUT)
        upstream.settimeout(TUNNEL_IDLE_TIMEOUT)
        sockets = (client, upstream)

        try:
            while True:
                readable, _, exceptional = select.select(
                    sockets, [], sockets, TUNNEL_IDLE_TIMEOUT
                )

                if exceptional or not readable:
                    break

                for source in readable:
                    destination = upstream if source is client else client
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    destination.sendall(chunk)
        except OSError:
            return

    def _read_body(self) -> bytes:
        transfer_encoding = self.headers.get(
            "Transfer-Encoding", ""
        ).lower()

        # Reject chunked request bodies rather than accidentally forwarding
        # an incomplete or ambiguously framed request.
        if "chunked" in transfer_encoding:
            raise ValueError("Chunked request bodies are not supported")

        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Invalid Content-Length") from exc

        if length < 0 or length > MAX_REQUEST_BODY:
            raise ValueError("Request body exceeds proxy limit")

        return self.rfile.read(length) if length else b""

    def _forward_http_request(self) -> None:
        if self.headers.get("Transfer-Encoding"):
            self._deny(400, "Transfer-Encoding is not supported by this proxy")
            return

        raw_url = self.path
        if not raw_url.startswith(("http://", "https://")):
            self._deny(400, "Proxy requires an absolute HTTP URL")
            return

        destination, reason = self._validated_destination(raw_url)
        if destination is None:
            self._deny(403, f"Destination denied: {reason}")
            return

        parsed, pinned_ip, port = destination

        try:
            body = self._read_body()
        except ValueError as exc:
            self._deny(400, str(exc))
            return

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        headers = []
        for name, value in self.headers.items():
            lowered = name.lower()

            if lowered in {
                "proxy-authorization",
                "proxy-connection",
                "connection",
                "keep-alive",
                "transfer-encoding",
                "upgrade",
            }:
                continue

            headers.append((name, value))

        # Replace Host to avoid forwarding an ambiguous authority.
        headers = [
            (name, value)
            for name, value in headers
            if name.lower() != "host"
        ]
        headers.append(("Host", parsed.netloc))
        headers.append(("Connection", "close"))

        request_head = (
            f"{self.command} {path} HTTP/1.1\r\n"
            + "".join(f"{name}: {value}\r\n" for name, value in headers)
            + "\r\n"
        ).encode("latin-1", errors="replace")

        try:
            with socket.create_connection(
                (pinned_ip, port),
                timeout=self.connect_timeout,
            ) as upstream:
                upstream.settimeout(self.connect_timeout)
                upstream.sendall(request_head)

                if body:
                    upstream.sendall(body)

                while True:
                    chunk = upstream.recv(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)

                self.wfile.flush()

        except OSError:
            # Avoid disclosing internal network or DNS details to the client.
            self._deny(502, "Upstream connection failed")

        self.close_connection = True

    def do_GET(self) -> None:
        self._forward_http_request()

    def do_HEAD(self) -> None:
        self._forward_http_request()

    def do_POST(self) -> None:
        self._forward_http_request()

    def do_PUT(self) -> None:
        self._forward_http_request()

    def do_PATCH(self) -> None:
        self._forward_http_request()

    def do_DELETE(self) -> None:
        self._forward_http_request()

    def do_OPTIONS(self) -> None:
        self._forward_http_request()


class ScopedProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scope-aware HTTP and HTTPS CONNECT egress proxy"
    )
    parser.add_argument(
        "--scope",
        type=Path,
        default=Path("config/scope.yaml"),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3128)
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise SystemExit("Invalid proxy port")

    engine = load_scope_engine(args.scope)

    handler = type(
        "ConfiguredScopedProxyHandler",
        (ScopedProxyHandler,),
        {"scope_engine": engine},
    )

    server = ScopedProxyServer((args.host, args.port), handler)

    print(
        f"[READY] Scoped egress proxy listening on "
        f"{args.host}:{args.port}"
    )

    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
