from __future__ import annotations

import ast
import socket
from pathlib import Path
from unittest.mock import patch

from security_analyzer.core.scope_engine import ScopeEngine, ScopePolicy

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_TEXTUAL_HANDLERS = {"on_mount", "on_tree_node_selected"}


def _engine() -> ScopeEngine:
    return ScopeEngine(ScopePolicy(allowed_domains=["target.example"]))


def _no_dns(*_args, **_kwargs):
    raise socket.gaierror(-2, "Name or service not known")


def test_dns_failure_blocks_by_default(monkeypatch):
    for name in ("SECURITY_ANALYZER_DNS_DELEGATED_TO_PROXY", "SECURITY_ANALYZER_EGRESS_ENFORCED",
                 "SECURITY_ANALYZER_PROXY_TRANSPORT"):
        monkeypatch.delenv(name, raising=False)
    with patch("socket.getaddrinfo", side_effect=_no_dns):
        decision = _engine().evaluate_url("https://target.example/", check_dns=True)
    assert decision.allowed is False and "DNS resolution failed" in decision.reason


def test_dns_failure_is_delegated_only_when_all_three_docker_variables_are_set(monkeypatch):
    monkeypatch.setenv("SECURITY_ANALYZER_DNS_DELEGATED_TO_PROXY", "1")
    monkeypatch.setenv("SECURITY_ANALYZER_EGRESS_ENFORCED", "1")
    with patch("socket.getaddrinfo", side_effect=_no_dns):
        assert _engine().evaluate_url("https://target.example/", check_dns=True).allowed is False
    monkeypatch.setenv("SECURITY_ANALYZER_PROXY_TRANSPORT", "docker")
    with patch("socket.getaddrinfo", side_effect=_no_dns):
        assert _engine().evaluate_url("https://target.example/", check_dns=True).allowed is True


def test_delegation_never_allows_out_of_scope_or_private_ip_literals(monkeypatch):
    monkeypatch.setenv("SECURITY_ANALYZER_DNS_DELEGATED_TO_PROXY", "1")
    monkeypatch.setenv("SECURITY_ANALYZER_EGRESS_ENFORCED", "1")
    monkeypatch.setenv("SECURITY_ANALYZER_PROXY_TRANSPORT", "docker")
    with patch("socket.getaddrinfo", side_effect=_no_dns):
        assert _engine().evaluate_url("https://evil.example/", check_dns=True).allowed is False
    permissive = ScopeEngine(ScopePolicy(allowed_domains=["10.0.0.5"], allow_private_ips=False))
    assert permissive.evaluate_url("https://10.0.0.5/", check_dns=True).allowed is False


def test_delegation_does_not_hide_a_hostname_that_resolves_to_a_private_ip(monkeypatch):
    monkeypatch.setenv("SECURITY_ANALYZER_DNS_DELEGATED_TO_PROXY", "1")
    monkeypatch.setenv("SECURITY_ANALYZER_EGRESS_ENFORCED", "1")
    monkeypatch.setenv("SECURITY_ANALYZER_PROXY_TRANSPORT", "docker")
    private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]
    with patch("socket.getaddrinfo", return_value=private):
        assert _engine().evaluate_url("https://target.example/", check_dns=True).allowed is False


def test_tui_has_no_method_that_textual_would_call_as_an_event_handler():
    """Textual calls any method named on_<event> or _on_<event>. A name like _on_ready is
    triggered by Textual's own Ready event and receives the wrong argument."""
    tree = ast.parse((ROOT / "src/security_analyzer/ui/tui.py").read_text(encoding="utf-8"))
    app = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "QuiverApp")
    names = {n.name for n in app.body if isinstance(n, ast.FunctionDef)}
    handlers = {n for n in names if n.startswith("on_") or n.startswith("_on_")}
    assert handlers <= ALLOWED_TEXTUAL_HANDLERS, handlers - ALLOWED_TEXTUAL_HANDLERS


def test_compose_scanner_service_sets_dns_delegation():
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert 'SECURITY_ANALYZER_DNS_DELEGATED_TO_PROXY: "1"' in text