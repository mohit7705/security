from security_analyzer.core.scope_engine import ScopeEngine, ScopePolicy
from security_analyzer.utils.redaction import scrub_text


def test_redaction_headers_and_ids():
    assert "abcdefghijklmnop12345" not in scrub_text("Authorization: Bearer abcdefghijklmnop12345")
    assert "xyz789" not in scrub_text("Cookie: sid=abc123; csrf=xyz789secret")
    assert scrub_text("order id 1700000000123") == "order id 1700000000123"


def test_excluded_paths_case_and_params():
    engine = ScopeEngine(ScopePolicy(["example.com"], excluded_paths=["/logout", "/admin"]))
    for path in ("/LOGOUT", "/Admin/x", "/logout;x=1", "/%2e%2e/logout"):
        assert not engine.evaluate_url("http://example.com" + path).allowed
    assert engine.evaluate_url("http://example.com/ok").allowed


def test_cgnat_blocked():
    engine = ScopeEngine(
        ScopePolicy(["example.com"], allowed_cidrs=["203.0.113.0/24"])
    )
    assert not engine.evaluate_url("http://100.64.0.1/").allowed
