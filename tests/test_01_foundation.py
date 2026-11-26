from __future__ import annotations


# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step1_foundation.py
# -----------------------------------------------------------------------------

import socket as src1_socket
from pathlib import Path as src1_Path
from types import SimpleNamespace as src1_SimpleNamespace
from unittest.mock import patch as src1_patch
import pytest as src1_pytest
from security_analyzer.authentication.identity_context import IdentityProfile as src1_IdentityProfile, IdentityContext as src1_IdentityContext
from security_analyzer.core.coverage_tracker import CoverageTracker as src1_CoverageTracker
from security_analyzer.core.exceptions import ConfigurationError as src1_ConfigurationError, ScopeViolationError as src1_ScopeViolationError, WorkspaceBoundaryError as src1_WorkspaceBoundaryError
from security_analyzer.core.orchestrator import ExecutionContext as src1_ExecutionContext, PipelineOrchestrator as src1_PipelineOrchestrator
from security_analyzer.core.scope_engine import ScopeEngine as src1_ScopeEngine, ScopePolicy as src1_ScopePolicy
from security_analyzer.core.stage_registry import ArtifactSpec as src1_ArtifactSpec, StageDefinition as src1_StageDefinition, StageResult as src1_StageResult, StageStatus as src1_StageStatus
from security_analyzer.core.workspace import WorkspaceManager as src1_WorkspaceManager
from security_analyzer.discovery.domain_enumeration import run_domain_enumeration as src1_run_domain_enumeration
from security_analyzer.discovery.endpoint_normalizer import normalize_endpoint as src1_normalize_endpoint
from security_analyzer.reporting.markdown_renderer import render_markdown_report as src1_render_markdown_report
from security_analyzer.scanners.nuclei_runner import run_nuclei_assessment as src1_run_nuclei_assessment
from security_analyzer.scanners.tls_posture_scanner import _inspect_tls_endpoint as src1__inspect_tls_endpoint
from security_analyzer.utils.http_client import ScopedHttpClient as src1_ScopedHttpClient, _get_pinned_ip as src1__get_pinned_ip
from security_analyzer.verification.ai_triage import OptionalAiTriage as src1_OptionalAiTriage

def test_scope_hardening_credentials_and_path_boundaries() -> None:
    policy = src1_ScopePolicy(allowed_domains=['authorized.example'], excluded_paths=['/admin'], allow_private_ips=False)
    engine = src1_ScopeEngine(policy)
    assert engine.evaluate_url('https://authorized.example/').allowed is True
    assert engine.evaluate_url('https://sub.authorized.example/api').allowed is True
    assert engine.evaluate_url('https://evil-authorized.example/').allowed is False
    cred_decision = engine.evaluate_url('https://user:pass@authorized.example/private')
    assert cred_decision.allowed is False
    assert 'credentials' in cred_decision.reason.lower()
    assert engine.evaluate_url('https://authorized.example/admin').allowed is False
    assert engine.evaluate_url('https://authorized.example/admin/users').allowed is False
    assert engine.evaluate_url('https://authorized.example/administrator').allowed is True
    spoof = engine.evaluate_url('https://evil.example/api', headers={'Host': 'authorized.example'})
    assert spoof.allowed is False

def test_private_multicast_reserved_and_dns_blocking_across_all_paths(tmp_path: Path) -> None:
    private_ok_engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['lab.example'], allow_private_ips=True))
    for bad_ip in ('224.0.0.1', '0.0.0.0', '240.0.0.1'):
        with src1_patch('socket.getaddrinfo', return_value=[(src1_socket.AF_INET, src1_socket.SOCK_STREAM, 6, '', (bad_ip, 443))]):
            dec = private_ok_engine.evaluate_url('https://lab.example/', check_dns=True)
            assert dec.allowed is False
    strict_engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['target.example'], allow_private_ips=False))
    ws = src1_WorkspaceManager(project_root=tmp_path)
    ws.init_scan('https://target.example')
    cov = src1_CoverageTracker(ws)
    with src1_patch('socket.getaddrinfo', return_value=[(src1_socket.AF_INET, src1_socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]):
        anon_client = src1_ScopedHttpClient(strict_engine, cov)
        with src1_pytest.raises(src1_ScopeViolationError):
            anon_client.get('https://target.example/api')
        auth_ctx = src1_IdentityContext(src1_IdentityProfile(identity_id='user_a', role='user', auth_method='bearer_token', token='tok_123'))
        auth_client = auth_ctx.create_http_client(strict_engine, cov)
        with src1_pytest.raises(src1_ScopeViolationError):
            auth_client.get('https://target.example/api')
        with src1_pytest.raises(src1_ScopeViolationError):
            src1__inspect_tls_endpoint('https://target.example/', strict_engine)
        ctx = src1_ExecutionContext(target='https://target.example/', workspace=ws, scope_engine=strict_engine, coverage=cov, config={})
        with src1_pytest.raises(src1_ScopeViolationError):
            src1_run_domain_enumeration(ctx, src1_StageDefinition('domain_enumeration', 'Domain Enum', 'discovery'))
        with src1_patch('shutil.which', return_value='/usr/bin/nuclei'):
            res = src1_run_nuclei_assessment(ctx, src1_StageDefinition('nuclei_assessment', 'Nuclei', 'analysis'))
            assert res.status == src1_StageStatus.PARTIAL
            assert ws.read_json('analysis/nuclei_findings.json')['targets_scanned'] == []

def test_dns_rebinding_ip_pinning_and_redirect_to_private_ip(tmp_path: Path) -> None:
    strict_engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['rebind.example', 'redir.example'], allow_private_ips=False))
    ws = src1_WorkspaceManager(project_root=tmp_path)
    ws.init_scan('https://rebind.example')
    cov = src1_CoverageTracker(ws)
    client = src1_ScopedHttpClient(strict_engine, cov)
    dns_answers = [[(src1_socket.AF_INET, src1_socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))], [(src1_socket.AF_INET, src1_socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]]

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == 'rebind.example':
            return dns_answers.pop(0) if len(dns_answers) > 1 else dns_answers[0]
        if host == 'redir.example':
            return [(src1_socket.AF_INET, src1_socket.SOCK_STREAM, 6, '', ('10.0.0.8', 443))]
        raise src1_socket.gaierror('unknown')

    def fake_send(prepared, **kwargs):
        assert src1__get_pinned_ip('rebind.example') == '93.184.216.34'
        resp = src1_SimpleNamespace(status_code=302, headers={'Location': 'https://redir.example/internal'}, close=lambda: None)
        return resp
    with src1_patch('socket.getaddrinfo', side_effect=fake_getaddrinfo), src1_patch.object(client.session, 'send', side_effect=fake_send):
        with src1_pytest.raises(src1_ScopeViolationError):
            client.get('https://rebind.example/start')

def test_pii_redaction_ai_triage_header_and_markdown_escaping() -> None:
    engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['authorized.example']))
    ep = src1_normalize_endpoint('https://authorized.example/users?email=alice@example.com&phone=%2B15551234567&user_id=9912&page=2', scope_engine=engine)
    assert ep is not None
    assert 'alice@example.com' not in ep.canonical_url
    assert '5551234567' not in ep.canonical_url
    assert '9912' not in ep.canonical_url
    assert 'page=2' in ep.canonical_url
    triage_bad = src1_OptionalAiTriage({'ai_triage': {'enabled': True, 'provider': 'gemini', 'endpoint_url': 'https://evil.example/steal'}})
    with src1_pytest.raises(src1_ConfigurationError):
        triage_bad._call_gemini('secret_key', 'prompt')
    captured: dict[str, object] = {}

    def fake_post(url, headers=None, json=None, timeout=None, **kwargs):
        captured['url'] = url
        captured['headers'] = headers
        return src1_SimpleNamespace(raise_for_status=lambda: None, json=lambda: {'candidates': [{'content': {'parts': [{'text': '{"rationale":"ok","remediation":"fix","recommend_human_review":false}'}]}}]})
    triage_ok = src1_OptionalAiTriage({'ai_triage': {'enabled': True, 'provider': 'gemini'}})
    with src1_patch('requests.post', side_effect=fake_post):
        triage_ok._call_gemini('AIza_TEST_KEY', 'prompt')
    assert 'AIza_TEST_KEY' not in str(captured['url'])
    assert captured['headers']['x-goog-api-key'] == 'AIza_TEST_KEY'
    md = src1_render_markdown_report({'scan_id': 's1', 'target': 'https://authorized.example', 'generated_at': '2026-11-26T00:00:00Z', 'summary': {'overall_status': 'SUCCESS', 'severity_counts': {}}, 'scope_snapshot': {'fingerprint': 'abcdef1234567890'}, 'coverage_summary': {'stages': {}, 'skipped_checks': []}, 'confirmed_findings': [{'finding_id': 'f1', 'severity': 'HIGH', 'verdict': 'CONFIRMED', 'confidence': 0.95, 'category': 'xss', 'title': '[Injected Link](https://evil.example) <script>alert(1)</script>', 'location': 'https://authorized.example/test', 'summary': '# Fake Heading | pipe', 'evidence': []}], 'review_queue': [], 'suppressed_false_positives': []})
    assert '<script>' not in md
    assert '[Injected Link](https://evil.example)' not in md

def test_workspace_enforces_single_output_folder(tmp_path: Path) -> None:
    ws = src1_WorkspaceManager(project_root=tmp_path)
    scan_dir = ws.init_scan('https://authorized.example')
    assert scan_dir.parent == (tmp_path / 'output').resolve()
    with src1_pytest.raises(src1_WorkspaceBoundaryError):
        ws.resolve_path('../escape.json')

def test_orchestrator_partial_propagation_and_fingerprint_resume(tmp_path: Path) -> None:
    ws = src1_WorkspaceManager(project_root=tmp_path)
    ws.init_scan('https://authorized.example')
    engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['authorized.example']))
    cov = src1_CoverageTracker(ws)
    defs = (src1_StageDefinition(stage_id='stage_a', title='Stage A', phase='discovery', artifacts=(src1_ArtifactSpec('discovery/a.json', ('schema_version', 'scan_id', 'stage_id', 'items')),)), src1_StageDefinition(stage_id='stage_b', title='Stage B', phase='analysis', dependencies=('stage_a',), artifacts=(src1_ArtifactSpec('analysis/b.json', ('schema_version', 'scan_id', 'stage_id', 'count')),)))
    orch = src1_PipelineOrchestrator(target='https://authorized.example', workspace=ws, scope_engine=engine, coverage=cov, config={'limit': 10}, definitions=defs)
    run_counts = {'stage_a': 0, 'stage_b': 0}

    def run_a(ctx, sdef):
        run_counts['stage_a'] += 1
        ctx.workspace.write_json_atomic('discovery/a.json', {'schema_version': '1.0', 'scan_id': ctx.workspace.scan_id, 'stage_id': sdef.stage_id, 'items': ['https://authorized.example/api/v1']})
        return src1_StageResult(stage_id=sdef.stage_id, status=src1_StageStatus.PARTIAL, summary='Partial crawl')

    def run_b(ctx, sdef):
        run_counts['stage_b'] += 1
        upstream = ctx.upstream_artifacts['stage_a']['discovery/a.json']
        ctx.workspace.write_json_atomic('analysis/b.json', {'schema_version': '1.0', 'scan_id': ctx.workspace.scan_id, 'stage_id': sdef.stage_id, 'count': len(upstream['items'])})
        return src1_StageResult(stage_id=sdef.stage_id, status=src1_StageStatus.SUCCESS, summary='Done')
    orch.register_runner('stage_a', run_a)
    orch.register_runner('stage_b', run_b)
    overall = orch.run(resume=False)
    assert overall == src1_StageStatus.PARTIAL
    assert run_counts == {'stage_a': 1, 'stage_b': 1}
    assert ws.read_json('analysis/b.json')['count'] == 1
    resumed = orch.run(resume=True)
    assert resumed == src1_StageStatus.PARTIAL
    assert run_counts == {'stage_a': 2, 'stage_b': 1}

def test_pinned_http_connection_uses_validated_socket_ip() -> None:
    from security_analyzer.utils import http_client
    captured: dict[str, object] = {}

    def fake_create_connection(address, timeout, **kwargs):
        captured['address'] = address
        captured['timeout'] = timeout
        return object()
    http_client._PINNED_IP_LOCAL.host_to_ip = {'pin.example': '93.184.216.34'}
    connection = http_client._PinnedHTTPConnection('pin.example', 443, timeout=3)
    with src1_patch.object(http_client.urllib3_connection, 'create_connection', side_effect=fake_create_connection):
        connection._new_conn()
    assert captured['address'] == ('93.184.216.34', 443)
    http_client._PINNED_IP_LOCAL.host_to_ip = {}

def test_har_json_body_and_url_credentials_are_redacted(tmp_path: Path) -> None:
    from security_analyzer.browser.har_recorder import HarRecorder
    ws = src1_WorkspaceManager(project_root=tmp_path)
    ws.init_scan('https://authorized.example')
    recorder = HarRecorder(ws)
    har = recorder.prepare_path()
    har.write_text('{"log":{"entries":[{"request":{"url":"https://alice:secret@authorized.example/api?email=alice@example.com","postData":{"mimeType":"application/json","text":"{\\"access_token\\":\\"abc123\\",\\"page\\":2}"}},"response":{"headers":[],"content":{"mimeType":"application/octet-stream","text":"raw-binary-secret"}}}]}}', encoding='utf-8')
    recorder.redact_sensitive_data()
    saved = har.read_text(encoding='utf-8')
    assert 'alice:secret' not in saved
    assert 'alice@example.com' not in saved
    assert 'abc123' not in saved
    assert 'raw-binary-secret' not in saved
    assert '[REDACTED]' in saved

def test_enforce_url_requires_dns_and_blocks_ipv4_mapped_loopback() -> None:
    engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['target.example'], allow_private_ips=False))
    assert engine.evaluate_url('https://target.example/').allowed is True
    with src1_patch('socket.getaddrinfo', return_value=[(src1_socket.AF_INET, src1_socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]):
        with src1_pytest.raises(src1_ScopeViolationError):
            engine.enforce_url('https://target.example/')
    mapped = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['::ffff:127.0.0.1'], allow_private_ips=False))
    decision = mapped.evaluate_url('https://[::ffff:127.0.0.1]/', check_dns=True)
    assert decision.allowed is False

def test_screenshot_capture_fails_closed_when_masking_fails(tmp_path: Path) -> None:
    from security_analyzer.browser.screenshot_capture import ScreenshotCapture
    ws = src1_WorkspaceManager(project_root=tmp_path)
    ws.init_scan('https://authorized.example')

    class BrokenPage:

        def evaluate(self, script):
            raise RuntimeError('masking unavailable')

        def screenshot(self, **kwargs):
            raise AssertionError('screenshot must not be taken after masking failure')
    capture = ScreenshotCapture(ws)
    with src1_pytest.raises(RuntimeError):
        capture.capture(BrokenPage(), 'https://authorized.example/profile?token=secret')
    assert capture.records == []
    assert not ws.resolve_path('browser/screenshots/page_001.png').exists()

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step1_security_regressions.py
# -----------------------------------------------------------------------------

import socket as src2_socket
import threading as src2_threading
from http.server import BaseHTTPRequestHandler as src2_BaseHTTPRequestHandler, ThreadingHTTPServer as src2_ThreadingHTTPServer
from unittest.mock import patch as src2_patch
import requests as src2_requests
from security_analyzer.core.coverage_tracker import CoverageTracker as src2_CoverageTracker
from security_analyzer.core.orchestrator import ExecutionContext as src2_ExecutionContext
from security_analyzer.core.scope_engine import ScopeEngine as src2_ScopeEngine, ScopePolicy as src2_ScopePolicy
from security_analyzer.core.stage_registry import StageDefinition as src2_StageDefinition, StageStatus as src2_StageStatus
from security_analyzer.egress_proxy import ScopedProxyHandler as src2_ScopedProxyHandler, ScopedProxyServer as src2_ScopedProxyServer
from security_analyzer.scanners.nuclei_runner import run_nuclei_assessment as src2_run_nuclei_assessment
from security_analyzer.core.workspace import WorkspaceManager as src2_WorkspaceManager

class src2__OriginHandler(src2_BaseHTTPRequestHandler):
    request_count = 0

    def do_GET(self):
        type(self).request_count += 1
        body = b'origin-ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

def src2__start_servers():
    origin = src2_ThreadingHTTPServer(('127.0.0.1', 0), src2__OriginHandler)
    src2__OriginHandler.request_count = 0
    origin_thread = src2_threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    port = origin.server_address[1]
    engine = src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['authorized.test'], allowed_ports=[port], excluded_paths=['/private'], allow_private_ips=True))
    handler = type('TestScopedProxyHandler', (src2_ScopedProxyHandler,), {'scope_engine': engine})
    proxy = src2_ScopedProxyServer(('127.0.0.1', 0), handler)
    proxy_thread = src2_threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    return (origin, proxy, port)

def src2__close_servers(origin, proxy):
    proxy.shutdown()
    proxy.server_close()
    origin.shutdown()
    origin.server_close()

def test_proxy_uses_scope_validated_ip_for_authorized_hostname():
    origin, proxy, origin_port = src2__start_servers()
    original_getaddrinfo = src2_socket.getaddrinfo

    def resolve(host, port, *args, **kwargs):
        if host == 'authorized.test':
            return original_getaddrinfo('127.0.0.1', port, *args, **kwargs)
        return original_getaddrinfo(host, port, *args, **kwargs)
    try:
        with src2_patch('socket.getaddrinfo', side_effect=resolve):
            session = src2_requests.Session()
            session.trust_env = False
            response = session.get(f'http://authorized.test:{origin_port}/ok', proxies={'http': f'http://127.0.0.1:{proxy.server_address[1]}'}, timeout=3)
        assert response.status_code == 200
        assert response.content == b'origin-ok'
        assert src2__OriginHandler.request_count == 1
    finally:
        src2__close_servers(origin, proxy)

def test_proxy_denies_out_of_scope_host_and_excluded_path_before_origin_request():
    origin, proxy, origin_port = src2__start_servers()
    proxy_url = f'http://127.0.0.1:{proxy.server_address[1]}'
    try:
        for url in (f'http://outside.test:{origin_port}/ok', f'http://authorized.test:{origin_port}/private/secret'):
            session = src2_requests.Session()
            session.trust_env = False
            response = session.get(url, proxies={'http': proxy_url}, timeout=3)
            assert response.status_code == 403
        assert src2__OriginHandler.request_count == 0
    finally:
        src2__close_servers(origin, proxy)

def test_nuclei_yaml_flag_cannot_enable_scanning_without_runtime_proxy(tmp_path, monkeypatch):
    monkeypatch.delenv('SECURITY_ANALYZER_PROXY', raising=False)
    monkeypatch.delenv('SECURITY_ANALYZER_EGRESS_ENFORCED', raising=False)
    workspace = src2_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://authorized.test')
    engine = src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['authorized.test']))
    coverage = src2_CoverageTracker(workspace)
    ctx = src2_ExecutionContext(target='https://authorized.test/', workspace=workspace, scope_engine=engine, coverage=coverage, config={'nuclei': {'egress_enforced': True}})
    monkeypatch.setattr('security_analyzer.scanners.nuclei_runner.shutil.which', lambda _: '/usr/bin/nuclei')
    result = src2_run_nuclei_assessment(ctx, src2_StageDefinition('nuclei_assessment', 'Nuclei', 'analysis'))
    assert result.status == src2_StageStatus.PARTIAL
    assert 'proxy is not configured' in result.summary
    assert workspace.read_json('analysis/nuclei_findings.json')['targets_scanned'] == []

def test_ffuf_requires_runtime_proxy(monkeypatch):
    from security_analyzer.discovery.directory_discovery import _run_ffuf
    monkeypatch.delenv('SECURITY_ANALYZER_PROXY', raising=False)
    monkeypatch.setattr('security_analyzer.discovery.directory_discovery.shutil.which', lambda _: '/usr/bin/ffuf')
    hits, skipped, reason = _run_ffuf('https://authorized.test', [], workspace=None, scope_engine=None, coverage=None, stage_id='directory_discovery', check_dns=False, max_threads=1)
    assert hits == []
    assert skipped == 0
    assert 'proxy is unavailable' in reason

def test_nmap_is_not_launched_without_a_scoped_tcp_transport(monkeypatch):
    from security_analyzer.discovery.http_probing import _run_nmap

    class NeverRunGovernor:

        def run_process(self, *_args, **_kwargs):
            raise AssertionError('Nmap must not attempt direct TCP egress')
    monkeypatch.setattr('security_analyzer.discovery.http_probing.shutil.which', lambda name: '/usr/bin/nmap' if name == 'nmap' else None)
    results, reason = _run_nmap(['authorized.example'], timeout_sec=30, governor=NeverRunGovernor())
    assert results == {}
    assert 'direct TCP scanning is not supported' in reason

def test_whois_is_not_launched_without_a_scoped_tcp_transport(monkeypatch):
    from security_analyzer.scanners.dns_infrastructure_scanner import _query_whois_record

    class NeverRunGovernor:

        def run_process(self, *_args, **_kwargs):
            raise AssertionError('WHOIS must not attempt direct TCP/43 egress')
    result, reason = _query_whois_record('authorized.example', NeverRunGovernor(), scope_engine=src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['authorized.example'])))
    assert result == {}
    assert 'raw TCP/43 is not supported' in reason

# -----------------------------------------------------------------------------
# Consolidated from: tests/security/test_step1_boundary.py
# -----------------------------------------------------------------------------

import os as src3_os
import socket as src3_socket
import time as src3_time
from pathlib import Path as src3_Path
from unittest.mock import patch as src3_patch
from security_analyzer.browser.browser_manager import ScopedBrowserManager as src3_ScopedBrowserManager
from security_analyzer.core.retention import cleanup_expired as src3_cleanup_expired, find_expired_scans as src3_find_expired_scans
from security_analyzer.core.scope_engine import ScopeEngine as src3_ScopeEngine, ScopePolicy as src3_ScopePolicy
from security_analyzer.reporting.html_renderer import HtmlRenderer as src3_HtmlRenderer
from security_analyzer.reporting.markdown_renderer import MarkdownRenderer as src3_MarkdownRenderer
from security_analyzer.utils.redaction import scrub_text as src3_scrub_text
src3_REPO_ROOT = src3_Path(__file__).resolve().parents[1]

def src3__resolve_to(ip: str):
    return [(src3_socket.AF_INET, src3_socket.SOCK_STREAM, 6, '', (ip, 443))]

def test_hostname_resolving_to_private_ip_is_blocked_when_dns_check_on():
    engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['target.example'], allow_private_ips=False))
    for ip in ('127.0.0.1', '10.0.0.5', '192.168.1.10'):
        with src3_patch('socket.getaddrinfo', return_value=src3__resolve_to(ip)):
            assert engine.evaluate_url('https://target.example/', check_dns=True).allowed is False

def test_special_addresses_blocked_even_when_private_ips_allowed():
    engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['lab.example'], allow_private_ips=True))
    for ip in ('0.0.0.0', '224.0.0.1', '240.0.0.1'):
        with src3_patch('socket.getaddrinfo', return_value=src3__resolve_to(ip)):
            assert engine.evaluate_url('https://lab.example/', check_dns=True).allowed is False

def test_out_of_scope_domain_is_blocked():
    engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['target.example']))
    assert engine.evaluate_url('https://evil.example/').allowed is False

def test_browser_popup_request_is_checked_by_scope_gate():

    class Request:
        url = 'https://evil.example/popup'
        headers = {}

    class Route:
        request = Request()
        aborted = False

        def abort(self, _reason):
            self.aborted = True

        def continue_(self, **_kwargs):
            raise AssertionError('Out-of-scope popup request must not continue')
    manager = object.__new__(src3_ScopedBrowserManager)
    manager.scope_engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['target.example']))
    manager.check_dns = False
    manager.blocked_requests = []
    manager.coverage = None
    route = Route()
    manager._intercept_route(route)
    assert route.aborted
    assert manager.blocked_requests[0]['url'] == Request.url

def test_scrub_text_masks_email_phone_and_tokens():
    text = 'mail bob@example.com call +91 98765 43210 token Bearer abcdef123456789'
    cleaned = src3_scrub_text(text)
    assert 'bob@example.com' not in cleaned
    assert '98765' not in cleaned
    assert 'abcdef123456789' not in cleaned

def test_report_renderers_redact_finding_text_before_escaping():
    secret = 'alice@example.com Bearer fake-token-123456789'
    report = {'confirmed_findings': [{'severity': 'HIGH', 'title': 'Sensitive test finding', 'finding_id': 'test-1', 'verdict': 'CONFIRMED', 'confidence': 0.9, 'category': 'test', 'description': secret, 'remediation': secret, 'resolved_evidence': [{'summary': secret, 'artifact_path': 'evidence.txt'}]}]}
    for rendered in (src3_MarkdownRenderer().render(report), src3_HtmlRenderer().render(report)):
        assert 'alice@example.com' not in rendered
        assert 'fake-token-123456789' not in rendered

def test_ignore_files_exist_and_cover_secrets():
    for name in ('.gitignore', '.dockerignore'):
        content = (src3_REPO_ROOT / name).read_text(encoding='utf-8')
        for required in ('.env', 'secrets/', 'output/', '__pycache__/'):
            assert required in content, f'{name} must contain {required}'
    assert (src3_REPO_ROOT / '.env.example').is_file()

def test_no_bytecode_in_source_tree():
    leftovers = [path for path in (src3_REPO_ROOT / 'src').rglob('*.pyc')]
    assert leftovers == []

def src3__make_scan(root: Path, name: str, age_days: int) -> src3_Path:
    scan = root / name
    scan.mkdir(parents=True)
    state = scan / 'scan_state.json'
    state.write_text('{}', encoding='utf-8')
    old = src3_time.time() - age_days * 86400
    src3_os.utime(state, (old, old))
    return scan

def test_cleanup_dry_run_keeps_data_and_execute_deletes_with_audit(tmp_path: Path):
    output_root = tmp_path / 'output'
    secrets_root = tmp_path / 'secrets'
    old_scan = src3__make_scan(output_root, 'old_scan', age_days=40)
    new_scan = src3__make_scan(output_root, 'new_scan', age_days=1)
    (secrets_root / 'old_scan').mkdir(parents=True)
    assert [path.name for path in src3_find_expired_scans(output_root, 30)] == ['old_scan']
    dry = src3_cleanup_expired(output_root, secrets_root, 30, execute=False)
    assert old_scan.exists() and (secrets_root / 'old_scan').exists()
    assert dry['executed'] is False
    real = src3_cleanup_expired(output_root, secrets_root, 30, execute=True)
    assert real['executed'] is True
    assert not old_scan.exists()
    assert not (secrets_root / 'old_scan').exists()
    assert new_scan.exists()
    audit_lines = (output_root / 'retention_audit.jsonl').read_text(encoding='utf-8').splitlines()
    assert any(('"action": "deleted"' in line for line in audit_lines))


# Step 1 shared read-only request safety regression tests.
def test_shared_request_safety_blocks_destructive_paths_and_write_methods() -> None:
    from security_analyzer.utils.request_safety import is_destructive_request

    blocked = (
        "https://authorized.example/account/logout",
        "https://authorized.example/api/unsubscribe",
        "https://authorized.example/api/orders/submit",
        "https://authorized.example/api/reset-password",
        "https://authorized.example/api/confirm-payment",
        "https://authorized.example/%2564elete/account",
    )
    for url in blocked:
        assert is_destructive_request(url, method="GET"), url

    assert is_destructive_request("https://authorized.example/api/orders/123", method="POST")
    assert is_destructive_request("https://authorized.example/api/orders/123", method="DELETE")
    assert is_destructive_request(
        "https://authorized.example/account/preferences",
        method="GET",
        label_hint="Delete this account",
    )

    assert not is_destructive_request("https://authorized.example/api/orders/123", method="GET")
    assert not is_destructive_request("https://authorized.example/repayment-history", method="GET")
    # Query parameter values must not cause a path-policy false positive.
    assert not is_destructive_request(
        "https://authorized.example/search?q=delete",
        method="GET",
    )


def test_repository_secret_ignore_files_exist_and_are_non_secret() -> None:
    root = src1_Path(__file__).resolve().parents[1]
    gitignore = (root / ".gitignore").read_text(encoding="utf-8")
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    env_example = (root / ".env.example").read_text(encoding="utf-8")

    for required in (".env", "secrets/", "output/", "__pycache__/"):
        assert required in gitignore
        assert required in dockerignore

    assert "USER_A_PASSWORD=" in env_example
    assert "USER_B_TOKEN=" in env_example
    assert "real-" not in env_example.lower()
