from __future__ import annotations


# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step4_hardening_contracts.py
# -----------------------------------------------------------------------------

import os as src1_os
import stat as src1_stat
import threading as src1_threading
from http.server import BaseHTTPRequestHandler as src1_BaseHTTPRequestHandler, ThreadingHTTPServer as src1_ThreadingHTTPServer
import sys as src1_sys
from pathlib import Path as src1_Path
from types import SimpleNamespace as src1_SimpleNamespace
import pytest as src1_pytest
import requests as src1_requests
from security_analyzer.core.coverage_tracker import CoverageTracker as src1_CoverageTracker
from security_analyzer.core.resource_governor import ProcessResult as src1_ProcessResult, ResourceGovernor as src1_ResourceGovernor, ResourceLimitExceeded as src1_ResourceLimitExceeded
from security_analyzer.core.scope_engine import ScopeDecision as src1_ScopeDecision, ScopeEngine as src1_ScopeEngine, ScopePolicy as src1_ScopePolicy
from security_analyzer.core.stage_registry import StageDefinition as src1_StageDefinition, StageStatus as src1_StageStatus
from security_analyzer.core.workspace import WorkspaceManager as src1_WorkspaceManager
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory as src1_UnifiedEndpointInventory
from security_analyzer.models.finding import FindingRecord as src1_FindingRecord, Severity as src1_Severity, Verdict as src1_Verdict
from security_analyzer.verification.evidence_store import EvidenceStore as src1_EvidenceStore, sanitize_evidence_value as src1_sanitize_evidence_value
from security_analyzer.verification.poc_replayer import DeterministicPocReplayer as src1_DeterministicPocReplayer

def src1__replayer(tmp_path: Path):
    workspace = src1_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://example.com/')
    engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['example.com'], allowed_ports=[443]))
    engine.evaluate_url = lambda url, **kwargs: src1_ScopeDecision(True, url, 'controlled unit-test scope', ('93.184.216.34',))
    coverage = src1_CoverageTracker(workspace)
    inventory = src1_UnifiedEndpointInventory(workspace)
    replayer = src1_DeterministicPocReplayer(workspace=workspace, scope_engine=engine, coverage=coverage, inventory=inventory, auth_manager=None)
    return (workspace, engine, coverage, inventory, replayer)

def src1__response(status: int, body: bytes, content_type: str='application/json', headers=None):
    response = src1_requests.Response()
    response.status_code = status
    response._content = body
    response.headers.update({'Content-Type': content_type})
    if headers:
        response.headers.update(headers)
    response.url = 'https://example.com/resource'
    return response

def test_resource_governor_rejects_non_finite_limits():
    for value in (float('nan'), float('inf'), float('-inf')):
        with src1_pytest.raises(ValueError):
            src1_ResourceGovernor({'max_scan_duration_sec': value})

def test_resource_governor_streams_stdout_lines_before_exit():
    governor = src1_ResourceGovernor({'max_external_processes': 2, 'max_concurrent_processes': 1})
    lines: list[str] = []
    result = governor.run_process(['/bin/sh', '-c', "printf 'first\\n'; sleep 0.1; printf 'second\\n'"], timeout_sec=3, inactivity_timeout_sec=2, stdout_line_callback=lines.append)
    assert result.returncode == 0
    assert lines == ['first', 'second']
    assert result.cancelled is False
    assert result.inactivity_timed_out is False

def test_resource_governor_inactivity_watchdog_terminates_quiet_process():
    governor = src1_ResourceGovernor({'max_external_processes': 2, 'max_concurrent_processes': 1})
    result = governor.run_process(['/bin/sh', '-c', 'sleep 2'], timeout_sec=4, inactivity_timeout_sec=0.15)
    assert result.inactivity_timed_out is True
    assert result.returncode == 126

def test_resource_governor_caps_combined_stdout_and_stderr():
    governor = src1_ResourceGovernor({'max_external_processes': 2, 'max_concurrent_processes': 1, 'max_process_output_bytes': 128})
    result = governor.run_process(['/bin/sh', '-c', "printf '%1000s' x; printf '%1000s' y >&2"], timeout_sec=3)
    assert result.output_truncated is True
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 128
    assert result.returncode == 125

def test_evidence_store_directory_is_private_and_non_finite_values_are_sanitized(tmp_path):
    workspace = src1_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://example.com/')
    with src1_EvidenceStore(workspace):
        pass
    mode = src1_stat.S_IMODE((workspace.scan_dir / 'verification').stat().st_mode)
    assert mode == 448
    assert src1_sanitize_evidence_value({'score': float('nan'), 'nested': [float('inf')]}) == {'score': None, 'nested': [None]}

def test_cors_header_reflection_is_not_confirmed_without_browser_readability_proof(tmp_path):
    workspace, _, _, _, replayer = src1__replayer(tmp_path)
    response = src1__response(200, b'{"private":"value"}', headers={'Access-Control-Allow-Origin': 'https://untrusted-origin.example', 'Access-Control-Allow-Credentials': 'true'})
    replayer._client_for_identity = lambda _identity: src1_SimpleNamespace(get=lambda *args, **kwargs: response)
    finding = src1_FindingRecord(title='CORS reflection', category='cors_origin_reflection', severity=src1_Severity.HIGH, verdict=src1_Verdict.LIKELY, confidence=0.8, asset_id='asset_1', endpoint_id='endpoint_1')
    outcome = replayer._replay_cors(finding, 'https://example.com/resource', stage_id='evidence_verification')
    assert outcome.verdict == src1_Verdict.NEEDS_HUMAN_REVIEW
    assert outcome.telemetry['requires_browser_validation'] is True
    assert outcome.evidence_record is not None

def test_generic_http_200_does_not_confirm_nuclei_template_match(tmp_path):
    _, _, _, _, replayer = src1__replayer(tmp_path)
    response = src1__response(200, b'ordinary page', 'text/html')
    replayer._client_for_identity = lambda _identity: src1_SimpleNamespace(get=lambda *args, **kwargs: response)
    finding = src1_FindingRecord(title='Scanner candidate', category='nuclei_template_match', severity=src1_Severity.MEDIUM, verdict=src1_Verdict.LIKELY, confidence=0.7, asset_id='asset_1', endpoint_id='endpoint_1')
    outcome = replayer._replay_http_exposure(finding, 'https://example.com/resource', stage_id='evidence_verification')
    assert outcome.verdict == src1_Verdict.NEEDS_HUMAN_REVIEW

def test_source_map_exposure_requires_embedded_source_content(tmp_path):
    _, _, _, _, replayer = src1__replayer(tmp_path)
    finding = src1_FindingRecord(title='Source map exposed', category='exposed_source_map', severity=src1_Severity.MEDIUM, verdict=src1_Verdict.LIKELY, confidence=0.7, asset_id='asset_1', endpoint_id='endpoint_1')
    empty_map = src1__response(200, b'{"version":3,"sources":["app.js"],"sourcesContent":[null]}')
    replayer._client_for_identity = lambda _identity: src1_SimpleNamespace(get=lambda *args, **kwargs: empty_map)
    outcome = replayer._replay_http_exposure(finding, 'https://example.com/app.js.map', stage_id='evidence_verification')
    assert outcome.verdict == src1_Verdict.FALSE_POSITIVE
    exposed_map = src1__response(200, b'{"version":3,"sources":["app.js"],"sourcesContent":["const x = 1;"]}')
    replayer._client_for_identity = lambda _identity: src1_SimpleNamespace(get=lambda *args, **kwargs: exposed_map)
    outcome = replayer._replay_http_exposure(finding, 'https://example.com/app.js.map', stage_id='evidence_verification')
    assert outcome.verdict == src1_Verdict.CONFIRMED

def test_posture_finding_without_verified_source_is_not_confirmed(tmp_path):
    _, _, _, _, replayer = src1__replayer(tmp_path)
    finding = src1_FindingRecord(title='Missing HSTS', category='missing_strict_transport_security', severity=src1_Severity.MEDIUM, verdict=src1_Verdict.LIKELY, confidence=0.7, asset_id='asset_1', endpoint_id='endpoint_1', metadata={'target_url': 'https://example.com/'})
    outcome = replayer.verify_finding(finding)
    assert outcome.verdict == src1_Verdict.NEEDS_HUMAN_REVIEW
    assert 'provenance' in outcome.reason.lower()

def test_evidence_verification_stage_is_partial_when_replay_crashes(tmp_path, monkeypatch):
    from security_analyzer.core.orchestrator import ExecutionContext
    from security_analyzer.verification import evidence_verifier
    from security_analyzer.verification.finding_deduplicator import FindingDeduplicator
    workspace = src1_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://example.com/')
    engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['example.com'], allowed_ports=[443]))
    engine.evaluate_url = lambda url, **kwargs: src1_ScopeDecision(True, url, 'unit scope')
    coverage = src1_CoverageTracker(workspace)
    finding = src1_FindingRecord(title='Replay crash fixture', category='custom_test', severity=src1_Severity.MEDIUM, verdict=src1_Verdict.LIKELY, confidence=0.6, asset_id='asset_1', endpoint_id='endpoint_1')
    monkeypatch.setattr(FindingDeduplicator, 'collect_from_workspace', lambda self, _workspace: [finding])
    monkeypatch.setattr(evidence_verifier, '_get_or_init_auth_manager', lambda _ctx: None)
    monkeypatch.setattr(evidence_verifier, 'load_validated_stage_artifact', lambda *args, **kwargs: None)
    monkeypatch.setattr(src1_DeterministicPocReplayer, 'verify_finding', lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError('synthetic replay failure')))
    ctx = ExecutionContext(target='https://example.com/', workspace=workspace, scope_engine=engine, coverage=coverage, config={'ai_triage': {'enabled': False}})
    result = evidence_verifier.run_evidence_verification(ctx, src1_StageDefinition('evidence_verification', 'Verification', 'verification'))
    assert result.status == src1_StageStatus.PARTIAL
    assert result.metrics['targets_tested'] == 0
    assert result.metrics['targets_skipped'] == 1

def test_testssl_nonzero_exit_is_not_accepted_even_if_report_exists(tmp_path, monkeypatch):
    from security_analyzer.scanners import tls_posture_scanner

    class FakeGovernor:

        def run_process(self, command, *, timeout_sec, **kwargs):
            output_path = src1_Path(command[command.index('--jsonfile') + 1])
            output_path.write_text('[]', encoding='utf-8')
            return src1_ProcessResult(command=tuple(command), returncode=7, stdout='', stderr='scanner failed', duration_sec=0.1)
    monkeypatch.setattr(tls_posture_scanner.shutil, 'which', lambda _name: '/usr/bin/testssl.sh')
    findings, ok, error = tls_posture_scanner._run_testssl('https://example.com/', proxy_url='http://127.0.0.1:3128', timeout_sec=30, governor=FakeGovernor(), existing_categories=set())
    assert findings == []
    assert ok is False
    assert 'code 7' in error

def test_dependency_doctor_requires_actual_chromium_launch(monkeypatch, tmp_path):
    import sys as src1_sys
    import types
    from security_analyzer.core.dependency_manager import DependencyManager
    executable = tmp_path / 'chromium'
    executable.write_text('#!/bin/sh\\nexit 0\\n', encoding='utf-8')

    class Browser:
        version = 'Chromium test'

        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True
    browser = Browser()

    class Chromium:
        executable_path = str(executable)

        def launch(self, *, headless):
            assert headless is True
            return browser

    class PlaywrightContext:
        chromium = Chromium()

        def __enter__(self):
            return types.SimpleNamespace(chromium=self.chromium)

        def __exit__(self, *_args):
            return False
    sync_api = types.ModuleType('playwright.sync_api')
    sync_api.sync_playwright = lambda: PlaywrightContext()
    monkeypatch.setitem(src1_sys.modules, 'playwright', types.ModuleType('playwright'))
    monkeypatch.setitem(src1_sys.modules, 'playwright.sync_api', sync_api)
    status = DependencyManager().check_browser_runtime(required=True)
    assert status.available is True
    assert status.version == 'Chromium test'
    assert browser.closed is True

def test_scoped_http_client_enforces_body_limit_without_governor():
    from security_analyzer.utils.http_client import ScopedHttpClient

    class Handler(src1_BaseHTTPRequestHandler):

        def do_GET(self):
            body = b'x' * 256
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return
    server = src1_ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = src1_threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['127.0.0.1'], allowed_ports=[port], allow_private_ips=True))
        client = ScopedHttpClient(engine, max_response_bytes=64)
        with src1_pytest.raises(src1_ResourceLimitExceeded):
            client.get(f'http://127.0.0.1:{port}/')
    finally:
        server.shutdown()
        server.server_close()

def test_nuclei_persists_sanitized_jsonl_events_before_timeout(tmp_path, monkeypatch):
    import json
    from security_analyzer.core.orchestrator import ExecutionContext
    from security_analyzer.scanners.nuclei_runner import run_nuclei_assessment
    workspace = src1_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://example.com/')
    engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['example.com'], allowed_ports=[443]))
    engine.evaluate_url = lambda url, **kwargs: src1_ScopeDecision(True, url, 'unit scope', ('93.184.216.34',))
    coverage = src1_CoverageTracker(workspace)

    class StreamingGovernor:

        def run_process(self, command, *, timeout_sec, stdout_line_callback, **kwargs):
            stdout_line_callback(json.dumps({'template-id': 'test-template', 'matched-at': 'https://example.com/', 'ip': '93.184.216.34', 'info': {'name': 'Test match', 'severity': 'medium', 'tags': ['safe']}, 'request': 'Authorization: Bearer must-not-be-persisted'}))
            return src1_ProcessResult(command=tuple(command), returncode=124, stdout='', stderr='partial scan', duration_sec=1, timed_out=True)
    ctx = ExecutionContext(target='https://example.com/', workspace=workspace, scope_engine=engine, coverage=coverage, config={'timeouts': {'nuclei_sec': 3}, 'limits': {'max_urls_per_stage': 10, 'requests_per_host_per_sec': 5}, 'nuclei': {'max_targets': 5, 'rate_limit': 5, 'concurrency': 2, 'bulk_size': 2, 'severities': 'low,medium,high,critical', 'inactivity_timeout_sec': 1}}, resource_governor=StreamingGovernor())
    monkeypatch.setattr('security_analyzer.scanners.nuclei_runner.shutil.which', lambda _name: '/usr/bin/nuclei')
    monkeypatch.setenv('SECURITY_ANALYZER_PROXY', 'http://127.0.0.1:3128')
    monkeypatch.setenv('SECURITY_ANALYZER_EGRESS_ENFORCED', '1')
    result = run_nuclei_assessment(ctx, src1_StageDefinition('nuclei_assessment', 'Nuclei', 'analysis'))
    event_file = workspace.resolve_path('analysis/nuclei_events.jsonl')
    assert result.status == src1_StageStatus.PARTIAL
    assert event_file.is_file()
    event = json.loads(event_file.read_text(encoding='utf-8').splitlines()[0])
    assert event['template_id'] == 'test-template'
    assert 'request' not in event
    assert 'must-not-be-persisted' not in event_file.read_text(encoding='utf-8')

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step5_6_hardening.py
# -----------------------------------------------------------------------------

import socket as src2_socket
import ssl as src2_ssl
import stat as src2_stat
import subprocess as src2_subprocess
import threading as src2_threading
import pytest as src2_pytest
from security_analyzer.core.dependency_manager import DependencyManager as src2_DependencyManager
from security_analyzer.deep_checks.authorization_idor import ADMIN_PATH_RE as src2_ADMIN_PATH_RE, ADMIN_ROLES as src2_ADMIN_ROLES
from security_analyzer.scanners.tls_posture_scanner import _probe_legacy_protocols as src2__probe_legacy_protocols

def test_admin_route_pattern_and_roles():
    assert src2_ADMIN_PATH_RE.search('/api/admin/users')
    assert src2_ADMIN_PATH_RE.search('/admin')
    assert not src2_ADMIN_PATH_RE.search('/api/administrators-guide-not')
    assert 'admin' in src2_ADMIN_ROLES and 'user' not in src2_ADMIN_ROLES

def test_probe_reports_supported_not_supported_and_untestable():
    seen = []

    def opener(context):
        seen.append((context.minimum_version, context.maximum_version))
        if context.minimum_version == src2_ssl.TLSVersion.TLSv1:
            return type('Connection', (), {'close': lambda self: None})()
        raise src2_ssl.SSLError('tlsv1 alert protocol version PROTOCOL_VERSION')
    result = src2__probe_legacy_protocols(opener)
    assert result == {'TLSv1': 'supported', 'TLSv1.1': 'not_supported'}
    assert all((minimum == maximum for minimum, maximum in seen))

    def broken(_context):
        raise ConnectionRefusedError()
    assert set(src2__probe_legacy_protocols(broken).values()) == {'untestable'}

def src2__make_cert(tmp_path):
    cert, key = (tmp_path / 'c.pem', tmp_path / 'k.pem')
    result = src2_subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert), '-days', '1', '-subj', '/CN=localhost'], capture_output=True)
    if result.returncode != 0:
        src2_pytest.skip('openssl not available')
    return (cert, key)

def test_probe_flags_a_real_tls10_only_server(tmp_path):
    cert, key = src2__make_cert(tmp_path)
    server_context = src2_ssl.SSLContext(src2_ssl.PROTOCOL_TLS_SERVER)
    try:
        server_context.minimum_version = src2_ssl.TLSVersion.TLSv1
        server_context.maximum_version = src2_ssl.TLSVersion.TLSv1
        server_context.set_ciphers('ALL:@SECLEVEL=0')
        server_context.load_cert_chain(str(cert), str(key))
    except (src2_ssl.SSLError, ValueError):
        src2_pytest.skip('local OpenSSL cannot serve TLS 1.0')
    listener = src2_socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(5)
    port = listener.getsockname()[1]
    stop = src2_threading.Event()

    def serve():
        listener.settimeout(0.5)
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except OSError:
                continue
            try:
                secured = server_context.wrap_socket(connection, server_side=True)
                secured.close()
            except Exception:
                connection.close()
    src2_threading.Thread(target=serve, daemon=True).start()

    def opener(context):
        raw = src2_socket.create_connection(('127.0.0.1', port), timeout=3)
        return context.wrap_socket(raw, server_hostname='localhost')
    try:
        result = src2__probe_legacy_protocols(opener)
    finally:
        stop.set()
        listener.close()
    if result['TLSv1'] == 'untestable':
        src2_pytest.skip('local OpenSSL cannot speak TLS 1.0')
    assert result['TLSv1'] == 'supported'
    assert result['TLSv1.1'] == 'not_supported'

def test_doctor_lists_only_used_tools_and_rejects_impostor(tmp_path, monkeypatch):
    assert set(src2_DependencyManager.CLI_COMMANDS) == {'subfinder', 'nuclei', 'ffuf', 'dig'}
    assert 'pytest' not in src2_DependencyManager.MODULES
    fake_nuclei = tmp_path / 'nuclei'
    fake_nuclei.write_text("#!/bin/sh\necho 'totally-different-program 1.0'\n", encoding='utf-8')
    fake_nuclei.chmod(fake_nuclei.stat().st_mode | src2_stat.S_IEXEC)
    monkeypatch.setenv('PATH', str(tmp_path))
    status = src2_DependencyManager().check_cli_tool('nuclei', True, ['-version'])
    assert status.available is False and status.version.startswith('identity_mismatch')
    fake_ffuf = tmp_path / 'ffuf'
    fake_ffuf.write_text("#!/bin/sh\necho 'ffuf version 2.1.0'\n", encoding='utf-8')
    fake_ffuf.chmod(fake_ffuf.stat().st_mode | src2_stat.S_IEXEC)
    assert src2_DependencyManager().check_cli_tool('ffuf', True, ['-V']).available is True

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step6_deep_checks.py
# -----------------------------------------------------------------------------

import json as src3_json
import threading as src3_threading
from http.server import BaseHTTPRequestHandler as src3_BaseHTTPRequestHandler, ThreadingHTTPServer as src3_ThreadingHTTPServer
from pathlib import Path as src3_Path
from security_analyzer.authentication import AuthManager as src3_AuthManager
from security_analyzer.core.coverage_tracker import CoverageTracker as src3_CoverageTracker
from security_analyzer.core.orchestrator import ExecutionContext as src3_ExecutionContext
from security_analyzer.core.scope_engine import ScopeEngine as src3_ScopeEngine, ScopePolicy as src3_ScopePolicy
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src3_STAGE_DEFINITIONS, StageStatus as src3_StageStatus
from security_analyzer.core.workspace import WorkspaceManager as src3_WorkspaceManager
from security_analyzer.deep_checks import run_authorization_idor as src3_run_authorization_idor, run_business_logic_checks as src3_run_business_logic_checks
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer as src3_EndpointNormalizer
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory as src3_UnifiedEndpointInventory

class src3__DeepChecksTestHandler(src3_BaseHTTPRequestHandler):

    def do_GET(self) -> None:
        auth = self.headers.get('Authorization', '')
        orig_url = self.headers.get('X-Original-URL', '')
        if self.path == '/api/public/catalog':
            self._reply(200, '{"items":["book","pen"]}')
            return
        if self.path in {'/api/orders/101', '/api/orders/102'}:
            if auth in {'Bearer tok_user_a', 'Bearer tok_user_b'}:
                oid = self.path.rsplit('/', 1)[-1]
                self._reply(200, src3_json.dumps({'order_id': oid, 'owner': 'alice', 'total': 499}))
            else:
                self._reply(401, '{"error":"login_required"}')
            return
        if self.path == '/api/admin/metrics':
            if auth == 'Bearer tok_user_a':
                self._reply(200, '{"revenue":99999,"users":420}')
            else:
                self._reply(403, '{"error":"admin_only"}')
            return
        if self.path == '/' and orig_url == '/api/admin/metrics':
            self._reply(200, '{"revenue":99999,"users":420}')
            return
        if self.path == '/':
            self._reply(200, '{"status":"home"}')
            return
        if self.path.startswith('/api/items'):
            if 'limit=-1' in self.path:
                self._reply(500, '{"error":"ValueError: negative limit"}')
            else:
                self._reply(200, '{"items":[1,2,3]}')
            return
        self._reply(404, '{"error":"not_found"}')

    def _reply(self, code: int, body: str) -> None:
        raw = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:
        return

def test_authorization_idor_and_business_logic_checks(tmp_path: Path, monkeypatch) -> None:
    server = src3_ThreadingHTTPServer(('127.0.0.1', 0), src3__DeepChecksTestHandler)
    port = server.server_address[1]
    thread = src3_threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f'http://127.0.0.1:{port}'
        monkeypatch.setenv('TOK_A', 'tok_user_a')
        monkeypatch.setenv('TOK_B', 'tok_user_b')
        profiles_yaml = tmp_path / 'auth_profiles.yaml'
        profiles_yaml.write_text('\nidentities:\n  user_a:\n    role: "user"\n    auth_method: "bearer_token"\n    token: "${TOK_A}"\n    owned_resource_ids:\n      - "101"\n  user_b:\n    role: "user"\n    auth_method: "bearer_token"\n    token: "${TOK_B}"\n', encoding='utf-8')
        ws = src3_WorkspaceManager(project_root=tmp_path)
        ws.init_scan(base_url)
        engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['127.0.0.1'], allowed_ports=[port], allow_private_ips=True))
        cov = src3_CoverageTracker(ws)
        inv = src3_UnifiedEndpointInventory(ws)
        norm = src3_EndpointNormalizer(engine)
        for u in (f'{base_url}/api/public/catalog', f'{base_url}/api/orders/101', f'{base_url}/api/admin/metrics', f'{base_url}/api/items?limit=10'):
            ep = norm.normalize(u, method='GET', source='http_probing', reachable=True)
            assert ep is not None
            inv.upsert_endpoint(ep)
        inv.save()
        auth_mgr = src3_AuthManager(scope_engine=engine, project_root=tmp_path, scan_id=ws.scan_id or 'test', default_target_url=base_url, coverage=cov, auth_profiles_path=profiles_yaml)
        auth_mgr.initialize_all()
        ctx = src3_ExecutionContext(target=base_url, workspace=ws, scope_engine=engine, coverage=cov, config={'auth_profiles_path': str(profiles_yaml), 'deep_checks': {'enable_rewrite_header_probes': True}}, upstream_artifacts={'api_js_intelligence': {'analysis/api_catalog.json': {'operations': [{'operation_id': 'updateUser', 'method': 'PATCH', 'url': f'{base_url}/api/users/1', 'path': '/api/users/1', 'body_fields': ['display_name', 'role', 'is_admin']}]}}}, auth_manager=auth_mgr)
        authz_def = next((s for s in src3_STAGE_DEFINITIONS if s.stage_id == 'authorization_idor'))
        authz_res = src3_run_authorization_idor(ctx, authz_def)
        assert authz_res.status == src3_StageStatus.SUCCESS
        authz_data = ws.read_json('analysis/authorization_matrix.json')
        categories = {f['category'] for f in authz_data['findings']}
        assert 'idor_bola' in categories
        assert 'access_control_header_bypass' in categories
        assert 'broken_authentication_enforcement' not in categories
        logic_def = next((s for s in src3_STAGE_DEFINITIONS if s.stage_id == 'business_logic_checks'))
        logic_res = src3_run_business_logic_checks(ctx, logic_def)
        assert logic_res.status == src3_StageStatus.SUCCESS
        logic_data = ws.read_json('analysis/business_logic.json')
        logic_categories = {f['category'] for f in logic_data['findings']}
        assert 'mass_assignment_surface' in logic_categories
        assert 'unhandled_boundary_exception' in logic_categories
    finally:
        server.shutdown()
        server.server_close()

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step8_scanner_reliability.py
# -----------------------------------------------------------------------------

import json as src4_json
import socket as src4_socket
from pathlib import Path as src4_Path
from types import SimpleNamespace as src4_SimpleNamespace
import pytest as src4_pytest
from security_analyzer.core.config_validation import validate_settings as src4_validate_settings
from security_analyzer.core.coverage_tracker import CoverageTracker as src4_CoverageTracker
from security_analyzer.core.exceptions import ConfigurationError as src4_ConfigurationError
from security_analyzer.core.orchestrator import ExecutionContext as src4_ExecutionContext
from security_analyzer.core.resource_governor import ProcessResult as src4_ProcessResult, ResourceLimitExceeded as src4_ResourceLimitExceeded
from security_analyzer.core.scope_engine import ScopeDecision as src4_ScopeDecision, ScopeEngine as src4_ScopeEngine, ScopePolicy as src4_ScopePolicy
from security_analyzer.core.stage_registry import StageDefinition as src4_StageDefinition, StageStatus as src4_StageStatus
from security_analyzer.core.workspace import WorkspaceManager as src4_WorkspaceManager
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory as src4_UnifiedEndpointInventory
from security_analyzer.discovery.directory_discovery import _run_ffuf as src4__run_ffuf
from security_analyzer.discovery.domain_enumeration import _run_subfinder as src4__run_subfinder
from security_analyzer.models.endpoint import EndpointRecord as src4_EndpointRecord
from security_analyzer.scanners.dns_infrastructure_scanner import _query_txt_records as src4__query_txt_records, _resolve_scoped_host as src4__resolve_scoped_host
from security_analyzer.scanners.nuclei_runner import _redact_url as src4__redact_url, _validated_local_proxy as src4__validated_local_proxy, parse_nuclei_jsonl as src4_parse_nuclei_jsonl, run_nuclei_assessment as src4_run_nuclei_assessment
from security_analyzer.scanners.tls_posture_scanner import _inspect_tls_endpoint as src4__inspect_tls_endpoint
from security_analyzer.scanners.header_exposure_scanner import run_security_review as src4_run_security_review

def src4__ctx(tmp_path: Path, *, governor=None, target='https://example.com/'):
    workspace = src4_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan(target)
    engine = src4_ScopeEngine(src4_ScopePolicy(allowed_domains=['example.com'], allowed_ports=[80, 443]))
    coverage = src4_CoverageTracker(workspace)
    return src4_ExecutionContext(target=target, workspace=workspace, scope_engine=engine, coverage=coverage, config={'timeouts': {'nuclei_sec': 3, 'tls_sec': 2, 'dns_sec': 2, 'http_connect_sec': 2, 'http_read_sec': 2, 'max_redirects': 2}, 'limits': {'max_urls_per_stage': 10, 'max_header_review_endpoints': 5, 'requests_per_host_per_sec': 5}, 'nuclei': {'max_targets': 5, 'rate_limit': 5, 'concurrency': 2, 'bulk_size': 2, 'severities': 'low,medium,high,critical'}, 'scope': {'check_dns': True}}, resource_governor=governor)

def src4__stage(stage_id: str) -> src4_StageDefinition:
    return src4_StageDefinition(stage_id, stage_id, 'analysis')

class src4__FakeGovernor:

    def __init__(self, result=None):
        self.result = result
        self.calls = []

    def run_process(self, command, *, timeout_sec, **kwargs):
        self.calls.append((list(command), timeout_sec))
        return self.result

def test_nuclei_requires_shared_resource_governor(tmp_path, monkeypatch):
    ctx = src4__ctx(tmp_path, governor=None)
    monkeypatch.setattr('security_analyzer.scanners.nuclei_runner.shutil.which', lambda _: '/usr/bin/nuclei')
    monkeypatch.setenv('SECURITY_ANALYZER_PROXY', 'http://127.0.0.1:3128')
    monkeypatch.setenv('SECURITY_ANALYZER_EGRESS_ENFORCED', '1')
    result = src4_run_nuclei_assessment(ctx, src4__stage('nuclei_assessment'))
    assert result.status == src4_StageStatus.PARTIAL
    assert 'ResourceGovernor' in result.summary
    assert ctx.workspace.read_json('analysis/nuclei_findings.json')['targets_scanned'] == []

def test_nuclei_rejects_non_loopback_proxy():
    assert src4__validated_local_proxy('http://127.0.0.1:3128')
    assert src4__validated_local_proxy('http://localhost:3128')
    assert not src4__validated_local_proxy('http://proxy.example.net:3128')
    assert not src4__validated_local_proxy('https://127.0.0.1:3128')
    assert not src4__validated_local_proxy('http://user:pass@127.0.0.1:3128')

def test_nuclei_timeout_is_partial_and_does_not_claim_targets_tested(tmp_path, monkeypatch):
    fake_governor = src4__FakeGovernor(src4_ProcessResult(command=('nuclei',), returncode=124, stdout='', stderr='', duration_sec=3.0, timed_out=True))
    ctx = src4__ctx(tmp_path, governor=fake_governor)
    monkeypatch.setattr('security_analyzer.scanners.nuclei_runner.shutil.which', lambda _: '/usr/bin/nuclei')
    monkeypatch.setenv('SECURITY_ANALYZER_PROXY', 'http://127.0.0.1:3128')
    monkeypatch.setenv('SECURITY_ANALYZER_EGRESS_ENFORCED', '1')
    monkeypatch.setattr(ctx.scope_engine, 'evaluate_url', lambda url, **kwargs: src4_ScopeDecision(True, url, 'test scope', ('93.184.216.34',)))
    result = src4_run_nuclei_assessment(ctx, src4__stage('nuclei_assessment'))
    assert result.status == src4_StageStatus.PARTIAL
    assert result.metrics['targets_tested'] == 0
    assert result.metrics['targets_skipped'] == 1
    artifact = ctx.workspace.read_json('analysis/nuclei_findings.json')
    assert artifact['execution']['timeout'] is True
    assert fake_governor.calls

def test_nuclei_url_redaction_removes_credentials_and_sensitive_query_values():
    safe = src4__redact_url('https://user:password@example.com/api?access_token=secret&page=2')
    assert safe == 'https://example.com/api?access_token=%5BREDACTED%5D&page=2'
    assert 'password' not in safe
    assert 'secret' not in safe
    path_safe = src4__redact_url('https://example.com/users/alice%40example.com/abcdefghijk.abcdefghijk.abcdefghijk')
    assert 'alice' not in path_safe
    assert 'abcdefghijk' not in path_safe

def test_scoped_dns_resolution_uses_scope_engine_results(monkeypatch):
    engine = src4_ScopeEngine(src4_ScopePolicy(allowed_domains=['example.com']))
    calls = []

    def evaluate(url, *, check_dns):
        calls.append((url, check_dns))
        return src4_ScopeDecision(True, url, 'allowed', ('93.184.216.34',))
    monkeypatch.setattr(engine, 'evaluate_url', evaluate)
    ips, error = src4__resolve_scoped_host('api.example.com', engine)
    assert ips == ['93.184.216.34']
    assert error == ''
    assert calls and calls[0][1] is True

def test_dns_txt_query_requires_scope_validation_and_governor(monkeypatch):
    engine = src4_ScopeEngine(src4_ScopePolicy(allowed_domains=['example.com']))
    monkeypatch.setattr('security_analyzer.scanners.dns_infrastructure_scanner.shutil.which', lambda _: '/usr/bin/dig')
    monkeypatch.setattr('security_analyzer.scanners.dns_infrastructure_scanner._resolve_scoped_host', lambda domain, scope_engine: (['93.184.216.34'], ''))
    fake_governor = src4__FakeGovernor(src4_ProcessResult(command=('dig',), returncode=0, stdout='"v=spf1 -all"\n', stderr='', duration_sec=0.1))
    records, error = src4__query_txt_records('example.com', fake_governor, scope_engine=engine, timeout_sec=2)
    assert records == ['v=spf1 -all']
    assert error == ''
    assert fake_governor.calls[0][0][-1] == 'example.com'

def test_dns_txt_query_refuses_to_run_without_governor(monkeypatch):
    engine = src4_ScopeEngine(src4_ScopePolicy(allowed_domains=['example.com']))
    monkeypatch.setattr('security_analyzer.scanners.dns_infrastructure_scanner.shutil.which', lambda _: '/usr/bin/dig')
    records, error = src4__query_txt_records('example.com', None, scope_engine=engine)
    assert records == []
    assert 'ResourceGovernor' in error

def test_tls_timeout_is_not_misclassified_as_invalid_certificate(monkeypatch):
    engine = src4_ScopeEngine(src4_ScopePolicy(allowed_domains=['example.com']))
    monkeypatch.setattr(engine, 'evaluate_url', lambda url, **kwargs: src4_ScopeDecision(True, url, 'allowed', ('93.184.216.34',)))

    class FakeGovernor:

        def __init__(self):
            self.acquired = 0
            self.released = 0

        def acquire_request(self, url, timeout=None):
            self.acquired += 1

        def remaining_sec(self, requested_timeout=None):
            return 1.0

        def release_request(self):
            self.released += 1
    governor = FakeGovernor()

    class FakeHTTPSConnection:

        def __init__(self, *args, **kwargs):
            self.sock = None
            self.closed = False

        def set_tunnel(self, host, port):
            self.tunnel = (host, port)

        def connect(self):
            raise src4_socket.timeout('test timeout')

        def close(self):
            self.closed = True
    monkeypatch.setattr('security_analyzer.scanners.tls_posture_scanner.http.client.HTTPSConnection', FakeHTTPSConnection)
    result = src4__inspect_tls_endpoint('https://example.com/', engine, timeout_sec=1, governor=governor, proxy_url='http://127.0.0.1:3128')
    assert result['certificate_valid'] is None
    assert 'timed out' in result['certificate_error'].lower()
    assert not any((finding['category'] == 'tls_certificate_invalid' for finding in result['findings']))
    assert governor.acquired == 1
    assert governor.released == 1

def test_header_review_stops_cleanly_when_request_budget_is_exhausted(tmp_path, monkeypatch):
    ctx = src4__ctx(tmp_path, governor=object())
    inventory = src4_UnifiedEndpointInventory(ctx.workspace)
    inventory.upsert_endpoint(src4_EndpointRecord(endpoint_id='ep_test', url='https://example.com/', canonical_url='https://example.com/', method='GET', scheme='https', hostname='example.com', port=443, path='/', reachable=True))
    inventory.save(stage_id='test')

    class FakeClient:

        def __init__(self, *args, **kwargs):
            pass

        def get(self, *args, **kwargs):
            raise src4_ResourceLimitExceeded('request cap reached')
    monkeypatch.setattr('security_analyzer.scanners.header_exposure_scanner.ScopedHttpClient', FakeClient)
    result = src4_run_security_review(ctx, src4__stage('security_review'))
    assert result.status == src4_StageStatus.PARTIAL
    assert result.metrics['targets_tested'] == 0
    payload = ctx.workspace.read_json('analysis/security_headers.json')
    assert payload['notes']

@src4_pytest.mark.parametrize('settings', [{'nuclei': {'severities': 'high;--unsafe'}}, {'nuclei': {'templates_dir': 123}}])
def test_step8_rejects_unsafe_or_inconsistent_scanner_settings(settings):
    with src4_pytest.raises(src4_ConfigurationError):
        src4_validate_settings(settings)

def test_subfinder_refuses_unbounded_execution_without_governor(monkeypatch):
    monkeypatch.setattr('security_analyzer.discovery.domain_enumeration.shutil.which', lambda _: '/usr/bin/subfinder')
    ok, hosts, reason = src4__run_subfinder('example.com', 5, governor=None)
    assert not ok
    assert hosts == []
    assert 'ResourceGovernor' in reason

def test_ffuf_refuses_unbounded_execution_without_governor(monkeypatch):
    monkeypatch.setattr('security_analyzer.discovery.directory_discovery.shutil.which', lambda _: '/usr/bin/ffuf')
    monkeypatch.setenv('SECURITY_ANALYZER_PROXY', 'http://127.0.0.1:3128')
    monkeypatch.setenv('SECURITY_ANALYZER_EGRESS_ENFORCED', '1')
    hits, skipped, reason = src4__run_ffuf('https://example.com/', ['admin'], workspace=None, scope_engine=None, coverage=None, stage_id='directory_discovery', check_dns=False, max_threads=2, governor=None)
    assert hits == []
    assert skipped == 0
    assert 'ResourceGovernor' in reason

def test_nuclei_parser_omits_raw_request_and_redacts_bearer_tokens():
    raw = src4_json.dumps({'template-id': 'sample', 'host': 'https://example.com/', 'matched-at': 'https://example.com/path?token=secret-value', 'request': 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz', 'response': 'Set-Cookie: session=private-session', 'info': {'name': 'Sample', 'severity': 'high', 'tags': ['exposure']}})
    parsed = src4_parse_nuclei_jsonl(raw)
    assert len(parsed) == 1
    serialized = src4_json.dumps(parsed)
    assert 'secret-value' not in serialized
    assert 'abcdefghijklmnopqrstuvwxyz' not in serialized
    assert 'private-session' not in serialized
    assert 'request' not in parsed[0]
    assert 'response' not in parsed[0]


def test_business_logic_is_partial_when_inventory_has_zero_endpoints(tmp_path: Path) -> None:
    from security_analyzer.core.stage_registry import STAGE_DEFINITIONS
    workspace = src3_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan("https://example.com/")
    engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=["example.com"], allowed_ports=[443]))
    coverage = src3_CoverageTracker(workspace)
    auth_manager = src3_AuthManager(
        scope_engine=engine,
        project_root=tmp_path,
        scan_id=workspace.scan_id or "test",
        default_target_url="https://example.com/",
        coverage=coverage,
        auth_profiles_path=None,
    )
    auth_manager.initialize_all()
    context = src3_ExecutionContext(
        target="https://example.com/",
        workspace=workspace,
        scope_engine=engine,
        coverage=coverage,
        config={},
        upstream_artifacts={
            "api_js_intelligence": {
                "analysis/api_catalog.json": {
                    "operations": [{
                        "operation_id": "profile.update",
                        "method": "PATCH",
                        "url": "https://example.com/api/profile",
                        "path": "/api/profile",
                        "body_fields": ["role"],
                    }]
                }
            }
        },
        auth_manager=auth_manager,
    )
    stage = next(item for item in STAGE_DEFINITIONS if item.stage_id == "business_logic_checks")
    result = src3_run_business_logic_checks(context, stage)
    assert result.status == src3_StageStatus.PARTIAL
    assert "no eligible endpoints" in result.summary
    assert workspace.read_json("analysis/business_logic.json")["summary"]["endpoints_total"] == 0


def test_directory_discovery_is_partial_when_ffuf_is_missing(tmp_path: Path, monkeypatch) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from security_analyzer.core.orchestrator import ExecutionContext
    from security_analyzer.core.stage_registry import STAGE_DEFINITIONS
    from security_analyzer.discovery import directory_discovery

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f"http://127.0.0.1:{server.server_address[1]}/"
        workspace = src3_WorkspaceManager(project_root=tmp_path)
        workspace.init_scan(base_url)
        engine = src3_ScopeEngine(src3_ScopePolicy(
            allowed_domains=["127.0.0.1"],
            allowed_ports=[server.server_address[1]],
            allow_private_ips=True,
        ))
        coverage = src3_CoverageTracker(workspace)
        monkeypatch.setattr(directory_discovery.shutil, "which", lambda _name: None)
        monkeypatch.setattr(directory_discovery, "_load_wordlist", lambda *_args, **_kwargs: ["robots.txt"])
        context = ExecutionContext(
            target=base_url,
            workspace=workspace,
            scope_engine=engine,
            coverage=coverage,
            config={
                "scope": {"check_dns": False},
                "limits": {"max_directory_words": 1, "max_urls_per_stage": 5, "max_concurrent_requests": 1},
                "timeouts": {"http_connect_sec": 2, "http_read_sec": 2, "directory_scan_sec": 5},
            },
            upstream_artifacts={
                "domain_enumeration": {
                    "discovery/subdomains.json": {
                        "hosts": [{"hostname": "127.0.0.1", "url": base_url}]
                    }
                }
            },
        )
        stage = next(item for item in STAGE_DEFINITIONS if item.stage_id == "directory_discovery")
        result = directory_discovery.run_directory_discovery(context, stage)
        assert result.status == src3_StageStatus.PARTIAL
        assert any("ffuf not installed" in note for note in workspace.read_json("discovery/directories.json")["notes"])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
