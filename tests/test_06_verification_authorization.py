from __future__ import annotations


# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step7_authorization_business_logic.py
# -----------------------------------------------------------------------------

from types import SimpleNamespace as src1_SimpleNamespace
import pytest as src1_pytest
from security_analyzer.core.config_validation import validate_settings as src1_validate_settings
from security_analyzer.core.exceptions import ConfigurationError as src1_ConfigurationError
from security_analyzer.deep_checks.authorization_idor import _extract_resource_ids as src1__extract_resource_ids, _path_matches_template as src1__path_matches_template, _resource_owner as src1__resource_owner

def test_resource_id_extraction_does_not_generate_neighbor_ids() -> None:
    url = 'https://api.example.test/v1/orders/12345?order_id=abc-123&page=2'
    values = src1__extract_resource_ids(url)
    assert ('path_segment[3]', '12345') in values
    assert ('query_param:order_id', 'abc-123') in values
    assert all((value not in {'12346', 'abc-124'} for _, value in values))

def test_resource_id_extraction_ignores_unrelated_query_parameters() -> None:
    values = src1__extract_resource_ids('https://api.example.test/orders?search=12345&page=2&token=secret')
    assert values == []

def test_openapi_path_template_matching_is_segment_bounded() -> None:
    assert src1__path_matches_template('/api/orders/123', '/api/orders/{orderId}')
    assert not src1__path_matches_template('/api/orders/123/items', '/api/orders/{orderId}')
    assert not src1__path_matches_template('/api/orders', '/api/orders/{orderId}')

def test_idor_owner_requires_one_explicit_profile_claim() -> None:
    endpoint = src1_SimpleNamespace(url='https://api.example.test/api/orders/12345')
    owner_profile = src1_SimpleNamespace(owned_resource_ids=['12345'])
    other_profile = src1_SimpleNamespace(owned_resource_ids=[])
    manager = src1_SimpleNamespace(profiles={'owner': owner_profile, 'other': other_profile})
    assert src1__resource_owner(manager, ['owner', 'other'], endpoint) == ('owner', 'path_segment[3]', '12345')

def test_ambiguous_ownership_is_not_attributed() -> None:
    endpoint = src1_SimpleNamespace(url='https://api.example.test/api/orders/12345')
    manager = src1_SimpleNamespace(profiles={'owner_a': src1_SimpleNamespace(owned_resource_ids=['12345']), 'owner_b': src1_SimpleNamespace(owned_resource_ids=['12345'])})
    assert src1__resource_owner(manager, ['owner_a', 'owner_b'], endpoint) == (None, None, None)

def test_step7_settings_are_bounded_and_opt_in() -> None:
    config = src1_validate_settings({})
    assert config['deep_checks']['enable_rewrite_header_probes'] is False
    assert config['deep_checks']['max_pagination_probe_value'] == 1000
    with src1_pytest.raises(src1_ConfigurationError):
        src1_validate_settings({'deep_checks': {'max_authz_endpoints': 100000}})
    with src1_pytest.raises(src1_ConfigurationError):
        src1_validate_settings({'deep_checks': {'enable_rewrite_header_probes': 'yes'}})
    with src1_pytest.raises(src1_ConfigurationError):
        src1_validate_settings({'deep_checks': {'allow_state_changing_probes': True}})

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step7_verification.py
# -----------------------------------------------------------------------------

import json as src2_json
import threading as src2_threading
from http.server import BaseHTTPRequestHandler as src2_BaseHTTPRequestHandler, ThreadingHTTPServer as src2_ThreadingHTTPServer
from pathlib import Path as src2_Path
from unittest.mock import patch as src2_patch
from security_analyzer.authentication import AuthManager as src2_AuthManager
from security_analyzer.core.coverage_tracker import CoverageTracker as src2_CoverageTracker
from security_analyzer.core.orchestrator import ExecutionContext as src2_ExecutionContext
from security_analyzer.core.scope_engine import ScopeEngine as src2_ScopeEngine, ScopePolicy as src2_ScopePolicy
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src2_STAGE_DEFINITIONS, StageStatus as src2_StageStatus
from security_analyzer.core.workspace import WorkspaceManager as src2_WorkspaceManager
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer as src2_EndpointNormalizer
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory as src2_UnifiedEndpointInventory
from security_analyzer.models.asset import make_asset_id as src2_make_asset_id
from security_analyzer.models.finding import FindingRecord as src2_FindingRecord, Severity as src2_Severity, Verdict as src2_Verdict
from security_analyzer.verification import OptionalAiTriage as src2_OptionalAiTriage, run_evidence_verification as src2_run_evidence_verification

class src2__VerificationTestHandler(src2_BaseHTTPRequestHandler):

    def do_GET(self) -> None:
        auth = self.headers.get('Authorization', '')
        if self.path == '/api/orders/102':
            if auth in {'Bearer tok_a', 'Bearer tok_b'}:
                self._reply(200, '{"order_id":102,"owner":"alice","amount":250}')
            else:
                self._reply(401, '{"error":"login_required"}')
            return
        if self.path == '/api/orders/999':
            if auth == 'Bearer tok_a':
                self._reply(200, '{"order_id":999,"owner":"alice"}')
            elif auth == 'Bearer tok_b':
                self._reply(403, '{"error":"forbidden"}')
            else:
                self._reply(401, '{"error":"login_required"}')
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

def test_deterministic_replay_dedup_and_ai_guardrails(tmp_path: Path, monkeypatch) -> None:
    server = src2_ThreadingHTTPServer(('127.0.0.1', 0), src2__VerificationTestHandler)
    port = server.server_address[1]
    thread = src2_threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f'http://127.0.0.1:{port}'
        monkeypatch.setenv('TOK_A', 'tok_a')
        monkeypatch.setenv('TOK_B', 'tok_b')
        profiles_yaml = tmp_path / 'auth.yaml'
        profiles_yaml.write_text('\nidentities:\n  user_a:\n    role: "user"\n    auth_method: "bearer_token"\n    token: "${TOK_A}"\n  user_b:\n    role: "user"\n    auth_method: "bearer_token"\n    token: "${TOK_B}"\n', encoding='utf-8')
        ws = src2_WorkspaceManager(project_root=tmp_path)
        scan_dir = ws.init_scan(base_url)
        engine = src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['127.0.0.1'], allowed_ports=[port], allow_private_ips=True))
        cov = src2_CoverageTracker(ws)
        inv = src2_UnifiedEndpointInventory(ws)
        norm = src2_EndpointNormalizer(engine)
        ep = norm.normalize(f'{base_url}/api/orders/101', method='GET', source='http_probing', reachable=True)
        assert ep is not None
        inv.upsert_endpoint(ep)
        inv.save()
        f_idor_1 = src2_FindingRecord(title='IDOR on /api/orders/102', category='idor_bola', severity=src2_Severity.MEDIUM, verdict=src2_Verdict.LIKELY, confidence=0.8, asset_id=src2_make_asset_id('127.0.0.1'), endpoint_id=ep.endpoint_id, identity_id='user_b', scanner_source='authorization_idor', metadata={'parameter_location': 'path_segment[3]', 'mutated_url': f'{base_url}/api/orders/102', 'owner_identity': 'user_a', 'attacker_identity': 'user_b', 'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'})
        f_idor_dup = src2_FindingRecord(title='Duplicate IDOR on /api/orders/102', category='idor_bola', severity=src2_Severity.HIGH, verdict=src2_Verdict.LIKELY, confidence=0.82, asset_id=src2_make_asset_id('127.0.0.1'), endpoint_id=ep.endpoint_id, identity_id='user_b', scanner_source='nuclei', metadata={'parameter_location': 'path_segment[3]', 'mutated_url': f'{base_url}/api/orders/102', 'owner_identity': 'user_a', 'attacker_identity': 'user_b'})
        f_fp = src2_FindingRecord(title='Transient IDOR on /api/orders/999', category='idor_bola', severity=src2_Severity.HIGH, verdict=src2_Verdict.LIKELY, confidence=0.8, asset_id=src2_make_asset_id('127.0.0.1'), endpoint_id=ep.endpoint_id, identity_id='user_b', scanner_source='authorization_idor', metadata={'parameter_location': 'path_segment[3]', 'mutated_url': f'{base_url}/api/orders/999', 'owner_identity': 'user_a', 'attacker_identity': 'user_b'})
        ws.write_json_atomic('analysis/authorization_matrix.json', {'schema_version': '1.0', 'scan_id': ws.scan_id, 'stage_id': 'authorization_idor', 'tests': [], 'findings': [f_idor_1.to_dict(), f_fp.to_dict()]})
        ws.write_json_atomic('analysis/nuclei_findings.json', {'schema_version': '1.0', 'scan_id': ws.scan_id, 'stage_id': 'nuclei_assessment', 'findings': [f_idor_dup.to_dict()]})
        stage_state = {stage.stage_id: {'status': 'PENDING', 'fingerprint': '', 'artifacts': []} for stage in src2_STAGE_DEFINITIONS}
        stage_state['authorization_idor'] = {'status': 'SUCCESS', 'fingerprint': 'test', 'artifacts': ['analysis/authorization_matrix.json']}
        stage_state['nuclei_assessment'] = {'status': 'SUCCESS', 'fingerprint': 'test', 'artifacts': ['analysis/nuclei_findings.json']}
        ws.write_json_atomic('scan_state.json', {'schema_version': '2.0', 'scan_id': ws.scan_id, 'target': base_url, 'stages': stage_state})
        auth_mgr = src2_AuthManager(scope_engine=engine, project_root=tmp_path, scan_id=ws.scan_id or 'test', default_target_url=base_url, coverage=cov, auth_profiles_path=profiles_yaml)
        auth_mgr.initialize_all()
        ctx = src2_ExecutionContext(target=base_url, workspace=ws, scope_engine=engine, coverage=cov, config={'auth_profiles_path': str(profiles_yaml), 'ai_triage': {'enabled': False}}, auth_manager=auth_mgr)
        ver_def = next((s for s in src2_STAGE_DEFINITIONS if s.stage_id == 'evidence_verification'))
        res = src2_run_evidence_verification(ctx, ver_def)
        assert res.status == src2_StageStatus.SUCCESS
        verified = ws.read_json('verification/verified_findings.json')
        assert verified['summary']['total_deduplicated_findings'] == 2
        assert verified['summary']['verdicts']['CONFIRMED'] == 1
        assert verified['summary']['verdicts']['FALSE_POSITIVE'] == 1
        confirmed_finding = next((f for f in verified['findings'] if f['verdict'] == 'CONFIRMED'))
        assert confirmed_finding['severity'] == 'HIGH'
        assert confirmed_finding['confidence'] >= 0.9
        assert confirmed_finding['metadata']['cvss_assessment']['base_score'] == 9.8
        assert confirmed_finding['metadata']['cvss_assessment']['score_type'] == 'CVSS_BASE_SCORE'
        assert sorted(confirmed_finding['metadata']['corroborating_sources']) == ['authorization_idor', 'nuclei']
        assert len(confirmed_finding['evidence_ids']) == 1
        assert (scan_dir / f"verification/evidence/{confirmed_finding['finding_id']}.json").exists()
        monkeypatch.setenv('OPENROUTER_API_KEY', 'dummy_key')
        triage = src2_OptionalAiTriage({'ai_triage': {'enabled': True, 'provider': 'openrouter'}})
        unconfirmed = src2_FindingRecord(title='Mass assignment surface', category='mass_assignment_surface', severity=src2_Severity.MEDIUM, verdict=src2_Verdict.NEEDS_HUMAN_REVIEW, confidence=0.65, asset_id=src2_make_asset_id('127.0.0.1'), endpoint_id='ep_1')
        with src2_patch.object(triage, '_call_openai_compatible', return_value={'rationale': 'Looks risky', 'remediation': 'Use DTO allowlist', 'recommend_human_review': False}):
            triage.triage_findings([unconfirmed])
        assert unconfirmed.verdict == src2_Verdict.NEEDS_HUMAN_REVIEW
    finally:
        server.shutdown()
        server.server_close()

# -----------------------------------------------------------------------------
# Consolidated from: tests/security/test_step7_verdicts.py
# -----------------------------------------------------------------------------

import threading as src3_threading
from http.server import BaseHTTPRequestHandler as src3_BaseHTTPRequestHandler, ThreadingHTTPServer as src3_ThreadingHTTPServer
import pytest as src3_pytest
from security_analyzer.core.coverage_tracker import CoverageTracker as src3_CoverageTracker
from security_analyzer.core.scope_engine import ScopeEngine as src3_ScopeEngine, ScopePolicy as src3_ScopePolicy
from security_analyzer.core.workspace import WorkspaceManager as src3_WorkspaceManager
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory as src3_UnifiedEndpointInventory
from security_analyzer.models.finding import FindingRecord as src3_FindingRecord, Severity as src3_Severity, Verdict as src3_Verdict
from security_analyzer.reporting.report_builder import ReportBuilder as src3_ReportBuilder
from security_analyzer.verification.finding_deduplicator import FindingDeduplicator as src3_FindingDeduplicator
from security_analyzer.verification.poc_replayer import DeterministicPocReplayer as src3_DeterministicPocReplayer
from security_analyzer.verification.severity_assessor import SeverityAssessor as src3_SeverityAssessor

class src3_Handler(src3_BaseHTTPRequestHandler):
    hits = 0

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == '/app.js':
            body, code = (b"const k='AKIAIOSFODNN7EXAMPLE';", 200)
        elif self.path == '/flaky':
            type(self).hits += 1
            body, code = (b'boom', 500) if type(self).hits == 1 else (b'ok', 200)
        else:
            body, code = (b'nf', 404)
        self.send_response(code)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

@src3_pytest.fixture()
def env(tmp_path):
    src3_Handler.hits = 0
    server = src3_ThreadingHTTPServer(('127.0.0.1', 0), src3_Handler)
    src3_threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    ws = src3_WorkspaceManager(project_root=tmp_path, output_root_name='output')
    ws.init_scan(f'http://127.0.0.1:{port}')
    engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['127.0.0.1'], allowed_ports=[port], allow_private_ips=True))
    replayer = src3_DeterministicPocReplayer(workspace=ws, scope_engine=engine, coverage=src3_CoverageTracker(ws), inventory=src3_UnifiedEndpointInventory(ws), auth_manager=None)
    yield (replayer, f'http://127.0.0.1:{port}', ws)
    server.shutdown()
    server.server_close()

def src3__finding(cat, url, **meta):
    return src3_FindingRecord(title=cat, category=cat, severity=src3_Severity.INFO, verdict=src3_Verdict.LIKELY, confidence=0.8, asset_id='a', endpoint_id='e', scanner_source='t', metadata={'url': url, **meta})

def test_secret_in_js_is_never_confirmed_from_http_200(env):
    replayer, base, _ = env
    outcome = replayer.verify_finding(src3__finding('hardcoded_secret_in_js', f'{base}/app.js'))
    assert outcome.verdict == src3_Verdict.NEEDS_HUMAN_REVIEW
    assert 'not established' in outcome.reason

def test_missing_secret_file_is_false_positive(env):
    replayer, base, _ = env
    outcome = replayer.verify_finding(src3__finding('hardcoded_secret_in_js', f'{base}/gone.js'))
    assert outcome.verdict == src3_Verdict.FALSE_POSITIVE

def test_one_off_500_is_not_confirmed(env):
    replayer, base, _ = env
    outcome = replayer.verify_finding(src3__finding('unhandled_boundary_exception', f'{base}/flaky'))
    assert outcome.verdict != src3_Verdict.CONFIRMED

def test_host_level_findings_merge_across_urls():
    key = src3_FindingDeduplicator.compute_dedup_key
    a = key(category='missing_csp', target_location='https://t.example/a')
    b = key(category='missing_csp', target_location='https://t.example/b/c')
    assert a == b
    assert key(category='idor_bola', target_location='https://t.example/a') != key(category='idor_bola', target_location='https://t.example/b')
    merged = src3_FindingDeduplicator().collect_and_deduplicate({'analysis/security_headers.json': {'findings': [{'category': 'missing_csp', 'url': 'https://t.example/a', 'title': 'Missing CSP'}, {'category': 'missing_csp', 'url': 'https://t.example/b/c', 'title': 'Missing CSP'}]}})
    assert len(merged) == 1
    assert set(merged[0].metadata['affected_urls']) == {'https://t.example/a', 'https://t.example/b/c'}

def test_risk_score_is_labelled_internal_not_cvss():
    result = src3_SeverityAssessor.assess(src3__finding('x', 'u'))
    assert result['method'] == 'internal_ranking_v1' and result['cvss'] is None
    assert 'NOT a CVSS' in result['label']

def test_report_separates_configuration_issues(tmp_path):
    assert src3_ReportBuilder._is_config_observation({'category': 'missing_content_security_policy'})
    assert src3_ReportBuilder._is_config_observation({'category': 'tls_legacy_protocol'})
    assert not src3_ReportBuilder._is_config_observation({'category': 'idor_bola'})

# -----------------------------------------------------------------------------
# Consolidated from: tests/integration/test_step5_lab_idor.py
# -----------------------------------------------------------------------------

import json as src4_json
import threading as src4_threading
from http.server import BaseHTTPRequestHandler as src4_BaseHTTPRequestHandler, ThreadingHTTPServer as src4_ThreadingHTTPServer
import pytest as src4_pytest
from security_analyzer.core.config_validation import validate_settings as src4_validate_settings
from security_analyzer.core.coverage_tracker import CoverageTracker as src4_CoverageTracker
from security_analyzer.core.orchestrator import ExecutionContext as src4_ExecutionContext
from security_analyzer.core.scope_engine import ScopeEngine as src4_ScopeEngine, ScopePolicy as src4_ScopePolicy
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src4_STAGE_DEFINITIONS
from security_analyzer.core.workspace import WorkspaceManager as src4_WorkspaceManager
from security_analyzer.deep_checks.authorization_idor import run_authorization_idor as src4_run_authorization_idor
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer as src4_EndpointNormalizer
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory as src4_UnifiedEndpointInventory
src4_TOKENS = {'tok-a': ('user_a', 'standard_user'), 'tok-b': ('user_b', 'standard_user'), 'tok-admin': ('root', 'admin')}
src4_OWNER = {'1': 'user_a', '2': 'user_b'}

class src4_Lab(src4_BaseHTTPRequestHandler):
    transient_seen: set[str] = set()
    transient_lock = src4_threading.Lock()

    def log_message(self, *args):
        pass

    def _send(self, code, body):
        data = src4_json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        token = self.headers.get('Authorization', '').replace('Bearer ', '')
        identity = src4_TOKENS.get(token)
        path = self.path.split('?')[0]
        if path == '/api/public/info':
            return self._send(200, {'name': 'lab', 'version': '1.0', 'items': [1, 2, 3]})
        if not identity:
            return self._send(401, {'error': 'auth'})
        if path == '/api/profile/1':
            return self._send(200, {'id': '1', 'email': 'owner-a', 'plan': 'gold', 'notes': 'private-a'})
        if path == '/api/profile/3':
            if identity[0] == 'user_a':
                return self._send(200, {'id': '3', 'email': 'owner-a', 'plan': 'gold', 'notes': 'private-a'})
            if identity[0] == 'user_b':
                with self.transient_lock:
                    repeated = token in self.transient_seen
                    self.transient_seen.add(token)
                if not repeated:
                    return self._send(200, {'id': '3', 'email': 'owner-a', 'plan': 'gold', 'notes': 'private-a'})
            return self._send(403, {'error': 'forbidden'})
        if path == '/api/profile/2':
            if identity[0] != src4_OWNER['2']:
                return self._send(403, {'error': 'forbidden'})
            return self._send(200, {'id': '2', 'email': 'owner-b', 'plan': 'silver', 'notes': 'private-b'})
        if path == '/api/admin/users':
            return self._send(200, {'users': ['a', 'b', 'root'], 'count': 3})
        return self._send(404, {'error': 'nf'})

    def do_POST(self):
        token = self.headers.get('Authorization', '').replace('Bearer ', '')
        identity = src4_TOKENS.get(token)
        length = int(self.headers.get('Content-Length', '0') or 0)
        try:
            request = src4_json.loads(self.rfile.read(length) or b'{}')
        except ValueError:
            return self._send(400, {'errors': [{'message': 'invalid json'}]})
        query = str(request.get('query', ''))
        if self.path != '/graphql' or 'me' not in query:
            return self._send(400, {'errors': [{'message': 'unsupported query'}]})
        if identity and identity[0] in {'user_a', 'root'}:
            return self._send(200, {'data': {'me': {'__typename': 'Profile'}}})
        return self._send(200, {'data': {'me': None}, 'errors': [{'message': 'forbidden'}]})

@src4_pytest.fixture
def lab():
    src4_Lab.transient_seen.clear()
    server = src4_ThreadingHTTPServer(('127.0.0.1', 0), src4_Lab)
    thread = src4_threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

def test_lab_finds_planted_idor_and_admin_flaw_without_false_positives(tmp_path, lab):
    base = f'http://127.0.0.1:{lab}'
    profiles = tmp_path / 'auth.yaml'
    profiles.write_text(f'\nidentities:\n  user_a:\n    role: standard_user\n    auth_method: bearer_token\n    token: tok-a\n    owned_resource_ids: ["1", "3"]\n  user_b:\n    role: standard_user\n    auth_method: bearer_token\n    token: tok-b\n    owned_resource_ids: ["2"]\n  root:\n    role: admin\n    auth_method: bearer_token\n    token: tok-admin\n', encoding='utf-8')
    workspace = src4_WorkspaceManager(project_root=tmp_path, output_root_name='output')
    workspace.init_scan(base)
    engine = src4_ScopeEngine(src4_ScopePolicy(allowed_domains=['127.0.0.1'], allowed_ports=[lab], allow_private_ips=True))
    coverage = src4_CoverageTracker(workspace)
    normalizer = src4_EndpointNormalizer(engine, coverage)
    inventory = src4_UnifiedEndpointInventory(workspace)
    for path in ('/api/profile/1', '/api/profile/2', '/api/profile/3', '/api/admin/users', '/api/public/info'):
        inventory.upsert_endpoint(normalizer.normalize(f'{base}{path}', source='api_spec', stage_id='api_js_intelligence'))
    inventory.upsert_endpoint(normalizer.normalize(f'{base}/graphql', method='POST', source='graphql', stage_id='api_js_intelligence', tags=['graphql', 'api_candidate']))
    inventory.save(stage_id='api_js_intelligence')
    config = src4_validate_settings({})
    config['auth_profiles_path'] = str(profiles)
    context = src4_ExecutionContext(target=base, workspace=workspace, scope_engine=engine, coverage=coverage, config=config, upstream_artifacts={'api_js_intelligence': {'analysis/api_catalog.json': {'operations': [{'operation_id': 'graphql.query.me', 'method': 'POST', 'url': f'{base}/graphql', 'path': '/graphql', 'source': 'graphql', 'tags': ['graphql', 'query'], 'graphql_field': 'me', 'graphql_args': [], 'graphql_returns_object': True}]}}})
    stage = next((definition for definition in src4_STAGE_DEFINITIONS if definition.stage_id == 'authorization_idor'))
    result = src4_run_authorization_idor(context, stage)
    assert result.status.value in {'SUCCESS', 'PARTIAL'}, result.summary
    payload = workspace.read_json('analysis/authorization_matrix.json')
    by_category = {}
    for finding in payload['findings']:
        by_category.setdefault(finding['category'], []).append(finding)
    idor = by_category.get('idor_bola', [])
    assert idor and all(('/api/profile/1' in finding['title'] for finding in idor))
    assert {finding['identity_id'] for finding in idor} == {'user_b', 'root'}
    assert all((finding['metadata']['reproduced'] is True for finding in idor))
    vertical = by_category.get('vertical_privilege_escalation', [])
    assert {finding['identity_id'] for finding in vertical} == {'user_a', 'user_b'}
    assert all(('/api/admin/users' in finding['title'] for finding in vertical))
    assert not any(('/api/profile/2' in finding['title'] for finding in payload['findings']))
    assert not any(('/api/public/info' in finding['title'] for finding in payload['findings']))
    graphql_checks = payload['graphql_field_access_checks']
    assert len(graphql_checks) == 1
    assert graphql_checks[0]['field'] == 'me'
    assert graphql_checks[0]['access_differs_by_identity'] is True
    assert graphql_checks[0]['finding_created'] is False
    flaky_test = next((test for test in payload['tests'] if test['path'] == '/api/profile/3'))
    flaky_probe = next((probe for probe in flaky_test['idor_probes'] if probe['tested_identity'] == 'user_b'))
    assert flaky_probe['same_object_response'] is True
    assert flaky_probe['reproduced'] is False
    assert flaky_probe['suspected_idor'] is False
    assert not any(('/api/profile/3' in finding['title'] for finding in payload['findings']))

# -----------------------------------------------------------------------------
# Step 3 lifecycle, CVSS and evidence-store acceptance tests
# -----------------------------------------------------------------------------

def test_cvss31_base_vector_calculation_and_validation() -> None:
    from security_analyzer.verification.cvss import (
        CvssVectorError as Step3CvssVectorError,
        calculate_cvss31 as step3_calculate_cvss31,
    )

    critical = step3_calculate_cvss31(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert critical["base_score"] == 9.8
    assert critical["base_severity"] == "CRITICAL"
    assert critical["score_type"] == "CVSS_BASE_SCORE"

    zero = step3_calculate_cvss31(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    )
    assert zero["base_score"] == 0.0
    assert zero["base_severity"] == "NONE"

    with src3_pytest.raises(Step3CvssVectorError):
        step3_calculate_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
    with src3_pytest.raises(Step3CvssVectorError):
        step3_calculate_cvss31(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:A"
        )


def test_finding_identifier_is_stable_across_scans_and_scanner_ids() -> None:
    from security_analyzer.models.finding import (
        FindingRecord as Step3FindingRecord,
        Severity as Step3Severity,
        Verdict as Step3Verdict,
    )
    from security_analyzer.verification.finding_deduplicator import (
        FindingDeduplicator as Step3FindingDeduplicator,
    )

    def collect(scanner_id: str):
        finding = Step3FindingRecord(
            finding_id=scanner_id,
            title="IDOR candidate",
            category="idor_bola",
            severity=Step3Severity.HIGH,
            verdict=Step3Verdict.LIKELY,
            confidence=0.8,
            asset_id="asset_test",
            endpoint_id="ep_test",
            identity_id="attacker",
            scanner_source="test_scanner",
            metadata={
                "target_url": "https://app.example.test/api/orders/123",
                "parameter_location": "path_segment[4]",
            },
        )
        return Step3FindingDeduplicator().collect_and_deduplicate(
            {
                "analysis/authorization_matrix.json": {
                    "findings": [finding.to_dict()]
                }
            }
        )

    first = collect("random_scan_uuid_a")
    second = collect("random_scan_uuid_b")
    assert len(first) == len(second) == 1
    assert first[0].finding_id == second[0].finding_id
    assert first[0].finding_id.startswith("find_")


def test_evidence_store_migration_history_review_and_backup_restore(tmp_path) -> None:
    import sqlite3 as step3_sqlite3
    from security_analyzer.core.workspace import (
        WorkspaceManager as Step3WorkspaceManager,
    )
    from security_analyzer.verification.evidence_store import (
        EvidenceStore as Step3EvidenceStore,
    )

    workspace = Step3WorkspaceManager(project_root=tmp_path)
    workspace.init_scan("https://app.example.test")

    # Simulate an existing v1 database. The v2 migration must be additive.
    database_path = workspace.resolve_path(Step3EvidenceStore.RELATIVE_PATH)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    legacy = step3_sqlite3.connect(database_path)
    legacy.execute("CREATE TABLE store_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    legacy.execute(
        "INSERT INTO store_meta(key, value) VALUES('scan_id', ?)",
        (workspace.scan_id,),
    )
    legacy.execute("PRAGMA user_version=1")
    legacy.commit()
    legacy.close()

    store = Step3EvidenceStore(workspace)
    assert store._connection.execute("PRAGMA user_version").fetchone()[0] == 2

    finding = {
        "finding_id": "find_step3_history",
        "category": "idor_bola",
        "severity": "HIGH",
        "verdict": "NEEDS_HUMAN_REVIEW",
        "confidence": 0.75,
        "metadata": {"target_url": "https://app.example.test/api/orders/123"},
    }
    store.record_finding(
        finding,
        actor="verification-engine",
        reason="Initial deterministic verification",
    )
    store.record_finding(
        {**finding, "verdict": "LIKELY", "confidence": 0.8},
        actor="verification-engine",
        reason="Second verification pass",
    )
    assert len(store.finding_history("find_step3_history")) == 2

    decision_id = store.record_human_review_decision(
        finding_id="find_step3_history",
        reviewer_id="reviewer-01",
        decision="CONFIRM",
        reason="Reproduction and authorization contrast reviewed",
        metadata={"ticket": "SEC-123"},
    )
    assert decision_id > 0
    review_history = store.human_review_history("find_step3_history")
    assert len(review_history) == 1
    assert review_history[0]["reviewer_id"] == "reviewer-01"
    assert review_history[0]["decision"] == "CONFIRM"
    assert len(store.finding_history("find_step3_history")) == 3

    # Lifecycle and reviewer-decision records are append-only.
    with src3_pytest.raises(step3_sqlite3.IntegrityError):
        store._connection.execute(
            "UPDATE finding_history SET reason='tampered' WHERE finding_id=?",
            ("find_step3_history",),
        )
    with src3_pytest.raises(step3_sqlite3.IntegrityError):
        store._connection.execute(
            "DELETE FROM human_review_decisions WHERE finding_id=?",
            ("find_step3_history",),
        )
    store._connection.rollback()

    backup_path = tmp_path / "backups" / "evidence.sqlite3"
    store.backup_to(backup_path)
    store.close()

    restored_path = tmp_path / "restored" / "evidence.sqlite3"
    Step3EvidenceStore.restore_from_backup(
        backup_path,
        restored_path,
        expected_scan_id=workspace.scan_id,
    )
    restored = step3_sqlite3.connect(restored_path)
    try:
        restored_meta = restored.execute(
            "SELECT value FROM store_meta WHERE key='scan_id'"
        ).fetchone()
        assert restored_meta[0] == workspace.scan_id
        assert restored.execute(
            "SELECT COUNT(*) FROM finding_history WHERE finding_id=?",
            ("find_step3_history",),
        ).fetchone()[0] == 3
        assert restored.execute(
            "SELECT verdict FROM findings WHERE finding_id=?",
            ("find_step3_history",),
        ).fetchone()[0] == "CONFIRMED"
        assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        restored.close()

