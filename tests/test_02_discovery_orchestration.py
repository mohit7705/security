from __future__ import annotations


# -----------------------------------------------------------------------------
# Consolidated from: tests/pipeline/test_step2_pipeline.py
# -----------------------------------------------------------------------------

import json as src1_json
from pathlib import Path as src1_Path
import pytest as src1_pytest
from security_analyzer.core.coverage_tracker import CoverageTracker as src1_CoverageTracker
from security_analyzer.core.exceptions import ArtifactValidationError as src1_ArtifactValidationError
from security_analyzer.core.orchestrator import PipelineOrchestrator as src1_PipelineOrchestrator
from security_analyzer.core.resource_governor import ResourceGovernor as src1_ResourceGovernor
from security_analyzer.core.scope_engine import ScopeEngine as src1_ScopeEngine, ScopePolicy as src1_ScopePolicy
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src1_STAGE_DEFINITIONS, ArtifactSpec as src1_ArtifactSpec, StageDefinition as src1_StageDefinition, StageResult as src1_StageResult, StageStatus as src1_StageStatus, compute_overall_status as src1_compute_overall_status, validate_stage_artifacts as src1_validate_stage_artifacts
from security_analyzer.core.workspace import WorkspaceManager as src1_WorkspaceManager
src1_DEFS = (src1_StageDefinition('a', 'A', 't', artifacts=(src1_ArtifactSpec('a.json', ('schema_version', 'scan_id', 'stage_id')),)), src1_StageDefinition('b', 'B', 't', dependencies=('a',), artifacts=(src1_ArtifactSpec('b.json', ('schema_version', 'scan_id', 'stage_id')),)), src1_StageDefinition('c', 'C', 't', dependencies=('b',), artifacts=(src1_ArtifactSpec('c.json', ('schema_version', 'scan_id', 'stage_id')),)))

def src1__make(tmp_path: Path, config: dict | None=None, scan_id: str | None=None):
    ws = src1_WorkspaceManager(project_root=tmp_path, output_root_name='output')
    if scan_id:
        ws.load_scan(scan_id)
    else:
        ws.init_scan('https://t.example/')
    engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['t.example']))
    orch = src1_PipelineOrchestrator(target='https://t.example/', workspace=ws, scope_engine=engine, coverage=src1_CoverageTracker(ws), config=config or {}, definitions=src1_DEFS)
    calls: list[str] = []

    def runner(ctx, sd):
        calls.append(sd.stage_id)
        ctx.workspace.write_json_atomic(sd.artifacts[0].relative_path, {'schema_version': '1.0', 'scan_id': ctx.workspace.scan_id, 'stage_id': sd.stage_id})
        return src1_StageResult(sd.stage_id, src1_StageStatus.SUCCESS, 'ok', [sd.artifacts[0].relative_path])
    for definition in src1_DEFS:
        orch.register_runner(definition.stage_id, runner)
    return (orch, ws, calls)

def test_resume_reuses_then_upstream_config_change_reruns_all(tmp_path):
    orch, ws, _ = src1__make(tmp_path, {'x': 1})
    assert orch.run() == src1_StageStatus.SUCCESS
    orch2, _, calls2 = src1__make(tmp_path, {'x': 1}, scan_id=ws.scan_id)
    orch2.run(resume=True)
    assert calls2 == []
    orch3, _, calls3 = src1__make(tmp_path, {'x': 2}, scan_id=ws.scan_id)
    orch3.run(resume=True)
    assert calls3 == ['a', 'b', 'c']

def test_artifacts_carry_provenance_and_stage_record(tmp_path):
    orch, ws, _ = src1__make(tmp_path)
    orch.run()
    provenance = ws.read_json('a.json')['provenance']
    assert provenance['producer_status'] == 'SUCCESS'
    assert provenance['input_fingerprint'] == orch.state['stages']['a']['fingerprint']
    entry = orch.state['stages']['a']
    assert entry['started_at'] and entry['finished_at'] and entry['config_hash']
    assert 'a.json' in entry['artifact_hashes']
    events = [src1_json.loads(line) for line in (ws.scan_dir / 'logs/execution.jsonl').read_text().splitlines()]
    assert any((event['event'] == 'stage_record' and event['stage_id'] == 'a' for event in events))
    assert (ws.scan_dir / 'meta/config_snapshot.json').is_file()

def test_stale_artifact_is_rejected(tmp_path):
    orch, ws, _ = src1__make(tmp_path)
    orch.run()
    payload = ws.read_json('a.json')
    payload['provenance']['input_fingerprint'] = 'old'
    ws.write_json_atomic('a.json', payload)
    with src1_pytest.raises(src1_ArtifactValidationError):
        src1_validate_stage_artifacts(ws, src1_DEFS[0], require_producer_state=True)

def test_failed_stage_skips_dependents_and_overall_fails(tmp_path):
    orch, _, _ = src1__make(tmp_path)
    orch.register_runner('b', lambda _ctx, _sd: (_ for _ in ()).throw(RuntimeError('boom')))
    assert orch.run() == src1_StageStatus.FAILED
    assert orch.state['stages']['b']['status'] == 'FAILED'
    assert orch.state['stages']['c']['status'] == 'SKIPPED'

def test_zero_tested_targets_is_never_success(tmp_path):
    orch, _, _ = src1__make(tmp_path)

    def runner(ctx, _sd):
        ctx.workspace.write_json_atomic('a.json', {'schema_version': '1.0', 'scan_id': ctx.workspace.scan_id, 'stage_id': 'a'})
        return src1_StageResult('a', src1_StageStatus.SUCCESS, 'x', ['a.json'], metrics={'targets_total': 3, 'targets_tested': 0})
    orch.register_runner('a', runner)
    orch.run(only_stages={'a'})
    assert orch.state['stages']['a']['status'] == 'PARTIAL'

def test_cancellation_keeps_partial_output_and_skips_rest(tmp_path):
    orch, ws, _ = src1__make(tmp_path)
    orch.register_runner('b', lambda _ctx, _sd: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert orch.run() == src1_StageStatus.FAILED
    assert orch.state['cancelled'] is True
    assert orch.state['stages']['a']['status'] == 'SUCCESS'
    assert orch.state['stages']['c']['status'] == 'SKIPPED'
    assert ws.state_file.is_file()

def test_governor_cancel_kills_child_process():
    import threading
    import time
    governor = src1_ResourceGovernor({})
    threading.Timer(0.3, governor.cancel).start()
    started = time.monotonic()
    result = governor.run_process(['sleep', '20'], timeout_sec=30)
    assert time.monotonic() - started < 5 and result.returncode != 0

def test_overall_status_rules():
    assert src1_compute_overall_status(['SUCCESS', 'SUCCESS']) == src1_StageStatus.SUCCESS
    assert src1_compute_overall_status(['SUCCESS', 'SKIPPED']) == src1_StageStatus.PARTIAL
    assert src1_compute_overall_status(['SUCCESS', 'FAILED', 'PARTIAL']) == src1_StageStatus.FAILED

def test_every_dependency_is_declared_and_verification_lists_all_producers():
    ids = {definition.stage_id for definition in src1_STAGE_DEFINITIONS}
    for definition in src1_STAGE_DEFINITIONS:
        assert set(definition.dependencies) <= ids
        assert set(definition.optional_dependencies) <= set(definition.dependencies)
    verification = next((d for d in src1_STAGE_DEFINITIONS if d.stage_id == 'evidence_verification'))
    producers = {'security_review', 'online_security_checks', 'nuclei_assessment', 'server_dns_checks', 'api_js_intelligence', 'authorization_idor', 'business_logic_checks'}
    assert producers <= set(verification.dependencies)
    api_intel = next((d for d in src1_STAGE_DEFINITIONS if d.stage_id == 'api_js_intelligence'))
    assert 'browser_capture' in api_intel.dependencies
    assert 'browser_capture' in api_intel.optional_dependencies
    report = next((d for d in src1_STAGE_DEFINITIONS if d.stage_id == 'consolidated_reporting'))
    assert 'evidence_verification' in report.dependencies

def test_report_never_shows_pending_or_running(tmp_path):
    from security_analyzer.reporting.report_builder import ReportBuilder
    orch, ws, _ = src1__make(tmp_path)
    orch.run()
    state = ws.read_json('scan_state.json')
    state['overall_status'] = 'PENDING'
    state['stages']['c']['status'] = 'RUNNING'
    ws.write_json_atomic('scan_state.json', state)
    report = ReportBuilder(ws).build(stage_id='c')
    assert report['overall_pipeline_status'] == 'SUCCESS'
    assert {stage['stage_id']: stage['status'] for stage in report['coverage']['stages']}['c'] == 'SUCCESS'

def test_inventory_records_contributors(tmp_path):
    from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
    ws = src1_WorkspaceManager(project_root=tmp_path, output_root_name='output')
    ws.init_scan('https://t.example/')
    inventory = UnifiedEndpointInventory(ws)
    inventory.save(stage_id='domain_enumeration')
    inventory.save(stage_id='http_probing')
    data = ws.read_json('inventory/unified_endpoints.json')
    assert data['stage_id'] == 'http_probing'
    assert data['contributors'] == ['domain_enumeration', 'http_probing']

def test_cli_scan_and_resume_accept_output_root():
    from security_analyzer.cli import build_parser
    parser = build_parser()
    assert parser.parse_args(['scan', '--target', 'https://t.example/', '--output-root', 'x']).output_root == 'x'
    assert parser.parse_args(['resume', '--scan-id', 's', '--output-root', 'x']).output_root == 'x'

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step2_discovery.py
# -----------------------------------------------------------------------------

import threading as src2_threading
from http.server import BaseHTTPRequestHandler as src2_BaseHTTPRequestHandler, ThreadingHTTPServer as src2_ThreadingHTTPServer
from pathlib import Path as src2_Path
from security_analyzer.core.scope_engine import ScopeEngine as src2_ScopeEngine, ScopePolicy as src2_ScopePolicy
from security_analyzer.core.workspace import WorkspaceManager as src2_WorkspaceManager
from security_analyzer.core.coverage_tracker import CoverageTracker as src2_CoverageTracker
from security_analyzer.core.orchestrator import PipelineOrchestrator as src2_PipelineOrchestrator
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src2_STAGE_DEFINITIONS
from security_analyzer.discovery import EndpointNormalizer as src2_EndpointNormalizer, UnifiedEndpointInventory as src2_UnifiedEndpointInventory, run_directory_discovery as src2_run_directory_discovery, run_domain_enumeration as src2_run_domain_enumeration, run_http_probing as src2_run_http_probing, run_redirect_analysis as src2_run_redirect_analysis
from security_analyzer.main import build_orchestrator as src2_build_orchestrator
from security_analyzer.authentication import run_auth_session_lifecycle as src2_run_auth_session_lifecycle

class src2__LocalTestHandler(src2_BaseHTTPRequestHandler):

    def do_GET(self) -> None:
        if self.path == '/':
            self._reply(200, 'text/html', '<html><head><title>Test Portal</title></head><body>OK</body></html>')
        elif self.path == '/api':
            self._reply(302, 'text/plain', '', headers={'Location': '/api/v1'})
        elif self.path == '/api/v1':
            self._reply(200, 'application/json', '{"status":"ok"}')
        elif self.path == '/external-bounce':
            self._reply(302, 'text/plain', '', headers={'Location': 'https://evil.example/phish'})
        else:
            self._reply(404, 'text/plain', 'not found')

    def _reply(self, code: int, ctype: str, body: str, headers: dict[str, str] | None=None) -> None:
        raw = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:
        return

def test_normalizer_preserves_methods_paths_and_redacts_secrets(tmp_path: Path) -> None:
    ws = src2_WorkspaceManager(project_root=tmp_path)
    ws.init_scan('https://api.example.com')
    engine = src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['example.com']))
    norm = src2_EndpointNormalizer(engine)
    inv = src2_UnifiedEndpointInventory(ws)
    ep_get = norm.normalize('https://api.example.com/v1/orders?status=open&token=secret123', method='GET', source='browser_capture')
    ep_post = norm.normalize('https://api.example.com/v1/orders?status=open&token=secret123', method='POST', source='openapi')
    assert ep_get is not None and ep_post is not None
    assert ep_get.endpoint_id != ep_post.endpoint_id
    assert ep_get.path == '/v1/orders'
    assert ep_get.query_param_names == ['status', 'token']
    assert ep_get.sample_query_params['token'] == '[REDACTED]'
    assert ep_get.sample_query_params['status'] == 'open'
    ep_get_dup = norm.normalize('https://api.example.com/v1/orders?token=other&status=closed', method='GET', source='javascript_intel', status_code=200, reachable=True)
    assert ep_get_dup is not None
    assert ep_get_dup.endpoint_id == ep_get.endpoint_id
    inv.upsert_endpoint(ep_get)
    inv.upsert_endpoint(ep_get_dup)
    inv.upsert_endpoint(ep_post)
    saved = inv.save(stage_id='test')
    assert saved['summary']['total_endpoints'] == 2
    merged = [e for e in saved['endpoints'] if e['method'] == 'GET'][0]
    assert sorted(merged['discovery_sources']) == ['browser_capture', 'javascript_intel']
    assert merged['reachable'] is True

def test_end_to_end_discovery_pipeline_in_output_folder(tmp_path: Path) -> None:
    server = src2_ThreadingHTTPServer(('127.0.0.1', 0), src2__LocalTestHandler)
    port = server.server_address[1]
    thread = src2_threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f'http://127.0.0.1:{port}'
        scope_file = tmp_path / 'scope.yaml'
        scope_file.write_text(f"allowed_domains: ['127.0.0.1']\nallowed_ports: [{port}]\nallow_private_ips: true\n", encoding='utf-8')
        settings_file = tmp_path / 'settings.yaml'
        settings_file.write_text('scope:\n  check_dns: false\nlimits:\n  max_directory_words: 15\n  max_urls_per_stage: 50\n  max_concurrent_requests: 2\ntimeouts:\n  http_connect_sec: 3\n  http_read_sec: 5\n  max_redirects: 3\n', encoding='utf-8')
        orch = src2_build_orchestrator(target=base_url, scope_path=scope_file, settings_path=settings_file, project_root=tmp_path)
        ws = orch.workspace
        engine = orch.scope_engine
        cov = orch.coverage
        scan_dir = ws.scan_dir
        seeded_inventory = src2_UnifiedEndpointInventory(ws)
        external_redirect = src2_EndpointNormalizer(engine, cov).normalize(f'{base_url}/external-bounce', source='test_seed', stage_id='test')
        assert external_redirect is not None
        seeded_inventory.upsert_endpoint(external_redirect)
        seeded_inventory.save(stage_id='test')
        orch = src2_PipelineOrchestrator(target=base_url, workspace=ws, scope_engine=engine, coverage=cov, config={'scope': {'check_dns': False}, 'limits': {'max_directory_words': 15, 'max_urls_per_stage': 50}, 'timeouts': {'http_connect_sec': 3, 'http_read_sec': 5, 'max_redirects': 3}}, definitions=tuple((definition for definition in src2_STAGE_DEFINITIONS if definition.stage_id in {'domain_enumeration', 'auth_session_lifecycle', 'browser_capture', 'directory_discovery', 'http_probing', 'redirect_analysis'})))
        orch.register_runner('domain_enumeration', src2_run_domain_enumeration)
        orch.register_runner('auth_session_lifecycle', src2_run_auth_session_lifecycle)
        orch.register_runner('directory_discovery', src2_run_directory_discovery)
        orch.register_runner('http_probing', src2_run_http_probing)
        orch.register_runner('redirect_analysis', src2_run_redirect_analysis)
        orch.run(resume=False)
        assert (scan_dir / 'discovery/subdomains.json').exists()
        assert (scan_dir / 'discovery/directories.json').exists()
        assert (scan_dir / 'discovery/http_probes.json').exists()
        assert (scan_dir / 'discovery/redirects.json').exists()
        inv_data = ws.read_json('inventory/unified_endpoints.json')
        paths = {ep['path'] for ep in inv_data['endpoints']}
        assert '/' in paths
        assert '/api' in paths
        assert '/api/v1' in paths
        redirects = ws.read_json('discovery/redirects.json')['chains']
        blocked = next((chain for chain in redirects if chain['start_url'].endswith('/external-bounce')))
        assert 'blocked_out_of_scope' in blocked['terminated_reason']
        assert blocked['hops'][-1]['in_scope'] is False
    finally:
        server.shutdown()
        server.server_close()

def test_main_registers_discovery_runners(tmp_path: Path) -> None:
    scope_file = tmp_path / 'scope.yaml'
    scope_file.write_text("allowed_domains: ['127.0.0.1']\nallowed_ports: [8080]\nallow_private_ips: true\n", encoding='utf-8')
    orch = src2_build_orchestrator(target='http://127.0.0.1:8080', scope_path=scope_file, project_root=tmp_path)
    assert {'domain_enumeration', 'auth_session_lifecycle', 'browser_capture', 'directory_discovery', 'http_probing', 'redirect_analysis', 'security_review', 'online_security_checks', 'nuclei_assessment', 'server_dns_checks', 'api_js_intelligence', 'authorization_idor', 'business_logic_checks'} <= set(orch._runners)

def test_inventory_writes_independent_stage_contribution_snapshots(tmp_path: Path) -> None:
    ws = src2_WorkspaceManager(project_root=tmp_path)
    ws.init_scan('https://api.example.com')
    inventory = src2_UnifiedEndpointInventory(ws)
    inventory.save(stage_id='domain_enumeration')
    domain_snapshot_before = ws.read_json('inventory/contributions/domain_enumeration.json')
    endpoint = src2_EndpointNormalizer(src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['example.com']))).normalize('https://api.example.com/v1', method='GET', source='http_probing')
    assert endpoint is not None
    inventory.upsert_endpoint(endpoint)
    inventory.save(stage_id='http_probing')
    domain_snapshot_after = ws.read_json('inventory/contributions/domain_enumeration.json')
    http_snapshot = ws.read_json('inventory/contributions/http_probing.json')
    aggregate = ws.read_json('inventory/unified_endpoints.json')
    assert domain_snapshot_after == domain_snapshot_before
    assert domain_snapshot_after['stage_id'] == 'domain_enumeration'
    assert http_snapshot['stage_id'] == 'http_probing'
    assert len(http_snapshot['endpoints']) == 1
    assert len(aggregate['endpoints']) == 1

def test_endpoint_contract_keeps_safe_request_metadata_without_values() -> None:
    engine = src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['example.com']))
    normalizer = src2_EndpointNormalizer(engine)
    endpoint = normalizer.normalize('https://api.example.com/v1/profile', method='POST', source='playwright_network', auth_context='user_a', request_content_type='application/json', request_headers={'content-type': 'application/json', 'accept': 'application/json', 'authorization': 'Bearer should-never-be-stored', 'cookie': 'session=should-never-be-stored'}, request_body_schema={'format': 'json', 'schema': {'email': 'string', 'age': 'number'}})
    assert endpoint is not None
    serialized = endpoint.to_dict()
    assert serialized['method'] == 'POST'
    assert serialized['auth_contexts'] == ['user_a']
    assert serialized['request_content_type'] == 'application/json'
    assert serialized['request_headers'] == {'content-type': 'application/json', 'accept': 'application/json'}
    assert serialized['request_body_schema']['schema'] == {'email': 'string', 'age': 'number'}
    assert 'should-never-be-stored' not in str(serialized)

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step2_orchestrator.py
# -----------------------------------------------------------------------------

from pathlib import Path as src3_Path
import pytest as src3_pytest
from security_analyzer.core.coverage_tracker import CoverageTracker as src3_CoverageTracker
from security_analyzer.core.exceptions import ArtifactValidationError as src3_ArtifactValidationError, StageExecutionError as src3_StageExecutionError
from security_analyzer.core.orchestrator import PipelineOrchestrator as src3_PipelineOrchestrator, _strip_volatile_fields as src3__strip_volatile_fields
from security_analyzer.core.scope_engine import ScopeEngine as src3_ScopeEngine, ScopePolicy as src3_ScopePolicy
from security_analyzer.core.stage_registry import ArtifactSpec as src3_ArtifactSpec, StageDefinition as src3_StageDefinition, StageResult as src3_StageResult, StageStatus as src3_StageStatus, load_validated_stage_artifact as src3_load_validated_stage_artifact
from security_analyzer.core.workspace import WorkspaceManager as src3_WorkspaceManager

def src3__make_orchestrator(tmp_path: Path, definitions: tuple[StageDefinition, ...]):
    workspace = src3_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://example.test')
    engine = src3_ScopeEngine(src3_ScopePolicy(allowed_domains=['example.test']))
    coverage = src3_CoverageTracker(workspace)
    orchestrator = src3_PipelineOrchestrator(target='https://example.test', workspace=workspace, scope_engine=engine, coverage=coverage, config={}, definitions=definitions)
    return orchestrator

def test_volatile_fields_are_removed_recursively():
    value = {'stable': 1, 'generated_at': 'one', 'nested': {'value': 2, 'timestamp': 'two'}, 'items': [{'recorded_at': 'three', 'name': 'x'}]}
    assert src3__strip_volatile_fields(value) == {'stable': 1, 'nested': {'value': 2}, 'items': [{'name': 'x'}]}

def test_unknown_optional_dependency_is_rejected(tmp_path: Path):
    definitions = (src3_StageDefinition('stage_a', 'A', 'test', optional_dependencies=('missing',)),)
    with src3_pytest.raises(src3_StageExecutionError, match='unknown dependencies'):
        src3__make_orchestrator(tmp_path, definitions)

def test_optional_skipped_dependency_does_not_block_consumer(tmp_path: Path):
    definitions = (src3_StageDefinition('optional', 'Optional', 'test'), src3_StageDefinition('consumer', 'Consumer', 'test', dependencies=('optional',), optional_dependencies=('optional',)))
    orchestrator = src3__make_orchestrator(tmp_path, definitions)
    orchestrator.state['stages']['optional']['status'] = src3_StageStatus.SKIPPED.value
    ok, reason, artifacts = orchestrator._collect_upstream_artifacts(orchestrator.definitions['consumer'])
    assert ok is True
    assert reason == ''
    assert artifacts == {}

def test_failed_optional_dependency_does_not_block_consumer(tmp_path: Path):
    definitions = (src3_StageDefinition('optional', 'Optional', 'test'), src3_StageDefinition('consumer', 'Consumer', 'test', dependencies=('optional',), optional_dependencies=('optional',)))
    orchestrator = src3__make_orchestrator(tmp_path, definitions)
    orchestrator.state['stages']['optional']['status'] = src3_StageStatus.FAILED.value
    ok, reason, artifacts = orchestrator._collect_upstream_artifacts(orchestrator.definitions['consumer'])
    assert ok is True
    assert reason == ''
    assert artifacts == {}
    assert orchestrator._upstream_stage_fingerprints(orchestrator.definitions['consumer']) == {
        'optional': 'OPTIONAL_FAILED'
    }

def test_artifact_loader_rejects_failed_producer_even_if_file_exists(tmp_path: Path):
    definitions = (src3_StageDefinition('producer', 'Producer', 'test', artifacts=(src3_ArtifactSpec('data/result.json', ('schema_version', 'scan_id', 'stage_id', 'items')),)),)
    orchestrator = src3__make_orchestrator(tmp_path, definitions)
    ws = orchestrator.workspace
    ws.write_json_atomic('data/result.json', {'schema_version': '1.0', 'scan_id': ws.scan_id, 'stage_id': 'producer', 'items': []})
    orchestrator.state['stages']['producer'].update({'status': src3_StageStatus.FAILED.value, 'artifacts': ['data/result.json']})
    ws.write_json_atomic('scan_state.json', orchestrator.state)
    assert src3_load_validated_stage_artifact(ws, 'producer', 'data/result.json') is None

def test_artifact_loader_requires_recorded_artifact_path(tmp_path: Path):
    definitions = (src3_StageDefinition('producer', 'Producer', 'test', artifacts=(src3_ArtifactSpec('data/result.json', ('schema_version', 'scan_id', 'stage_id', 'items')),)),)
    orchestrator = src3__make_orchestrator(tmp_path, definitions)
    ws = orchestrator.workspace
    ws.write_json_atomic('data/result.json', {'schema_version': '1.0', 'scan_id': ws.scan_id, 'stage_id': 'producer', 'items': []})
    orchestrator.state['stages']['producer'].update({'status': src3_StageStatus.SUCCESS.value, 'artifacts': []})
    ws.write_json_atomic('scan_state.json', orchestrator.state)
    assert src3_load_validated_stage_artifact(ws, 'producer', 'data/result.json') is None

def test_upstream_fingerprint_ignores_volatile_timestamps(tmp_path: Path):
    definitions = (src3_StageDefinition('producer', 'Producer', 'test', artifacts=(src3_ArtifactSpec('data/producer.json', ('schema_version', 'scan_id', 'stage_id', 'value')),)), src3_StageDefinition('consumer', 'Consumer', 'test', dependencies=('producer',)))
    orchestrator = src3__make_orchestrator(tmp_path, definitions)
    ws = orchestrator.workspace
    ws.write_json_atomic('data/producer.json', {'schema_version': '1.0', 'scan_id': ws.scan_id, 'stage_id': 'producer', 'value': 7, 'generated_at': '2026-01-01T00:00:00Z'})
    orchestrator.state['stages']['producer'].update({'status': src3_StageStatus.SUCCESS.value, 'fingerprint': 'producer-fp', 'artifacts': ['data/producer.json']})
    before = orchestrator.compute_stage_fingerprint(orchestrator.definitions['consumer'])
    ws.write_json_atomic('data/producer.json', {'schema_version': '1.0', 'scan_id': ws.scan_id, 'stage_id': 'producer', 'value': 7, 'generated_at': '2026-02-01T00:00:00Z'})
    after = orchestrator.compute_stage_fingerprint(orchestrator.definitions['consumer'])
    assert before == after

def test_reusable_partial_stage_is_skipped_on_resume(tmp_path: Path):
    definitions = (src3_StageDefinition('partial_stage', 'Partial Stage', 'test', artifacts=(src3_ArtifactSpec('data/partial.json', ('schema_version', 'scan_id', 'stage_id', 'items')),)),)
    orchestrator = src3__make_orchestrator(tmp_path, definitions)
    calls = {'count': 0}

    def runner(ctx, stage_def):
        calls['count'] += 1
        ctx.workspace.write_json_atomic('data/partial.json', {'schema_version': '1.0', 'scan_id': ctx.workspace.scan_id, 'stage_id': stage_def.stage_id, 'items': []})
        from security_analyzer.core.stage_registry import StageResult
        return StageResult(stage_id=stage_def.stage_id, status=src3_StageStatus.PARTIAL, summary='Optional capability unavailable; deterministic fallback used', artifacts=['data/partial.json'], reusable_partial=True)
    orchestrator.register_runner('partial_stage', runner)
    assert orchestrator.run(resume=False) == src3_StageStatus.PARTIAL
    assert calls['count'] == 1
    assert orchestrator.run(resume=True) == src3_StageStatus.PARTIAL
    assert calls['count'] == 1

def test_resume_rejects_artifact_modified_after_success(tmp_path: Path):
    definitions = (src3_StageDefinition('producer', 'Producer', 'test', artifacts=(src3_ArtifactSpec('data/result.json', ('schema_version', 'scan_id', 'stage_id', 'value')),)),)
    orchestrator = src3__make_orchestrator(tmp_path, definitions)

    def runner(ctx, stage_def):
        ctx.workspace.write_json_atomic('data/result.json', {'schema_version': '1.0', 'scan_id': ctx.workspace.scan_id, 'stage_id': stage_def.stage_id, 'value': 1})
        from security_analyzer.core.stage_registry import StageResult
        return StageResult(stage_id=stage_def.stage_id, status=src3_StageStatus.SUCCESS, artifacts=['data/result.json'])
    orchestrator.register_runner('producer', runner)
    orchestrator.run(resume=False)
    fingerprint = orchestrator.compute_stage_fingerprint(orchestrator.definitions['producer'])
    payload = orchestrator.workspace.read_json('data/result.json')
    payload['value'] = 2
    orchestrator.workspace.write_json_atomic('data/result.json', payload)
    assert orchestrator._can_reuse_completed_stage(orchestrator.definitions['producer'], fingerprint) is False

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step4_endpoint_inventory.py
# -----------------------------------------------------------------------------

from pathlib import Path as src4_Path
import pytest as src4_pytest
from security_analyzer.core.exceptions import ArtifactValidationError as src4_ArtifactValidationError
from security_analyzer.core.scope_engine import ScopeEngine as src4_ScopeEngine, ScopePolicy as src4_ScopePolicy
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src4_STAGE_DEFINITIONS
from security_analyzer.core.workspace import WorkspaceManager as src4_WorkspaceManager
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer as src4_EndpointNormalizer, normalize_endpoint as src4_normalize_endpoint
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory as src4_UnifiedEndpointInventory

def src4__workspace(tmp_path: Path) -> src4_WorkspaceManager:
    workspace = src4_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://api.example.com')
    return workspace

def src4__engine() -> src4_ScopeEngine:
    return src4_ScopeEngine(src4_ScopePolicy(allowed_domains=['example.com']))

def test_normalizer_rejects_malformed_and_invalid_methods() -> None:
    engine = src4__engine()
    assert src4_normalize_endpoint('https://api.example.com:bad/x', scope_engine=engine) is None
    assert src4_normalize_endpoint('https://api.example.com/x', scope_engine=engine, method='GET\r\nX: y') is None
    assert src4_normalize_endpoint('https://api.example.com/' + 'x' * 9000, scope_engine=engine) is None
    assert src4_normalize_endpoint('https://evil.example/x', scope_engine=engine) is None

def test_normalizer_redacts_secrets_without_over_redacting_harmless_names() -> None:
    endpoint = src4_normalize_endpoint('https://api.example.com/items?access_token=secret&email=a%40b.com&jwt=abcdefghijk.abcdefghijk.abcdefghijk&monkey=banana&page=2', scope_engine=src4__engine())
    assert endpoint is not None
    assert 'secret' not in endpoint.canonical_url
    assert 'a%40b.com' not in endpoint.canonical_url
    assert 'abcdefghijk' not in endpoint.canonical_url
    assert endpoint.sample_query_params['access_token'] == '[REDACTED]'
    assert endpoint.sample_query_params['email'] == '[REDACTED]'
    assert endpoint.sample_query_params['jwt'] == '[REDACTED]'
    assert endpoint.sample_query_params['monkey'] == 'banana'
    assert 'page=2' in endpoint.canonical_url

def test_normalizer_redacts_pii_and_bearer_tokens_in_path_segments() -> None:
    endpoint = src4_normalize_endpoint('https://api.example.com/users/alice%40example.com/abcdefghijk.abcdefghijk.abcdefghijk', scope_engine=src4__engine())
    assert endpoint is not None
    assert 'alice' not in endpoint.path
    assert 'abcdefghijk' not in endpoint.path
    assert '%5BREDACTED%5D' in endpoint.path

def test_endpoint_identity_is_stable_across_query_values_and_order() -> None:
    first = src4_normalize_endpoint('https://api.example.com/v1/orders?status=open&page=1', scope_engine=src4__engine())
    second = src4_normalize_endpoint('https://api.example.com/v1/orders?page=2&status=closed', scope_engine=src4__engine(), source='javascript')
    assert first is not None
    assert second is not None
    assert first.endpoint_id == second.endpoint_id

def test_inventory_merges_sources_and_returns_defensive_copies(tmp_path: Path) -> None:
    workspace = src4__workspace(tmp_path)
    normalizer = src4_EndpointNormalizer(src4__engine())
    inventory = src4_UnifiedEndpointInventory(workspace)
    first = normalizer.normalize('https://api.example.com/v1/orders?status=open', source='browser_capture', status_code=200)
    second = normalizer.normalize('https://api.example.com/v1/orders?status=closed', source='javascript_intel', status_code=204)
    assert first is not None
    assert second is not None
    inventory.upsert_endpoint(first)
    inventory.upsert_endpoint(second)
    returned = inventory.all_endpoints()[0]
    returned.discovery_sources.clear()
    saved = inventory.save(stage_id='test_inventory')
    assert saved['summary']['total_endpoints'] == 1
    assert saved['endpoints'][0]['discovery_sources'] == ['browser_capture', 'javascript_intel']
    assert saved['endpoints'][0]['status_codes'] == [200, 204]
    reloaded = src4_UnifiedEndpointInventory(workspace)
    assert len(reloaded.all_endpoints()) == 1
    assert reloaded.all_endpoints()[0].discovery_sources == ['browser_capture', 'javascript_intel']

def test_inventory_rejects_cross_scan_data(tmp_path: Path) -> None:
    workspace = src4__workspace(tmp_path)
    inventory = src4_UnifiedEndpointInventory(workspace)
    inventory.save(stage_id='test')
    payload = workspace.read_json(src4_UnifiedEndpointInventory.RELATIVE_PATH)
    payload['scan_id'] = 'another-scan'
    workspace.write_json_atomic(src4_UnifiedEndpointInventory.RELATIVE_PATH, payload)
    with src4_pytest.raises(src4_ArtifactValidationError, match='different scan'):
        src4_UnifiedEndpointInventory(workspace)

def test_browser_capture_declares_stage_owned_inventory_snapshot() -> None:
    browser = next((item for item in src4_STAGE_DEFINITIONS if item.stage_id == 'browser_capture'))
    paths = {artifact.relative_path for artifact in browser.artifacts}
    assert 'inventory/unified_endpoints.json' not in paths
    assert 'inventory/contributions/browser_capture.json' in paths

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step3_inventory_fixes.py
# -----------------------------------------------------------------------------

from security_analyzer.core.coverage_tracker import CoverageTracker as src5_CoverageTracker
from security_analyzer.core.scope_engine import ScopeEngine as src5_ScopeEngine, ScopePolicy as src5_ScopePolicy
from security_analyzer.core.workspace import WorkspaceManager as src5_WorkspaceManager
from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer as src5_EndpointNormalizer
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory as src5_UnifiedEndpointInventory
from security_analyzer.intelligence.js_bundle_analyzer import API_PATH_RE as src5_API_PATH_RE

def src5__setup(tmp_path):
    workspace = src5_WorkspaceManager(project_root=tmp_path, output_root_name='output')
    workspace.init_scan('https://t.example/')
    engine = src5_ScopeEngine(src5_ScopePolicy(allowed_domains=['t.example']))
    coverage = src5_CoverageTracker(workspace)
    return (workspace, src5_EndpointNormalizer(engine, coverage), src5_UnifiedEndpointInventory(workspace))

def test_unprobed_endpoint_is_not_marked_unreachable(tmp_path):
    _, normalizer, _ = src5__setup(tmp_path)
    endpoint = normalizer.normalize('https://t.example/api/x', source='api_spec', stage_id='api_js_intelligence')
    assert endpoint.reachable is None
    seen = normalizer.normalize('https://t.example/api/y', source='probe', stage_id='s', status_code=200)
    assert seen.reachable is True

def test_js_routes_with_query_string_are_extracted():
    found = [match.group(1) for match in src5_API_PATH_RE.finditer('fetch("/api/items?limit=10&page=2")')]
    assert found == ['/api/items?limit=10&page=2']

def test_methods_stay_separate_and_identity_is_recorded(tmp_path):
    _, normalizer, inventory = src5__setup(tmp_path)
    get = normalizer.normalize('https://t.example/api/p', method='GET', source='browser', stage_id='s', auth_context='user_a')
    post = normalizer.normalize('https://t.example/api/p', method='POST', source='browser', stage_id='s')
    inventory.upsert_endpoint(get)
    inventory.upsert_endpoint(post)
    assert len(inventory.get_endpoints()) == 2
    assert get.auth_contexts == ['user_a'] and get.authenticated is True
    assert post.auth_contexts == ['anonymous']

def test_inventory_summary_and_versioned_export(tmp_path):
    workspace, normalizer, inventory = src5__setup(tmp_path)
    inventory.upsert_endpoint(normalizer.normalize('https://t.example/a', source='s', stage_id='s'))
    inventory.upsert_endpoint(normalizer.normalize('https://t.example/a', method='POST', source='s', stage_id='s'))
    data = inventory.save(stage_id='http_probing')
    assert data['summary']['total_endpoints'] == 2
    assert data['summary']['unique_urls'] == 1
    assert data['summary']['unprobed_endpoints'] == 2
    exports = list((workspace.scan_dir / 'inventory' / 'export').glob('unified_endpoints.v*.json'))
    assert len(exports) == 1

def test_inventory_is_stable_for_same_inputs(tmp_path):
    _, normalizer, inventory = src5__setup(tmp_path)
    for url in ('https://t.example/b', 'https://t.example/a'):
        inventory.upsert_endpoint(normalizer.normalize(url, source='s', stage_id='s'))
    first = [endpoint['endpoint_id'] for endpoint in inventory.save(stage_id='x')['endpoints']]
    second = [endpoint['endpoint_id'] for endpoint in inventory.save(stage_id='x')['endpoints']]
    assert first == second

def test_api_templates_use_owned_resource_id_and_preserve_template_tag(tmp_path, monkeypatch):
    from security_analyzer.core.orchestrator import ExecutionContext
    from security_analyzer.core.stage_registry import StageDefinition
    from security_analyzer.intelligence.api_intelligence import run_api_js_intelligence
    from security_analyzer.intelligence.openapi_analyzer import ApiOperationRecord
    workspace, _, _ = src5__setup(tmp_path)
    profile_path = tmp_path / 'auth_profiles.yaml'
    profile_path.write_text('identities:\n  user_a:\n    auth_method: bearer_token\n    owned_resource_ids: [acct-42, acct-99]\n', encoding='utf-8')
    operation = ApiOperationRecord(operation_id='profile.get', method='GET', url='https://t.example/api/profile/{profile_id}', path='/api/profile/{profile_id}', source='openapi', path_params=['profile_id'])
    monkeypatch.setattr('security_analyzer.intelligence.api_intelligence.OpenApiAnalyzer.discover_and_parse', lambda *_args, **_kwargs: ([], [operation], []))
    monkeypatch.setattr('security_analyzer.intelligence.api_intelligence.GraphQlAnalyzer.analyze', lambda *_args, **_kwargs: ([], [], []))
    monkeypatch.setattr('security_analyzer.intelligence.api_intelligence.JsBundleAnalyzer.discover_bundle_urls', lambda *_args, **_kwargs: [])
    monkeypatch.setattr('security_analyzer.intelligence.api_intelligence.JsBundleAnalyzer.analyze_bundles', lambda *_args, **_kwargs: ([], ['https://t.example/api/orders/{order_id}'], []))
    engine = src5_ScopeEngine(src5_ScopePolicy(allowed_domains=['t.example']))
    ctx = ExecutionContext(target='https://t.example/', workspace=workspace, scope_engine=engine, coverage=src5_CoverageTracker(workspace), config={'auth_profiles_path': str(profile_path)})
    run_api_js_intelligence(ctx, StageDefinition('api_js_intelligence', 'API', 'analysis'))
    endpoints = src5_UnifiedEndpointInventory(workspace).get_endpoints()
    owned_urls = {endpoint.url for endpoint in endpoints}
    assert any('/api/profile/acct-42' in url for url in owned_urls)
    assert any('/api/profile/acct-99' in url for url in owned_urls)
    assert any('/api/orders/acct-42' in url for url in owned_urls)
    assert any('/api/orders/acct-99' in url for url in owned_urls)
    assert all('{' not in url and '}' not in url for url in owned_urls)
    owned_endpoint = next((endpoint for endpoint in endpoints if '/api/profile/acct-42' in endpoint.url))
    assert 'template:/api/profile/{profile_id}' in owned_endpoint.tags

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step3_resources.py
# -----------------------------------------------------------------------------

import sys as src6_sys
import pytest as src6_pytest
from security_analyzer.core.config_validation import validate_settings as src6_validate_settings
from security_analyzer.core.dependency_manager import DependencyManager as src6_DependencyManager
from security_analyzer.core.exceptions import ConfigurationError as src6_ConfigurationError
from security_analyzer.core.resource_governor import ResourceGovernor as src6_ResourceGovernor, ResourceLimitExceeded as src6_ResourceLimitExceeded

def test_settings_merge_step3_resource_defaults():
    cfg = src6_validate_settings({'limits': {'max_total_requests': 50}})
    assert cfg['limits']['max_total_requests'] == 50
    assert cfg['limits']['max_concurrent_requests'] == 10
    assert cfg['timeouts']['nuclei_sec'] == 300

@src6_pytest.mark.parametrize('settings', [{'limits': {'max_total_requests': 0}}, {'limits': {'requests_per_host_per_sec': -1}}, {'limits': {'max_concurrent_processes': 5, 'max_external_processes': 2}}, {'timeouts': {'nuclei_sec': 0}}, {'nuclei': {'concurrency': 30, 'rate_limit': 10}}])
def test_invalid_resource_settings_are_rejected(settings):
    with src6_pytest.raises(src6_ConfigurationError):
        src6_validate_settings(settings)

def test_dependency_profiles_reject_unknown_profile():
    with src6_pytest.raises(ValueError):
        src6_DependencyManager().inspect_all('unrecognized')

def test_request_budget_is_scan_wide():
    governor = src6_ResourceGovernor({'max_total_requests': 1, 'requests_per_host_per_sec': 1000, 'max_concurrent_requests': 1})
    governor.acquire_request('https://example.test/')
    governor.release_request()
    with src6_pytest.raises(src6_ResourceLimitExceeded):
        governor.acquire_request('https://example.test/')

def test_process_output_is_bounded():
    governor = src6_ResourceGovernor({'max_external_processes': 2, 'max_concurrent_processes': 1, 'max_process_output_bytes': 128})
    result = governor.run_process(['/bin/sh', '-c', "printf '%1000s' x"], timeout_sec=5)
    assert result.output_truncated is True
    assert len(result.stdout.encode()) <= 128
    assert result.returncode == 125

def test_process_timeout_terminates_process():
    governor = src6_ResourceGovernor({'max_external_processes': 2, 'max_concurrent_processes': 1})
    result = governor.run_process([src6_sys.executable, '-c', 'import time; time.sleep(5)'], timeout_sec=0.2)
    assert result.timed_out is True
    assert result.returncode == 124


def test_http_probing_skips_destructive_and_non_read_endpoints(tmp_path: Path) -> None:
    from unittest.mock import patch
    from security_analyzer.core.coverage_tracker import CoverageTracker
    from security_analyzer.core.orchestrator import ExecutionContext
    from security_analyzer.core.stage_registry import StageDefinition
    from security_analyzer.discovery.endpoint_normalizer import EndpointNormalizer
    from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
    from security_analyzer.discovery.http_probing import run_http_probing

    workspace = src2_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan("https://authorized.example")
    engine = src2_ScopeEngine(src2_ScopePolicy(allowed_domains=["authorized.example"]))
    coverage = CoverageTracker(workspace)
    inventory = UnifiedEndpointInventory(workspace)
    normalizer = EndpointNormalizer(engine, coverage)

    destructive_get = normalizer.normalize(
        "https://authorized.example/account/unsubscribe",
        method="GET",
        source="test",
        stage_id="test",
    )
    write_method = normalizer.normalize(
        "https://authorized.example/api/orders/123",
        method="POST",
        source="test",
        stage_id="test",
    )
    safe_get = normalizer.normalize(
        "https://authorized.example/api/orders/123",
        method="GET",
        source="test",
        stage_id="test",
    )
    assert destructive_get is not None
    assert write_method is not None
    assert safe_get is not None

    inventory.upsert_endpoint(destructive_get)
    inventory.upsert_endpoint(write_method)
    inventory.upsert_endpoint(safe_get)
    inventory.save(stage_id="test")

    context = ExecutionContext(
        target="https://authorized.example",
        workspace=workspace,
        scope_engine=engine,
        coverage=coverage,
        config={"scope": {"check_dns": False}, "limits": {"max_urls_per_stage": 20}},
    )
    stage = StageDefinition("http_probing", "HTTP probing", "discovery")

    from types import SimpleNamespace

    safe_response = SimpleNamespace(
        status_code=200,
        headers={"Content-Type": "application/json"},
        text="{}",
        content=b"{}",
    )
    with patch(
        "security_analyzer.discovery.http_probing.ScopedHttpClient.request",
        return_value=safe_response,
    ) as request:
        result = run_http_probing(context, stage)

    assert request.call_count == 1
    assert request.call_args.args[1] == safe_get.url
    assert result.metrics["destructive_or_non_read_skipped"] == 2
    assert result.status.value == "SUCCESS"


def test_coverage_tracker_restores_previous_scan_coverage_on_resume(tmp_path: Path):
    workspace = src3_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://example.test')
    first = src3_CoverageTracker(workspace, limits={'max_requests': 100})
    first.record_stage_coverage('domain_enumeration', status='SUCCESS', targets_total=15, targets_tested=15)
    first.record_target_tested('http_probing', 'https://example.test/api/orders?token=secret', status_code=200)
    first.record_request_failure('redirect_analysis', 'https://example.test/redirect?key=secret', 'timeout')
    first.record_skipped_check('directory_discovery', 'ffuf', 'not installed')

    resumed = src3_CoverageTracker(workspace, limits={'max_requests': 100})
    snapshot = resumed.snapshot()
    assert snapshot['stages']['domain_enumeration']['targets_tested'] == 15
    assert len(snapshot['tested_targets']) == 1
    assert len(snapshot['request_failures']) == 1
    assert len(snapshot['skipped_checks']) == 1
    assert 'secret' not in str(snapshot)

    resumed.record_stage_coverage('http_probing', status='PARTIAL', targets_total=20, targets_tested=10)
    after = src3_CoverageTracker(workspace).snapshot()
    assert after['stages']['domain_enumeration']['status'] == 'SUCCESS'
    assert after['stages']['http_probing']['status'] == 'PARTIAL'


def test_coverage_tracker_rejects_coverage_from_another_scan(tmp_path: Path):
    workspace = src3_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://example.test')
    workspace.write_json_atomic('coverage_summary.json', {
        'schema_version': '1.0',
        'scan_id': 'different-scan',
        'stages': {},
        'tested_targets': [],
        'out_of_scope_blocks': [],
        'request_failures': [],
        'skipped_checks': [],
    })
    with src3_pytest.raises(src3_ArtifactValidationError, match='different scan'):
        src3_CoverageTracker(workspace)


def test_failed_optional_stage_does_not_prevent_downstream_report_stage(tmp_path: Path):
    definitions = (
        src3_StageDefinition('optional_scanner', 'Optional scanner', 'analysis'),
        src3_StageDefinition(
            'report_consumer',
            'Report consumer',
            'reporting',
            dependencies=('optional_scanner',),
            optional_dependencies=('optional_scanner',),
            artifacts=(src3_ArtifactSpec('reports/consumer.json', ('schema_version', 'scan_id', 'stage_id', 'generated')),),
        ),
    )
    orchestrator = src3__make_orchestrator(tmp_path, definitions)
    consumer_calls = []

    def failed_optional(_ctx, _definition):
        return src3_StageResult(
            'optional_scanner',
            src3_StageStatus.FAILED,
            summary='Optional scanner failed',
            error='controlled test failure',
        )

    def report_consumer(ctx, definition):
        consumer_calls.append(definition.stage_id)
        ctx.workspace.write_json_atomic('reports/consumer.json', {
            'schema_version': '1.0',
            'scan_id': ctx.workspace.scan_id,
            'stage_id': definition.stage_id,
            'generated': True,
        })
        return src3_StageResult(
            definition.stage_id,
            src3_StageStatus.SUCCESS,
            summary='Report generated despite optional scanner failure',
            artifacts=['reports/consumer.json'],
        )

    orchestrator.register_runner('optional_scanner', failed_optional)
    orchestrator.register_runner('report_consumer', report_consumer)
    overall = orchestrator.run()
    assert overall == src3_StageStatus.FAILED
    assert consumer_calls == ['report_consumer']
    assert orchestrator.state['stages']['report_consumer']['status'] == 'SUCCESS'
    assert orchestrator.workspace.read_json('reports/consumer.json')['generated'] is True
