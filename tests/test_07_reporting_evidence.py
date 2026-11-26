from __future__ import annotations


# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step8_reporting.py
# -----------------------------------------------------------------------------

import json as src1_json
import threading as src1_threading
from http.server import BaseHTTPRequestHandler as src1_BaseHTTPRequestHandler, ThreadingHTTPServer as src1_ThreadingHTTPServer
from pathlib import Path as src1_Path
from unittest.mock import patch as src1_patch
from security_analyzer.core.coverage_tracker import CoverageTracker as src1_CoverageTracker
from security_analyzer.core.orchestrator import ExecutionContext as src1_ExecutionContext, PipelineOrchestrator as src1_PipelineOrchestrator
from security_analyzer.core.scope_engine import ScopeEngine as src1_ScopeEngine, ScopePolicy as src1_ScopePolicy
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src1_STAGE_DEFINITIONS, StageStatus as src1_StageStatus
from security_analyzer.core.workspace import WorkspaceManager as src1_WorkspaceManager
from security_analyzer.main import register_available_stages as src1_register_available_stages
from security_analyzer.reporting import run_consolidated_reporting as src1_run_consolidated_reporting

class src1__FullPipelineTestHandler(src1_BaseHTTPRequestHandler):

    def do_GET(self) -> None:
        if self.path == '/':
            html = "<html><head><title>App &lt;Home&gt;</title></head><body><a href='/api/public'>Public</a></body></html>"
            self._reply(200, 'text/html', html, {'Access-Control-Allow-Origin': 'https://untrusted-origin.example'})
        elif self.path == '/api/public':
            self._reply(200, 'application/json', '{"ok":true}')
        else:
            self._reply(404, 'text/plain', 'not found')

    def _reply(self, code: int, ctype: str, body: str, extra: dict[str, str] | None=None) -> None:
        raw = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(raw)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:
        return

def test_consolidated_report_verdict_separation_and_xss_escaping(tmp_path: Path) -> None:
    ws = src1_WorkspaceManager(project_root=tmp_path)
    scan_dir = ws.init_scan('https://example.com')
    engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['example.com']))
    cov = src1_CoverageTracker(ws)
    ws.write_json_atomic('scope_snapshot.json', engine.policy.to_dict())
    ws.write_json_atomic('verification/evidence/find_conf.json', {'schema_version': '1.0', 'scan_id': ws.scan_id, 'finding_id': 'find_conf'})
    ev_sha = ws.file_sha256('verification/evidence/find_conf.json')
    ws.write_json_atomic('verification/verified_findings.json', {'schema_version': '1.0', 'scan_id': ws.scan_id, 'stage_id': 'evidence_verification', 'findings': [{'finding_id': 'find_conf', 'title': 'Confirmed IDOR <script>alert(1)</script>', 'category': 'idor_bola', 'severity': 'HIGH', 'verdict': 'CONFIRMED', 'confidence': 0.95, 'asset_id': 'asset_1', 'endpoint_id': 'ep_1', 'identity_id': 'user_b', 'description': 'Cross-user access reproduced', 'evidence_ids': ['ev_1'], 'metadata': {'target_url': 'https://example.com/api/orders/102', 'severity_assessment': {'risk_score': 7.6, 'risk_band': 'HIGH', 'label': 'Internal ranking score (0-10). This is NOT a CVSS score.', 'cvss': None}}}, {'finding_id': 'find_rev', 'title': 'Mass Assignment Surface', 'category': 'mass_assignment_surface', 'severity': 'MEDIUM', 'verdict': 'NEEDS_HUMAN_REVIEW', 'confidence': 0.65, 'asset_id': 'asset_1', 'endpoint_id': 'ep_2', 'identity_id': 'user_a', 'description': 'Role field in schema', 'evidence_ids': [], 'metadata': {'target_url': 'https://example.com/api/users/1'}}, {'finding_id': 'find_tls', 'title': 'TLS 1.0 accepted', 'category': 'tls_legacy_protocol', 'severity': 'LOW', 'verdict': 'CONFIRMED', 'confidence': 0.95, 'asset_id': 'asset_1', 'endpoint_id': 'ep_tls', 'identity_id': 'anonymous', 'description': 'Legacy protocol negotiation succeeded', 'evidence_ids': [], 'metadata': {'target_url': 'https://example.com/'}}, {'finding_id': 'find_fp', 'title': 'Transient Glitch', 'category': 'idor_bola', 'severity': 'CRITICAL', 'verdict': 'FALSE_POSITIVE', 'confidence': 0.1, 'asset_id': 'asset_1', 'endpoint_id': 'ep_3', 'identity_id': 'user_b', 'description': 'Did not reproduce', 'evidence_ids': [], 'metadata': {'verification': {'reason': '403 Forbidden on replay'}}}], 'evidence_records': [{'evidence_id': 'ev_1', 'artifact_path': 'verification/evidence/find_conf.json', 'evidence_type': 'idor_differential_replay', 'summary': 'IDOR proof', 'sha256': ev_sha}]})
    ws.write_json_atomic('scan_state.json', {'schema_version': '2.0', 'scan_id': ws.scan_id, 'target': 'https://example.com', 'overall_status': 'SUCCESS', 'stages': {'evidence_verification': {'status': 'SUCCESS', 'fingerprint': 'test', 'artifacts': ['verification/verified_findings.json']}, 'nuclei_assessment': {'status': 'SKIPPED', 'summary': 'Nuclei unavailable'}}})
    ctx = src1_ExecutionContext(target='https://example.com', workspace=ws, scope_engine=engine, coverage=cov, config={})
    rep_def = next((s for s in src1_STAGE_DEFINITIONS if s.stage_id == 'consolidated_reporting'))
    res = src1_run_consolidated_reporting(ctx, rep_def)
    assert res.status == src1_StageStatus.SUCCESS
    rep_json = ws.read_json('reports/security_report.json')
    assert rep_json['summary']['confirmed_count'] == 2
    assert rep_json['summary']['confirmed_vulnerability_count'] == 1
    assert rep_json['summary']['confirmed_configuration_count'] == 1
    assert len(rep_json['confirmed_vulnerabilities']) == 1
    assert len(rep_json['confirmed_configuration_issues']) == 1
    assert rep_json['summary']['confirmed_by_severity']['HIGH'] == 1
    assert rep_json['summary']['confirmed_by_severity']['CRITICAL'] == 0
    assert rep_json['summary']['review_queue_count'] == 1
    assert rep_json['summary']['suppressed_false_positives_count'] == 1
    assert rep_json['confirmed_findings'][0]['resolved_evidence'][0]['verified_sha256'] == ev_sha
    md_text = (scan_dir / 'reports/security_report.md').read_text(encoding='utf-8')
    assert '## 3. Confirmed Vulnerabilities' in md_text
    assert '## 3b. Confirmed Configuration Issues' in md_text
    assert 'Internal ranking (not CVSS)' in md_text
    assert '## 3c. Incomplete Coverage' in md_text
    assert '## 5. Findings Requiring Human Review' in md_text
    assert '## 6. Suppressed False Positives' in md_text
    html_text = (scan_dir / 'reports/security_report.html').read_text(encoding='utf-8')
    assert '<script>alert(1)</script>' not in html_text
    assert '&lt;script&gt;alert(1)&lt;/script&gt;' in html_text
    assert 'Internal ranking (not CVSS)' in html_text

def test_full_15_stage_end_to_end_pipeline(tmp_path: Path) -> None:
    server = src1_ThreadingHTTPServer(('127.0.0.1', 0), src1__FullPipelineTestHandler)
    port = server.server_address[1]
    thread = src1_threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base_url = f'http://127.0.0.1:{port}'
        ws = src1_WorkspaceManager(project_root=tmp_path)
        scan_dir = ws.init_scan(base_url)
        engine = src1_ScopeEngine(src1_ScopePolicy(allowed_domains=['127.0.0.1'], allowed_ports=[port], allow_private_ips=True))
        cov = src1_CoverageTracker(ws)
        orch = src1_PipelineOrchestrator(target=base_url, workspace=ws, scope_engine=engine, coverage=cov, config={'scope': {'check_dns': False}, 'limits': {'max_directory_words': 5, 'max_urls_per_stage': 25}, 'timeouts': {'http_connect_sec': 3, 'http_read_sec': 5, 'max_redirects': 2}, 'ai_triage': {'enabled': False}})
        src1_register_available_stages(orch)
        assert set(orch._runners.keys()) == {s.stage_id for s in src1_STAGE_DEFINITIONS}
        with src1_patch('security_analyzer.browser.application_crawler.is_playwright_installed', return_value=False), src1_patch('security_analyzer.scanners.nuclei_runner.shutil.which', return_value=None):
            overall = orch.run(resume=False)
        assert overall in {src1_StageStatus.SUCCESS, src1_StageStatus.PARTIAL}
        assert (scan_dir / 'reports/security_report.json').exists()
        assert (scan_dir / 'reports/security_report.md').exists()
        assert (scan_dir / 'reports/security_report.html').exists()
        final_rep = ws.read_json('reports/security_report.json')
        review_cats = {f['category'] for f in final_rep['review_queue']}
        assert 'cors_origin_reflection' in review_cats
    finally:
        server.shutdown()
        server.server_close()

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step9_evidence_contracts.py
# -----------------------------------------------------------------------------

import json as src2_json
import socket as src2_socket
from pathlib import Path as src2_Path
from types import SimpleNamespace as src2_SimpleNamespace
from unittest.mock import patch as src2_patch
import pytest as src2_pytest
from security_analyzer.core.exceptions import ConfigurationError as src2_ConfigurationError
from security_analyzer.core.scope_engine import ScopeEngine as src2_ScopeEngine, ScopePolicy as src2_ScopePolicy
from security_analyzer.core.workspace import WorkspaceManager as src2_WorkspaceManager
from security_analyzer.models.evidence import EvidenceRecord as src2_EvidenceRecord
from security_analyzer.models.finding import FindingRecord as src2_FindingRecord, Severity as src2_Severity, Verdict as src2_Verdict
from security_analyzer.verification.ai_triage import OptionalAiTriage as src2_OptionalAiTriage, _validate_ai_endpoint as src2__validate_ai_endpoint
from security_analyzer.verification.confidence_scorer import ConfidenceScorer as src2_ConfidenceScorer
from security_analyzer.verification.evidence_store import EvidenceStore as src2_EvidenceStore
from security_analyzer.verification.poc_replayer import ReplayOutcome as src2_ReplayOutcome
from security_analyzer.verification.severity_assessor import SeverityAssessor as src2_SeverityAssessor

def src2__workspace(tmp_path: Path) -> src2_WorkspaceManager:
    workspace = src2_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://authorized.example')
    return workspace

def test_evidence_store_indexes_and_verifies_immutable_artifact(tmp_path: Path) -> None:
    workspace = src2__workspace(tmp_path)
    evidence_id = 'ev_test_0001'
    finding_id = 'find_test_0001'
    artifact = 'verification/evidence/find_test_0001.json'
    workspace.write_json_atomic(artifact, {'schema_version': '1.1', 'scan_id': workspace.scan_id, 'finding_id': finding_id, 'evidence_id': evidence_id, 'telemetry': {'Authorization': 'Bearer do-not-store'}})
    record = src2_EvidenceRecord(artifact_path=artifact, evidence_type='test', summary='proof', sha256=workspace.file_sha256(artifact), evidence_id=evidence_id)
    with src2_EvidenceStore(workspace) as store:
        integrity = store.verify_record(record, finding_id=finding_id)
        assert integrity['valid'] is True
        store.record_evidence(record, finding_id=finding_id, integrity=integrity)
        store.record_finding({'finding_id': finding_id, 'category': 'test', 'severity': 'HIGH', 'verdict': 'CONFIRMED', 'confidence': 0.95})
        store.record_replay({'finding_id': finding_id, 'verdict': 'CONFIRMED', 'replayed': True, 'reproducible': True, 'identity_contrast_verified': False, 'evidence_integrity': True})
        assert store.summary() == {'evidence_total': 1, 'evidence_verified': 1, 'evidence_invalid': 0, 'findings_indexed': 1, 'replay_outcomes': 1}
    workspace.write_json_atomic(artifact, {'schema_version': '1.1', 'scan_id': workspace.scan_id, 'finding_id': finding_id, 'evidence_id': evidence_id, 'telemetry': {'result': 'tampered'}})
    with src2_EvidenceStore(workspace) as store:
        integrity = store.verify_record(record, finding_id=finding_id)
        assert integrity['valid'] is False
        assert integrity['reason'] == 'sha256_mismatch'

def test_evidence_store_rejects_path_escape(tmp_path: Path) -> None:
    workspace = src2__workspace(tmp_path)
    record = src2_EvidenceRecord(artifact_path='../outside.json', evidence_type='test', summary='unsafe', sha256='abc')
    with src2_EvidenceStore(workspace) as store:
        result = store.verify_record(record, finding_id='find_1')
    assert result['valid'] is False
    assert result['reason'] == 'unsafe_artifact_path'

def test_ai_prompt_uses_real_finding_fields_and_redacts_sensitive_metadata() -> None:
    finding = src2_FindingRecord(title='Bearer eyJabcdefgh.eyJabcdefgh.eyJabcdefgh leaked', category='secret_exposure', severity=src2_Severity.HIGH, verdict=src2_Verdict.NEEDS_HUMAN_REVIEW, confidence=0.72, asset_id='asset_1', endpoint_id='endpoint_1', description='Potential password=topsecret in response', metadata={'target_url': 'https://authorized.example/api?token=supersecret', 'authorization': 'Bearer sensitive', 'corroborating_sources': ['scanner_a', 'scanner_b']})
    triage = src2_OptionalAiTriage({'ai_triage': {'enabled': True, 'provider': 'openrouter'}})
    prompt = triage._build_prompt(finding)
    assert 'endpoint_1' in prompt
    assert 'asset_1' in prompt
    assert 'supersecret' not in prompt
    assert 'topsecret' not in prompt
    assert 'Bearer sensitive' not in prompt
    assert 'finding.location' not in prompt

def test_ai_endpoint_allowlist_cannot_be_expanded_to_arbitrary_host() -> None:
    with src2_pytest.raises(src2_ConfigurationError):
        src2__validate_ai_endpoint('https://evil.example/v1/chat/completions', ['evil.example'])
    assert src2__validate_ai_endpoint('https://api.openai.com/v1/chat/completions').startswith('https://api.openai.com/')

def test_ai_triage_is_advisory_and_never_changes_verdict_or_severity() -> None:
    finding = src2_FindingRecord(title='Possible access control issue', category='idor_bola', severity=src2_Severity.HIGH, verdict=src2_Verdict.NEEDS_HUMAN_REVIEW, confidence=0.7, asset_id='asset_1', endpoint_id='endpoint_1')
    triage = src2_OptionalAiTriage({'ai_triage': {'enabled': True, 'provider': 'openrouter'}})
    with src2_patch.dict('os.environ', {'OPENROUTER_API_KEY': 'test-key'}):
        with src2_patch.object(triage, '_call_openai_compatible', return_value={'rationale': 'Review ownership proof', 'remediation': 'Apply object-level authorization', 'recommend_human_review': False}):
            result, summary = triage.triage_findings([finding])
    assert result[0].verdict == src2_Verdict.NEEDS_HUMAN_REVIEW
    assert result[0].severity == src2_Severity.HIGH
    assert result[0].remediation == ''
    assert result[0].metadata['ai_triage']['remediation_suggestion']
    assert summary['processed'] == 1

def test_confidence_requires_integrity_for_confirmed_verdict() -> None:
    finding = src2_FindingRecord(title='Issue', category='test', severity=src2_Severity.HIGH, verdict=src2_Verdict.CONFIRMED, confidence=0.9, asset_id='asset_1', endpoint_id='endpoint_1')
    outcome = src2_ReplayOutcome(finding_id=finding.finding_id, replayed=True, verdict=src2_Verdict.CONFIRMED, reproducible=True, identity_contrast_verified=True, reason='reproduced')
    score = src2_ConfidenceScorer.score(finding, outcome, evidence_integrity=False)
    assert score < 0.8

def test_severity_assessment_is_explainable_and_never_upgrades() -> None:
    finding = src2_FindingRecord(title='Issue', category='test', severity=src2_Severity.MEDIUM, verdict=src2_Verdict.NEEDS_HUMAN_REVIEW, confidence=0.6, asset_id='asset_1', endpoint_id='endpoint_1')
    assessment = src2_SeverityAssessor.assess(finding)
    assert assessment['source_severity'] == 'MEDIUM'
    assert assessment['severity_was_upgraded'] is False
    assert assessment['risk_score'] == 1.95
    assert assessment['risk_band'] == 'LOW'

def test_untrusted_finding_id_cannot_escape_evidence_directory() -> None:
    from security_analyzer.verification.finding_deduplicator import FindingDeduplicator
    findings = FindingDeduplicator().collect_and_deduplicate({'analysis/authorization_matrix.json': {'findings': [{'finding_id': '../../reports/security_report', 'title': 'Untrusted ID', 'category': 'idor_bola', 'severity': 'HIGH', 'verdict': 'LIKELY', 'confidence': float('nan'), 'asset_id': 'asset_1', 'endpoint_id': 'ep_1', 'metadata': {'target_url': 'https://authorized.example/api/1'}}]}})
    assert len(findings) == 1
    assert findings[0].finding_id.startswith('find_')
    assert '/' not in findings[0].finding_id
    assert findings[0].confidence == 0.6

def test_http_exposure_server_error_is_inconclusive_not_false_positive(tmp_path: Path) -> None:
    import requests
    from security_analyzer.core.coverage_tracker import CoverageTracker
    from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
    from security_analyzer.verification.poc_replayer import DeterministicPocReplayer
    workspace = src2__workspace(tmp_path)
    engine = src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['authorized.example']))
    coverage = CoverageTracker(workspace)
    inventory = UnifiedEndpointInventory(workspace)
    replayer = DeterministicPocReplayer(workspace=workspace, scope_engine=engine, coverage=coverage, inventory=inventory, auth_manager=None)
    response = requests.Response()
    response.status_code = 503
    response.headers['Content-Type'] = 'text/plain'
    response._content = b'temporarily unavailable'

    class _Client:

        def get(self, *args, **kwargs):
            return response
    replayer._client_for_identity = lambda identity_id: _Client()
    finding = src2_FindingRecord(title='Exposed artifact', category='nuclei:test-template', severity=src2_Severity.HIGH, verdict=src2_Verdict.LIKELY, confidence=0.7, asset_id='asset_1', endpoint_id='ep_1', metadata={'target_url': 'https://authorized.example/openapi.json'})
    with src2_patch('socket.getaddrinfo', return_value=[(src2_socket.AF_INET, src2_socket.SOCK_STREAM, 6, '', ('93.184.216.34', 443))]):
        outcome = replayer.verify_finding(finding)
    assert outcome.verdict == src2_Verdict.INCONCLUSIVE
    assert outcome.evidence_record is not None

def test_evidence_database_is_scan_bound_and_append_only(tmp_path: Path) -> None:
    import shutil
    import sqlite3
    first = src2__workspace(tmp_path)
    artifact = 'verification/evidence/append_only.json'
    evidence_id = 'ev_append_only'
    finding_id = 'find_append_only'
    first.write_json_atomic(artifact, {'schema_version': '1.1', 'scan_id': first.scan_id, 'finding_id': finding_id, 'evidence_id': evidence_id})
    record = src2_EvidenceRecord(artifact_path=artifact, evidence_type='test', summary='immutable', sha256=first.file_sha256(artifact), evidence_id=evidence_id)
    with src2_EvidenceStore(first) as store:
        integrity = store.verify_record(record, finding_id=finding_id)
        store.record_evidence(record, finding_id=finding_id, integrity=integrity)
        with src2_pytest.raises(sqlite3.IntegrityError, match='append-only'):
            with store._connection:
                store._connection.execute("UPDATE evidence_records SET summary='changed'")
    second = src2_WorkspaceManager(project_root=tmp_path)
    second.init_scan('https://authorized.example', scan_id='different_scan')
    source_db = first.resolve_path(src2_EvidenceStore.RELATIVE_PATH)
    destination_db = second.resolve_path(src2_EvidenceStore.RELATIVE_PATH)
    shutil.copy2(source_db, destination_db)
    with src2_pytest.raises(ValueError, match='different scan'):
        src2_EvidenceStore(second)

def test_nuclei_finding_preserves_matched_location_and_template_provenance() -> None:
    from security_analyzer.verification.finding_deduplicator import FindingDeduplicator
    findings = FindingDeduplicator().collect_and_deduplicate({'analysis/nuclei_findings.json': {'findings': [{'title': 'Potential exposed panel', 'category': 'nuclei_template_match', 'severity': 'MEDIUM', 'location': 'https://authorized.example/admin/panel', 'template_id': 'exposed-panel', 'matcher_name': 'status-code'}]}})
    assert len(findings) == 1
    assert findings[0].metadata['target_url'] == 'https://authorized.example/admin/panel'
    assert findings[0].metadata['template_id'] == 'exposed-panel'
    assert findings[0].metadata['source_artifact'] == 'analysis/nuclei_findings.json'

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step5_release_reporting.py
# -----------------------------------------------------------------------------

import json as src3_json
from pathlib import Path as src3_Path
from security_analyzer.cli import main as src3_main
from security_analyzer.core.workspace import WorkspaceManager as src3_WorkspaceManager
from security_analyzer.reporting.report_builder import ReportBuilder as src3_ReportBuilder

def test_finding_lifecycle_categories_are_distinct():
    findings = [{'finding_id': 'confirmed', 'verdict': 'CONFIRMED'}, {'finding_id': 'likely', 'verdict': 'LIKELY'}, {'finding_id': 'review', 'verdict': 'NEEDS_HUMAN_REVIEW'}, {'finding_id': 'inconclusive', 'verdict': 'INCONCLUSIVE'}, {'finding_id': 'false-positive', 'verdict': 'FALSE_POSITIVE'}]
    potential, human_review, false_positives = src3_ReportBuilder._classify_findings(findings)
    assert [item['finding_id'] for item in potential] == ['likely']
    assert {item['finding_id'] for item in human_review} == {'review', 'inconclusive'}
    assert [item['finding_id'] for item in false_positives] == ['false-positive']

def test_status_and_report_honor_custom_output_root(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('security_analyzer.cli.load_settings', lambda _path: {})
    workspace = src3_WorkspaceManager(output_root_name='custom-scans')
    scan_dir = workspace.init_scan('https://example.test')
    workspace.write_json_atomic('scan_state.json', {'scan_id': workspace.scan_id, 'target': 'https://example.test', 'overall_status': 'PARTIAL', 'stages': {}})
    status_code = src3_main(['status', '--scan-id', workspace.scan_id, '--settings', 'unused.yaml', '--output-root', 'custom-scans'])
    status_payload = src3_json.loads(capsys.readouterr().out)
    assert status_code == 0
    assert src3_Path(status_payload['scan_dir']) == scan_dir
    report_code = src3_main(['report', '--scan-id', workspace.scan_id, '--settings', 'unused.yaml', '--output-root', 'custom-scans'])
    report_payload = src3_json.loads(capsys.readouterr().out)
    assert report_code == 0
    assert report_payload['scan_id'] == workspace.scan_id
    assert (scan_dir / 'reports/security_report.json').is_file()
    assert (scan_dir / 'reports/security_report.md').is_file()
    assert (scan_dir / 'reports/security_report.html').is_file()
