from __future__ import annotations

from pathlib import Path

# -----------------------------------------------------------------------------
# Consolidated from: tests/pipeline/test_step8_full_run.py
# -----------------------------------------------------------------------------

import json as src1_json
import threading as src1_threading
from http.server import BaseHTTPRequestHandler as src1_BaseHTTPRequestHandler, ThreadingHTTPServer as src1_ThreadingHTTPServer
from unittest.mock import patch as src1_patch
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS as src1_STAGE_DEFINITIONS
from security_analyzer.main import build_orchestrator as src1_build_orchestrator

class src1_Lab(src1_BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == '/':
            body, content_type = (b"<html><title>Lab</title><a href='/api/public/info'>x</a></html>", 'text/html')
        elif self.path == '/api/public/info':
            body, content_type = (src1_json.dumps({'name': 'lab', 'items': [1, 2, 3]}).encode(), 'application/json')
        else:
            body, content_type = (b'not found', 'text/plain')
        self.send_response(200 if self.path in {'/', '/api/public/info'} else 404)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def test_full_15_stage_run_through_orchestrator_and_resume(tmp_path, monkeypatch):
    for name in ('SECURITY_ANALYZER_PROXY', 'SECURITY_ANALYZER_EGRESS_ENFORCED'):
        monkeypatch.delenv(name, raising=False)
    server = src1_ThreadingHTTPServer(('127.0.0.1', 0), src1_Lab)
    src1_threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    base = f'http://127.0.0.1:{port}/'
    scope = tmp_path / 'scope.yaml'
    scope.write_text(f"allowed_domains: ['127.0.0.1']\nallowed_ports: [{port}]\nallow_private_ips: true\n", encoding='utf-8')
    try:
        orch = src1_build_orchestrator(target=base, scope_path=scope, project_root=tmp_path)
        with src1_patch('security_analyzer.browser.application_crawler.is_playwright_installed', return_value=False), src1_patch('security_analyzer.scanners.nuclei_runner.shutil.which', return_value=None):
            orch.run()
        state = orch.state
        assert set(state['stages']) == {definition.stage_id for definition in src1_STAGE_DEFINITIONS}
        assert len(state['stages']) == 15
        assert all((stage['status'] in {'SUCCESS', 'PARTIAL', 'SKIPPED', 'FAILED'} for stage in state['stages'].values()))
        assert state['stages']['evidence_verification']['status'] in {'SUCCESS', 'PARTIAL'}
        assert state['stages']['consolidated_reporting']['status'] in {'SUCCESS', 'PARTIAL'}
        report = orch.workspace.read_json('reports/security_report.json')
        assert report['overall_pipeline_status'] in {'SUCCESS', 'PARTIAL', 'FAILED'}
        assert report['scan_id'] == orch.workspace.scan_id
        resumed = src1_build_orchestrator(target=base, scope_path=scope, project_root=tmp_path, scan_id=orch.workspace.scan_id)
        with src1_patch('security_analyzer.browser.application_crawler.is_playwright_installed', return_value=False), src1_patch('security_analyzer.scanners.nuclei_runner.shutil.which', return_value=None):
            resumed.run(resume=True)
        events = [src1_json.loads(line) for line in (resumed.workspace.scan_dir / 'logs/execution.jsonl').read_text(encoding='utf-8').splitlines()]
        assert any((event.get('event') == 'stage_reused' for event in events))
    finally:
        server.shutdown()
        server.server_close()

# -----------------------------------------------------------------------------
# Consolidated from: tests/unit/test_step10_cli_release.py
# -----------------------------------------------------------------------------

import json as src2_json
from pathlib import Path as src2_Path
import pytest as src2_pytest
from security_analyzer.cli import main as src2_main
from security_analyzer.core.coverage_tracker import CoverageTracker as src2_CoverageTracker
from security_analyzer.core.exceptions import StageExecutionError as src2_StageExecutionError
from security_analyzer.core.orchestrator import PipelineOrchestrator as src2_PipelineOrchestrator
from security_analyzer.core.scope_engine import ScopeEngine as src2_ScopeEngine, ScopePolicy as src2_ScopePolicy
from security_analyzer.core.stage_registry import ArtifactSpec as src2_ArtifactSpec, StageDefinition as src2_StageDefinition, StageResult as src2_StageResult, StageStatus as src2_StageStatus
from security_analyzer.core.workspace import WorkspaceManager as src2_WorkspaceManager

def src2__orchestrator(tmp_path: Path):
    definitions = (src2_StageDefinition('foundation', 'Foundation', 'test', artifacts=(src2_ArtifactSpec('test/foundation.json', ('schema_version', 'scan_id', 'stage_id', 'ready')),)), src2_StageDefinition('middle', 'Middle', 'test', dependencies=('foundation',), artifacts=(src2_ArtifactSpec('test/middle.json', ('schema_version', 'scan_id', 'stage_id', 'ready')),)), src2_StageDefinition('requested', 'Requested', 'test', dependencies=('middle',), artifacts=(src2_ArtifactSpec('test/requested.json', ('schema_version', 'scan_id', 'stage_id', 'ready')),)), src2_StageDefinition('unrelated', 'Unrelated', 'test'))
    workspace = src2_WorkspaceManager(project_root=tmp_path)
    workspace.init_scan('https://example.test')
    orchestrator = src2_PipelineOrchestrator(target='https://example.test', workspace=workspace, scope_engine=src2_ScopeEngine(src2_ScopePolicy(allowed_domains=['example.test'])), coverage=src2_CoverageTracker(workspace), config={}, definitions=definitions)
    calls: list[str] = []

    def runner(ctx, stage_def):
        calls.append(stage_def.stage_id)
        relative = stage_def.artifacts[0].relative_path
        ctx.workspace.write_json_atomic(relative, {'schema_version': '1.0', 'scan_id': ctx.workspace.scan_id, 'stage_id': stage_def.stage_id, 'ready': True})
        return src2_StageResult(stage_id=stage_def.stage_id, status=src2_StageStatus.SUCCESS, summary='ok', artifacts=[relative])
    for definition in definitions:
        orchestrator.register_runner(definition.stage_id, runner)
    return (orchestrator, calls)

def test_selected_stage_automatically_runs_transitive_dependencies(tmp_path: Path):
    orchestrator, calls = src2__orchestrator(tmp_path)
    status = orchestrator.run(resume=False, only_stages={'requested'})
    assert calls == ['foundation', 'middle', 'requested']
    assert orchestrator.state['stages']['unrelated']['status'] == 'PENDING'
    assert status == src2_StageStatus.PARTIAL
    events = [src2_json.loads(line) for line in orchestrator.workspace.execution_log_file.read_text().splitlines()]
    selection = next((item for item in events if item.get('event') == 'stage_selection_expanded'))
    assert selection['requested_stage_ids'] == ['requested']
    assert selection['selected_stage_ids'] == ['foundation', 'middle', 'requested']

def test_selected_stage_rejects_unknown_ids(tmp_path: Path):
    orchestrator, _ = src2__orchestrator(tmp_path)
    with src2_pytest.raises(src2_StageExecutionError, match='Unknown requested stage IDs'):
        orchestrator.run(only_stages={'not-a-stage'})

def test_stages_command_lists_registered_pipeline(capsys):
    assert src2_main(['stages']) == 0
    payload = src2_json.loads(capsys.readouterr().out)
    assert len(payload) == 15
    assert payload[0]['stage_id'] == 'domain_enumeration'
    assert payload[-1]['stage_id'] == 'consolidated_reporting'

def test_status_command_reports_invalid_scan_id_without_traceback(monkeypatch, tmp_path: Path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('security_analyzer.cli.load_settings', lambda _path: {'output_root': 'output'})
    code = src2_main(['status', '--scan-id', '../escape', '--settings', 'unused.yaml'])
    captured = capsys.readouterr()
    assert code == 2
    error = src2_json.loads(captured.err)
    assert error['error_type'] == 'WorkspaceBoundaryError'
    assert captured.out == ''

def test_cli_version_is_available(capsys):
    with src2_pytest.raises(SystemExit) as exc:
        src2_main(['--version'])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == 'quiver 0.1.0'


# -----------------------------------------------------------------------------
# Step 5 release, packaging and offline benchmark regression coverage
# -----------------------------------------------------------------------------

from scripts.benchmark_lab import score as src3_benchmark_score


def test_benchmark_handles_empty_ground_truth_without_inventing_precision_or_recall():
    report = {
        "scan_id": "scan-empty",
        "target": "http://lab.example.test/",
        "overall_pipeline_status": "SUCCESS",
        "confirmed_findings": [],
        "potential_findings": [],
        "needs_human_review": [],
        "coverage": {"total_endpoints": 0, "unprobed_endpoints": 0},
    }
    manifest = {
        "benchmark": "safe-control-only",
        "target_application": "synthetic lab",
        "expected_findings": [],
        "known_safe_controls": [{"id": "SAFE-1", "endpoint_contains": "/health"}],
    }
    state = {"scan_id": "scan-empty", "target": report["target"], "stages": {}}

    result = src3_benchmark_score(report, manifest, state)

    assert result["metrics"]["true_positives"] == 0
    assert result["metrics"]["false_positives"] == 0
    assert result["metrics"]["false_negatives"] == 0
    assert result["metrics"]["precision"] is None
    assert result["metrics"]["recall"] is None
    assert result["metrics"]["endpoint_coverage"] is None
    src2_json.dumps(result, allow_nan=False)


def test_benchmark_rejects_impossible_coverage_and_nonmatching_scan_ids():
    report = {
        "scan_id": "scan-a",
        "confirmed_findings": [],
        "coverage": {"total_endpoints": 2, "unprobed_endpoints": 3},
    }
    manifest = {"expected_findings": [], "known_safe_controls": []}
    state = {"scan_id": "scan-a", "stages": {}}

    with src2_pytest.raises(ValueError, match="cannot exceed"):
        src3_benchmark_score(report, manifest, state)

    report["coverage"] = {"total_endpoints": 0, "unprobed_endpoints": 0}
    state["scan_id"] = "scan-b"
    with src2_pytest.raises(ValueError, match="must both exist and match"):
        src3_benchmark_score(report, manifest, state)


def test_step5_repository_hygiene_and_ci_contracts():
    repo_root = src2_Path(__file__).resolve().parents[1]
    gitignore = (repo_root / ".gitignore").read_text(encoding="utf-8")
    dockerignore = (repo_root / ".dockerignore").read_text(encoding="utf-8")
    env_example = (repo_root / ".env.example").read_text(encoding="utf-8")
    workflow = (repo_root / ".github/workflows/ci-and-scan.yml").read_text(encoding="utf-8")
    dockerfile = (repo_root / "Dockerfile").read_text(encoding="utf-8")
    compose = (repo_root / "docker-compose.yml").read_text(encoding="utf-8")

    for content in (gitignore, dockerignore):
        for required in (".env", "secrets/", "output/", "__pycache__/"):
            assert required in content
    assert "!.env.example" in gitignore
    assert "USER_A_TOKEN=" in env_example
    assert "USER_B_TOKEN=" in env_example
    assert "YOUR_REAL" not in env_example
    assert "pull_request:" in workflow
    assert "workflow_dispatch:" in workflow
    assert "run_juice_shop_scan" in workflow
    assert "quiver --version" in workflow
    assert "contents: read" in workflow
    assert 'ENTRYPOINT ["quiver"]' in dockerfile
    assert 'profiles: ["lab"]' in compose
    assert "scanner_internal" in compose


def test_benchmark_calculates_tp_fp_fn_precision_recall_and_coverage():
    report = {
        "scan_id": "scan-metrics",
        "target": "http://lab.example.test/",
        "overall_pipeline_status": "PARTIAL",
        "confirmed_vulnerabilities": [
            {
                "finding_id": "F-1",
                "category": "xss",
                "title": "Reflected XSS in search",
                "severity": "HIGH",
                "metadata": {"target_url": "http://lab.example.test/search?q=1"},
            },
            {
                "finding_id": "F-2",
                "category": "misconfiguration",
                "title": "False alert on public health endpoint",
                "severity": "LOW",
                "metadata": {"target_url": "http://lab.example.test/public/health"},
            },
        ],
        "potential_findings": [{"finding_id": "P-1"}],
        "needs_human_review": [{"finding_id": "R-1"}],
        "coverage": {"total_endpoints": 10, "unprobed_endpoints": 2},
    }
    manifest = {
        "expected_findings": [
            {
                "id": "LAB-XSS-1",
                "category": "xss",
                "title_contains": "reflected xss",
                "endpoint_contains": "/search",
                "severity": "HIGH",
            },
        ],
        "known_safe_controls": [
            {"id": "SAFE-HEALTH", "endpoint_contains": "/public/health"},
        ],
    }
    state = {
        "scan_id": "scan-metrics",
        "target": report["target"],
        "stages": {
            "stage_a": {"duration_sec": 1.25},
            "stage_b": {"duration_sec": 0.75},
            "bad_duration": {"duration_sec": float("nan")},
        },
    }

    result = src3_benchmark_score(report, manifest, state)

    assert result["metrics"]["true_positives"] == 1
    assert result["metrics"]["false_positives"] == 1
    assert result["metrics"]["false_negatives"] == 0
    assert result["metrics"]["precision"] == 0.5
    assert result["metrics"]["recall"] == 1.0
    assert result["metrics"]["endpoint_coverage"] == 0.8
    assert result["metrics"]["execution_seconds_sum_of_stage_durations"] == 2.0
    assert len(result["confirmed_findings_on_known_safe_controls"]) == 1
    assert result["metrics"]["potential_findings"] == 1
    assert result["metrics"]["needs_human_review"] == 1
