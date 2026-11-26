from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import yaml

from security_analyzer.browser import run_browser_capture
from security_analyzer.authentication import run_auth_session_lifecycle
from security_analyzer.deep_checks import run_authorization_idor, run_business_logic_checks
from security_analyzer.core.coverage_tracker import CoverageTracker
from security_analyzer.core.dependency_manager import DependencyManager
from security_analyzer.core.config_validation import validate_settings
from security_analyzer.core.environment_snapshot import build_environment_snapshot
from security_analyzer.core.exceptions import ConfigurationError, SecurityAnalyzerError
from security_analyzer.core.orchestrator import PipelineOrchestrator
from security_analyzer.core.scope_engine import ScopeEngine, ScopePolicy
from security_analyzer.core.stage_registry import StageStatus
from security_analyzer.core.workspace import WorkspaceManager
from security_analyzer.discovery import (
    run_directory_discovery,
    run_domain_enumeration,
    run_http_probing,
    run_redirect_analysis,
)
from security_analyzer.intelligence import run_api_js_intelligence
from security_analyzer.scanners import (
    run_nuclei_assessment,
    run_online_security_checks,
    run_security_review,
    run_server_dns_checks,
)
from security_analyzer.reporting import run_consolidated_reporting
from security_analyzer.verification import run_evidence_verification


def load_settings(settings_path: Path | None) -> dict[str, Any]:
    if settings_path is None:
        return validate_settings({})
    if not settings_path.is_file():
        raise ConfigurationError(f"Settings file does not exist or is not a regular file: {settings_path}")
    try:
        loaded = yaml.safe_load(settings_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"Could not read settings file {settings_path}: {type(exc).__name__}") from exc
    if not isinstance(loaded, dict):
        raise ConfigurationError(f"Settings file must be a YAML mapping: {settings_path}")
    return validate_settings(loaded)


def _validate_baseline_workspace(
    *,
    baseline_scan_id: str,
    current_scan_id: str,
    project_root: Path | None,
    output_root_name: str,
) -> str:
    clean_baseline = baseline_scan_id.strip()
    if not clean_baseline:
        raise ConfigurationError("baseline_scan_id must not be empty")
    if clean_baseline == current_scan_id:
        raise ConfigurationError("baseline_scan_id must differ from the active scan_id")
    baseline_ws = WorkspaceManager(
        project_root=project_root,
        output_root_name=output_root_name,
    )
    try:
        baseline_ws.load_scan(clean_baseline)
    except SecurityAnalyzerError as exc:
        raise ConfigurationError(f"Invalid baseline scan {clean_baseline!r}: {exc}") from exc
    return clean_baseline


def build_orchestrator(
    *,
    target: str,
    scope_path: Path,
    settings_path: Path | None = None,
    auth_profiles_path: Path | None = None,
    scan_id: str | None = None,
    project_root: Path | None = None,
    output_root: str | None = None,
    baseline_scan_id: str | None = None,
) -> PipelineOrchestrator:
    settings = load_settings(settings_path)
    if output_root:
        settings["output_root"] = output_root
    if auth_profiles_path is not None:
        settings["auth_profiles_path"] = str(auth_profiles_path)
    resolved_output_root = str(settings.get("output_root", "output"))
    workspace = WorkspaceManager(
        project_root=project_root,
        output_root_name=resolved_output_root,
    )
    if scan_id:
        workspace.load_scan(scan_id)
    else:
        workspace.init_scan(target)

    selected_baseline = baseline_scan_id or str(settings.get("baseline_scan_id") or "").strip() or None
    if selected_baseline:
        settings["baseline_scan_id"] = _validate_baseline_workspace(
            baseline_scan_id=selected_baseline,
            current_scan_id=workspace.scan_id,
            project_root=workspace.project_root,
            output_root_name=resolved_output_root,
        )

    workspace.write_json_atomic(
        "meta/environment_snapshot.json",
        build_environment_snapshot(settings, project_root=workspace.project_root),
    )

    policy = ScopePolicy.from_yaml(scope_path, target_url=target)
    scope_engine = ScopeEngine(policy)
    scope_engine.enforce_url(target, check_dns=True)

    coverage = CoverageTracker(workspace, limits=settings.get("limits", {}))
    orchestrator = PipelineOrchestrator(
        target=target,
        workspace=workspace,
        scope_engine=scope_engine,
        coverage=coverage,
        config=settings,
    )
    register_available_stages(orchestrator)
    return orchestrator


def register_available_stages(orchestrator: PipelineOrchestrator) -> None:
    orchestrator.register_runner("domain_enumeration", run_domain_enumeration)
    orchestrator.register_runner("auth_session_lifecycle", run_auth_session_lifecycle)
    orchestrator.register_runner("browser_capture", run_browser_capture)
    orchestrator.register_runner("directory_discovery", run_directory_discovery)
    orchestrator.register_runner("http_probing", run_http_probing)
    orchestrator.register_runner("redirect_analysis", run_redirect_analysis)
    orchestrator.register_runner("security_review", run_security_review)
    orchestrator.register_runner("online_security_checks", run_online_security_checks)
    orchestrator.register_runner("nuclei_assessment", run_nuclei_assessment)
    orchestrator.register_runner("server_dns_checks", run_server_dns_checks)
    orchestrator.register_runner("api_js_intelligence", run_api_js_intelligence)
    orchestrator.register_runner("authorization_idor", run_authorization_idor)
    orchestrator.register_runner("business_logic_checks", run_business_logic_checks)
    orchestrator.register_runner("evidence_verification", run_evidence_verification)
    orchestrator.register_runner("consolidated_reporting", run_consolidated_reporting)


def run_doctor(profile: str = "core-only", settings_path: Path | None = None) -> dict[str, Any]:
    settings = load_settings(settings_path)
    report = DependencyManager().inspect_all(profile=profile)
    report["settings_valid"] = True
    report["resource_limits"] = settings["limits"]
    return report


def status_to_exit_code(status: StageStatus) -> int:
    if status == StageStatus.SUCCESS:
        return 0
    if status == StageStatus.PARTIAL:
        return 2
    return 1


def execute_scan(
    *,
    target: str,
    scope_path: Path,
    settings_path: Path | None = None,
    auth_profiles_path: Path | None = None,
    project_root: Path | None = None,
    output_root: str | None = None,
    baseline_scan_id: str | None = None,
    on_ready: Callable[[PipelineOrchestrator], None] | None = None,
) -> tuple[int, dict[str, Any]]:
    try:
        orchestrator = build_orchestrator(
            target=target,
            scope_path=scope_path,
            settings_path=settings_path,
            auth_profiles_path=auth_profiles_path,
            project_root=project_root,
            output_root=output_root,
            baseline_scan_id=baseline_scan_id,
        )
        if on_ready is not None:
            on_ready(orchestrator)
        overall = orchestrator.run(resume=False)
        if orchestrator.state.get("cancelled"):
            return 130, orchestrator.state
        return status_to_exit_code(overall), orchestrator.state
    except SecurityAnalyzerError as exc:
        return 1, {"error": str(exc)}


def resume_scan(
    *,
    scan_id: str,
    scope_path: Path,
    settings_path: Path | None = None,
    auth_profiles_path: Path | None = None,
    only_stages: set[str] | None = None,
    project_root: Path | None = None,
    output_root: str | None = None,
    baseline_scan_id: str | None = None,
    on_ready: Callable[[PipelineOrchestrator], None] | None = None,
) -> tuple[int, dict[str, Any]]:
    try:
        settings = load_settings(settings_path)
        if output_root:
            settings["output_root"] = output_root
        workspace = WorkspaceManager(
            project_root=project_root,
            output_root_name=str(settings.get("output_root", "output")),
        )
        workspace.load_scan(scan_id)
        existing_state = workspace.read_json("scan_state.json")
        target = str(existing_state["target"])
        effective_baseline = (
            baseline_scan_id
            or str(existing_state.get("baseline_scan_id") or "").strip()
            or None
        )

        orchestrator = build_orchestrator(
            target=target,
            scope_path=scope_path,
            settings_path=settings_path,
            auth_profiles_path=auth_profiles_path,
            scan_id=scan_id,
            project_root=project_root,
            output_root=output_root,
            baseline_scan_id=effective_baseline,
        )
        if on_ready is not None:
            on_ready(orchestrator)
        overall = orchestrator.run(resume=True, only_stages=only_stages)
        if orchestrator.state.get("cancelled"):
            return 130, orchestrator.state
        return status_to_exit_code(overall), orchestrator.state
    except SecurityAnalyzerError as exc:
        return 1, {"error": str(exc)}
