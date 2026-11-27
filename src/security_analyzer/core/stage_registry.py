from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from security_analyzer.core.exceptions import ArtifactValidationError
from security_analyzer.core.workspace import WorkspaceManager


class StageStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


STAGE_STATUS_RULES: dict[str, str] = {
    StageStatus.SUCCESS.value: "Required checks completed and declared artifacts passed schema validation.",
    StageStatus.PARTIAL.value: "Valid artifacts were produced, but coverage or optional capabilities were incomplete.",
    StageStatus.FAILED.value: "Required execution failed, crashed, or produced missing/invalid required artifacts.",
    StageStatus.SKIPPED.value: "The stage was deliberately bypassed because a prerequisite or optional capability was unavailable.",
}


def compute_overall_status(statuses) -> StageStatus:
    """Compute the single authoritative overall status used by scans and reports."""
    values = {
        status.value if isinstance(status, StageStatus) else str(status)
        for status in statuses
    }
    if StageStatus.FAILED.value in values:
        return StageStatus.FAILED
    if values & {
        StageStatus.PARTIAL.value,
        StageStatus.SKIPPED.value,
        StageStatus.PENDING.value,
        StageStatus.RUNNING.value,
    }:
        return StageStatus.PARTIAL
    return StageStatus.SUCCESS


@dataclass(frozen=True)
class ArtifactSpec:
    relative_path: str
    required_keys: tuple[str, ...] = ("schema_version", "scan_id", "stage_id")
    # Used only for shared artifacts whose latest writer may be another declared stage.
    allowed_stage_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class StageDefinition:
    stage_id: str
    title: str
    phase: str
    dependencies: tuple[str, ...] = ()
    optional_dependencies: tuple[str, ...] = ()
    artifacts: tuple[ArtifactSpec, ...] = ()
    allow_partial_dependencies: bool = True


@dataclass
class StageResult:
    stage_id: str
    status: StageStatus
    summary: str = ""
    artifacts: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    reusable_partial: bool = False


STAGE_DEFINITIONS: tuple[StageDefinition, ...] = (
    StageDefinition(
        "domain_enumeration", "Domain & Subdomain Enumeration", "discovery",
        artifacts=(
            ArtifactSpec("discovery/subdomains.json", ("schema_version", "scan_id", "stage_id", "hosts")),
            ArtifactSpec("inventory/contributions/domain_enumeration.json", ("schema_version", "scan_id", "stage_id", "endpoints")),
        ),
    ),
    StageDefinition(
        "auth_session_lifecycle", "Authentication & Isolated Session Lifecycle", "discovery",
        dependencies=("domain_enumeration",),
        artifacts=(ArtifactSpec("analysis/auth_sessions.json", ("schema_version", "scan_id", "stage_id", "records")),),
    ),
    StageDefinition(
        "browser_capture", "Playwright Application & SPA Capture", "discovery",
        dependencies=("domain_enumeration", "auth_session_lifecycle"),
        artifacts=(
            ArtifactSpec("browser/crawl_routes.json", ("schema_version", "scan_id", "stage_id", "endpoints")),
            ArtifactSpec("inventory/contributions/browser_capture.json", ("schema_version", "scan_id", "stage_id", "endpoints")),
        ),
    ),
    StageDefinition(
        "directory_discovery", "Directory & Content Discovery", "discovery",
        dependencies=("domain_enumeration",),
        artifacts=(
            ArtifactSpec("discovery/directories.json", ("schema_version", "scan_id", "stage_id", "paths")),
            ArtifactSpec("inventory/contributions/directory_discovery.json", ("schema_version", "scan_id", "stage_id", "endpoints")),
        ),
    ),
    StageDefinition(
        "http_probing", "HTTP Service Probing", "discovery",
        dependencies=("domain_enumeration", "directory_discovery", "browser_capture"),
        optional_dependencies=("browser_capture",),
        artifacts=(
            ArtifactSpec("discovery/http_probes.json", ("schema_version", "scan_id", "stage_id", "probes")),
            ArtifactSpec("inventory/contributions/http_probing.json", ("schema_version", "scan_id", "stage_id", "endpoints")),
        ),
    ),
    StageDefinition(
        "redirect_analysis", "Redirect Chain & Boundary Analysis", "discovery",
        dependencies=("http_probing",),
        artifacts=(
            ArtifactSpec("discovery/redirects.json", ("schema_version", "scan_id", "stage_id", "chains")),
            ArtifactSpec(
                "inventory/contributions/redirect_analysis.json",
                ("schema_version", "scan_id", "stage_id", "endpoints"),
            ),
        ),
    ),
    StageDefinition(
        "security_review", "Configuration & Exposure Review", "analysis",
        dependencies=("redirect_analysis",),
        artifacts=(ArtifactSpec("analysis/security_headers.json", ("schema_version", "scan_id", "stage_id", "findings")),),
    ),
    StageDefinition(
        "online_security_checks", "TLS & Transport Security Posture", "analysis",
        dependencies=("redirect_analysis",),
        artifacts=(ArtifactSpec("analysis/tls_posture.json", ("schema_version", "scan_id", "stage_id", "results")),),
    ),
    StageDefinition(
        "server_dns_checks", "DNS & Infrastructure Posture Checks", "analysis",
        dependencies=("domain_enumeration",),
        artifacts=(ArtifactSpec("analysis/dns_infrastructure.json", ("schema_version", "scan_id", "stage_id", "records")),),
    ),
    StageDefinition(
        "api_js_intelligence", "API Schema & JavaScript Intelligence", "analysis",
        dependencies=("redirect_analysis", "browser_capture"),
        optional_dependencies=("browser_capture",),
        artifacts=(
            ArtifactSpec("analysis/api_catalog.json", ("schema_version", "scan_id", "stage_id", "operations")),
            ArtifactSpec("analysis/javascript_intel.json", ("schema_version", "scan_id", "stage_id", "bundles")),
            ArtifactSpec(
                "inventory/contributions/api_js_intelligence.json",
                ("schema_version", "scan_id", "stage_id", "endpoints"),
            ),
        ),
    ),
    StageDefinition(
        "nuclei_assessment", "Nuclei Template Vulnerability Scan", "analysis",
        dependencies=("redirect_analysis", "auth_session_lifecycle", "api_js_intelligence"),
        optional_dependencies=("api_js_intelligence",),
        artifacts=(ArtifactSpec("analysis/nuclei_findings.json", ("schema_version", "scan_id", "stage_id", "findings")),),
    ),
    StageDefinition(
        "authorization_idor", "Multi-Identity Authorization & IDOR Analysis", "deep_checks",
        dependencies=("auth_session_lifecycle", "api_js_intelligence"),
        artifacts=(ArtifactSpec("analysis/authorization_matrix.json", ("schema_version", "scan_id", "stage_id", "tests")),),
    ),
    StageDefinition(
        "business_logic_checks", "Stateful Workflow & Business Logic Analysis", "deep_checks",
        dependencies=("auth_session_lifecycle", "api_js_intelligence"),
        artifacts=(ArtifactSpec("analysis/business_logic.json", ("schema_version", "scan_id", "stage_id", "workflows")),),
    ),
    StageDefinition(
        "evidence_verification", "Deterministic Replay & Evidence Verification", "verification",
        dependencies=(
            "security_review", "online_security_checks", "server_dns_checks",
            "api_js_intelligence", "nuclei_assessment", "authorization_idor", "business_logic_checks",
        ),
        optional_dependencies=("online_security_checks", "nuclei_assessment", "server_dns_checks"),
        artifacts=(ArtifactSpec("verification/verified_findings.json", ("schema_version", "scan_id", "stage_id", "findings")),),
    ),
    StageDefinition(
        "consolidated_reporting", "Consolidated Assessment Reporting", "reporting",
        dependencies=("evidence_verification",),
        artifacts=(ArtifactSpec("reports/security_report.json", ("schema_version", "scan_id", "stage_id", "summary")),),
    ),
)


def validate_stage_artifacts(
    workspace: WorkspaceManager,
    stage_def: StageDefinition,
    *,
    require_producer_state: bool = False,
) -> dict[str, dict[str, Any]]:
    """Validate declared JSON artifact envelopes, scan identity and permitted writer."""
    loaded: dict[str, dict[str, Any]] = {}
    for spec in stage_def.artifacts:
        envelope = {"schema_version", "scan_id", "stage_id"}
        if not envelope.issubset(spec.required_keys):
            raise ArtifactValidationError(
                f"Artifact schema for {spec.relative_path!r} must require {sorted(envelope)}"
            )
        path = workspace.resolve_path(spec.relative_path)
        if not path.is_file() or path.stat().st_size == 0:
            raise ArtifactValidationError(
                f"Stage {stage_def.stage_id!r} missing or empty required artifact: {spec.relative_path}"
            )
        try:
            payload = workspace.read_json(spec.relative_path)
        except Exception as exc:
            raise ArtifactValidationError(
                f"Stage {stage_def.stage_id!r} produced invalid JSON in {spec.relative_path}: {exc}"
            ) from exc
        missing = [key for key in spec.required_keys if key not in payload]
        if missing:
            raise ArtifactValidationError(
                f"Artifact {spec.relative_path} missing required keys: {missing}"
            )
        if payload.get("scan_id") != workspace.scan_id:
            raise ArtifactValidationError(
                f"Artifact {spec.relative_path} scan_id mismatch: expected {workspace.scan_id!r}, got {payload.get('scan_id')!r}"
            )
        allowed = set(spec.allowed_stage_ids) if spec.allowed_stage_ids else {stage_def.stage_id}
        actual_writer = str(payload.get("stage_id", ""))
        if actual_writer not in allowed:
            raise ArtifactValidationError(
                f"Artifact {spec.relative_path} stage_id mismatch: expected one of {sorted(allowed)}, got {actual_writer!r}"
            )
        if require_producer_state:
            if not workspace.state_file.is_file():
                raise ArtifactValidationError("scan_state.json is required for provenance validation")
            try:
                state = workspace.read_json("scan_state.json")
                if state.get("scan_id") != workspace.scan_id:
                    raise ArtifactValidationError("scan_state.json belongs to a different scan")
                writer_state = (state.get("stages") or {}).get(actual_writer, {})
            except Exception as exc:
                raise ArtifactValidationError(f"Cannot validate artifact producer state: {exc}") from exc
            if writer_state.get("status") not in {StageStatus.SUCCESS.value, StageStatus.PARTIAL.value}:
                raise ArtifactValidationError(
                    f"Artifact {spec.relative_path} writer {actual_writer!r} is not complete"
                )
            recorded = writer_state.get("artifacts")
            if not isinstance(recorded, list) or spec.relative_path not in recorded:
                raise ArtifactValidationError(
                    f"Artifact {spec.relative_path} is not recorded by writer {actual_writer!r}"
                )
            if "provenance" in payload:
                provenance = payload.get("provenance")
                if not isinstance(provenance, dict):
                    raise ArtifactValidationError(
                        f"Artifact {spec.relative_path} has invalid provenance"
                    )
                if (
                    provenance.get("scan_id") != workspace.scan_id
                    or provenance.get("stage_id") != actual_writer
                    or provenance.get("input_fingerprint") != writer_state.get("fingerprint")
                ):
                    raise ArtifactValidationError(
                        f"Artifact {spec.relative_path} is stale: producer provenance does not match"
                    )
                if (
                    provenance.get("producer_status")
                    not in {StageStatus.SUCCESS.value, StageStatus.PARTIAL.value}
                    or provenance.get("producer_status") != writer_state.get("status")
                ):
                    raise ArtifactValidationError(
                        f"Artifact {spec.relative_path} has an incomplete producer"
                    )
        loaded[spec.relative_path] = payload
    return loaded


def load_validated_stage_artifact(
    workspace: WorkspaceManager,
    producer_stage_id: str,
    relative_path: str,
    *,
    required_keys: tuple[str, ...] = ("schema_version", "scan_id", "stage_id"),
    allowed_stage_ids: tuple[str, ...] = (),
) -> dict[str, Any] | None:
    """Load an artifact only when its actual writer completed successfully in this scan."""
    if not workspace.state_file.is_file():
        return None
    try:
        state = workspace.read_json("scan_state.json")
        if state.get("scan_id") != workspace.scan_id:
            return None
        stages = state.get("stages")
        if not isinstance(stages, dict):
            return None
        path = workspace.resolve_path(relative_path)
        if not path.is_file() or path.stat().st_size == 0:
            return None
        payload = workspace.read_json(relative_path)
        if any(key not in payload for key in required_keys):
            return None
        if payload.get("scan_id") != workspace.scan_id:
            return None
        allowed = set(allowed_stage_ids) if allowed_stage_ids else {producer_stage_id}
        actual_writer = str(payload.get("stage_id", ""))
        if actual_writer not in allowed:
            return None
        writer_state = stages.get(actual_writer)
        if not isinstance(writer_state, dict):
            return None
        if writer_state.get("status") not in {StageStatus.SUCCESS.value, StageStatus.PARTIAL.value}:
            return None
        recorded = writer_state.get("artifacts")
        if not isinstance(recorded, list) or relative_path not in recorded:
            return None
        if "provenance" in payload:
            provenance = payload.get("provenance")
            if not isinstance(provenance, dict):
                return None
            if (
                provenance.get("scan_id") != workspace.scan_id
                or provenance.get("stage_id") != actual_writer
                or provenance.get("input_fingerprint") != writer_state.get("fingerprint")
                or provenance.get("producer_status") != writer_state.get("status")
                or provenance.get("producer_status") not in {StageStatus.SUCCESS.value, StageStatus.PARTIAL.value}
            ):
                return None
        # The requested producer must also be a completed stage, except when it is
        # the same stage as the actual writer (shared artifacts are checked above).
        requested_state = stages.get(producer_stage_id)
        if not isinstance(requested_state, dict):
            return None
        if requested_state.get("status") not in {StageStatus.SUCCESS.value, StageStatus.PARTIAL.value}:
            return None
        requested_recorded = requested_state.get("artifacts")
        if not isinstance(requested_recorded, list) or relative_path not in requested_recorded:
            return None
        return payload
    except Exception:
        return None