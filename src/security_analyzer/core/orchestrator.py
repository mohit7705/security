from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from security_analyzer.core.coverage_tracker import CoverageTracker
from security_analyzer.core.exceptions import ArtifactValidationError, StageExecutionError
from security_analyzer.core.scope_engine import ScopeEngine
from security_analyzer.core.stage_registry import (
    STAGE_DEFINITIONS,
    StageDefinition,
    StageResult,
    StageStatus,
    compute_overall_status,
    validate_stage_artifacts,
)
from security_analyzer.utils.redaction import scrub_text
from security_analyzer.core.workspace import WorkspaceManager
from security_analyzer.core.resource_governor import ResourceGovernor, ResourceLimitExceeded

_VOLATILE_JSON_KEYS = {"generated_at", "updated_at", "recorded_at", "timestamp", "first_observed", "last_observed"}
_TERMINAL_REUSABLE_STATUSES = {StageStatus.SUCCESS.value, StageStatus.PARTIAL.value}
_SECRET_CONFIG_KEYS = ("password", "passwd", "token", "secret", "api_key", "apikey", "authorization", "cookie")


def _strip_volatile_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_volatile_fields(item)
            for key, item in value.items()
            if key not in _VOLATILE_JSON_KEYS
        }
    if isinstance(value, list):
        return [_strip_volatile_fields(item) for item in value]
    return value


def _canonical_hash(value: Any) -> str:
    canonical = json.dumps(_strip_volatile_fields(value), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _redact_config(value: Any) -> Any:
    """Keep a useful config snapshot while masking values under secret-like keys."""
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            if any(part in str(key).lower() for part in _SECRET_CONFIG_KEYS):
                cleaned[str(key)] = "[REDACTED]"
            else:
                cleaned[str(key)] = _redact_config(item)
        return cleaned
    if isinstance(value, list):
        return [_redact_config(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_config(item) for item in value]
    return value


@dataclass
class ExecutionContext:
    target: str
    workspace: WorkspaceManager
    scope_engine: ScopeEngine
    coverage: CoverageTracker
    config: dict[str, Any]
    upstream_artifacts: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    auth_manager: Any = None
    resource_governor: ResourceGovernor | None = None
    baseline_scan_id: str | None = None
    progress_callback: Callable[[dict[str, Any]], None] | None = None


StageRunner = Callable[[ExecutionContext, StageDefinition], StageResult]


class PipelineOrchestrator:
    """Dependency-aware pipeline runner with provenance validation and deterministic resume."""

    def __init__(
        self,
        *,
        target: str,
        workspace: WorkspaceManager,
        scope_engine: ScopeEngine,
        coverage: CoverageTracker,
        config: dict[str, Any],
        definitions: tuple[StageDefinition, ...] = STAGE_DEFINITIONS,
    ) -> None:
        self.target = target
        self.workspace = workspace
        self.scope_engine = scope_engine
        self.coverage = coverage
        self.config = config
        self.resource_governor = ResourceGovernor(config.get("limits", {}))

        ids = [definition.stage_id for definition in definitions]
        if len(set(ids)) != len(ids):
            raise StageExecutionError("Stage definitions contain duplicate stage IDs")
        if any(not stage_id or stage_id.strip() != stage_id for stage_id in ids):
            raise StageExecutionError("Stage IDs must be non-empty canonical strings")

        self.definitions = {definition.stage_id: definition for definition in definitions}
        self.ordered_ids = ids
        positions = {stage_id: index for index, stage_id in enumerate(ids)}

        for definition in definitions:
            dependencies = set(definition.dependencies)
            optional = set(definition.optional_dependencies)
            unknown = (dependencies | optional) - set(self.definitions)
            if unknown:
                raise StageExecutionError(
                    f"Stage {definition.stage_id!r} has unknown dependencies: {sorted(unknown)}"
                )
            if not optional.issubset(dependencies):
                raise StageExecutionError(
                    f"Optional dependencies must also be declared dependencies for {definition.stage_id!r}"
                )
            if len(definition.dependencies) != len(dependencies):
                raise StageExecutionError(f"Stage {definition.stage_id!r} has duplicate dependencies")
            later = [dep for dep in definition.dependencies if positions[dep] >= positions[definition.stage_id]]
            if later:
                raise StageExecutionError(
                    f"Dependencies must precede stage {definition.stage_id!r}: {later}"
                )
            artifact_paths = [spec.relative_path for spec in definition.artifacts]
            if len(artifact_paths) != len(set(artifact_paths)):
                raise StageExecutionError(f"Stage {definition.stage_id!r} declares duplicate artifact paths")

        self._runners: dict[str, StageRunner] = {}
        self._started: dict[str, tuple[str, float]] = {}
        self._cancelled = False
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self.state = self._load_or_init_state()

    def add_listener(self, listener: Callable[[dict[str, Any]], None]) -> None:
        """Subscribe to progress events; listener errors never stop a scan."""
        self._listeners.append(listener)

    def _emit(self, event: dict[str, Any]) -> None:
        event.setdefault("scan_id", self.workspace.scan_id)
        event.setdefault("scan_dir", str(self.workspace.scan_dir))
        for listener in list(self._listeners):
            try:
                listener(dict(event))
            except Exception:
                pass

    def cancel(self) -> None:
        """Request that running work stops at its next safe cancellation point."""
        self._cancelled = True
        self.resource_governor.cancel()

    def register_runner(self, stage_id: str, runner: StageRunner) -> None:
        if stage_id not in self.definitions:
            raise StageExecutionError(f"Unknown stage_id: {stage_id!r}")
        if not callable(runner):
            raise StageExecutionError(f"Runner for {stage_id!r} is not callable")
        self._runners[stage_id] = runner

    def _default_stage_state(self, now: str) -> dict[str, Any]:
        return {
            "status": StageStatus.PENDING.value,
            "fingerprint": "",
            "upstream_fingerprints": {},
            "reusable_partial": False,
            "summary": "",
            "error": "",
            "artifacts": [],
            "started_at": "",
            "finished_at": "",
            "duration_sec": 0.0,
            "config_hash": "",
            "artifact_hashes": {},
            "updated_at": now,
        }

    def _load_or_init_state(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        configured_baseline = str(self.config.get("baseline_scan_id") or "").strip()
        if self.workspace.state_file.exists():
            try:
                existing = self.workspace.read_json("scan_state.json")
            except Exception as exc:
                raise StageExecutionError(f"Existing scan_state.json is invalid: {exc}") from exc
            if existing.get("scan_id") != self.workspace.scan_id:
                raise StageExecutionError("Existing scan_state.json belongs to a different scan")
            old_stages = existing.get("stages")
            if not isinstance(old_stages, dict):
                old_stages = {}

            normalized: dict[str, dict[str, Any]] = {}
            for stage_id in self.ordered_ids:
                entry = old_stages.get(stage_id)
                if not isinstance(entry, dict):
                    normalized[stage_id] = self._default_stage_state(now)
                    continue
                merged = self._default_stage_state(now)
                merged.update(entry)
                if merged.get("status") not in {status.value for status in StageStatus}:
                    merged["status"] = StageStatus.PENDING.value
                    merged["fingerprint"] = ""
                    merged["artifacts"] = []
                    merged["error"] = "Invalid prior status; stage reset to PENDING"
                if not isinstance(merged.get("artifacts"), list):
                    merged["artifacts"] = []
                if not isinstance(merged.get("upstream_fingerprints"), dict):
                    merged["upstream_fingerprints"] = {}
                merged["reusable_partial"] = bool(merged.get("reusable_partial", False))
                normalized[stage_id] = merged

            resolved_baseline = configured_baseline or str(existing.get("baseline_scan_id") or "").strip()
            existing.update(
                {
                    "schema_version": "2.0",
                    "scan_id": self.workspace.scan_id,
                    "target": existing.get("target") or self.target,
                    "stages": normalized,
                }
            )
            if resolved_baseline:
                existing["baseline_scan_id"] = resolved_baseline
            self._persist_state(existing)
            return existing

        state: dict[str, Any] = {
            "schema_version": "2.0",
            "scan_id": self.workspace.scan_id,
            "target": self.target,
            "created_at": now,
            "updated_at": now,
            "scope_fingerprint": self.scope_engine.policy.fingerprint(),
            "overall_status": StageStatus.PENDING.value,
            "stages": {stage_id: self._default_stage_state(now) for stage_id in self.ordered_ids},
        }
        if configured_baseline:
            state["baseline_scan_id"] = configured_baseline
        self._persist_state(state)
        return state

    def _persist_state(self, state: dict[str, Any] | None = None) -> None:
        target_state = state if state is not None else self.state
        target_state["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.workspace.write_json_atomic("scan_state.json", target_state)

    def _semantic_artifact_hash(self, relative_path: str) -> str:
        path = self.workspace.resolve_path(relative_path)
        if not path.is_file():
            return "MISSING"
        try:
            return _canonical_hash(self.workspace.read_json(relative_path))
        except Exception:
            return self.workspace.file_sha256(relative_path)

    def _stamp_provenance(
        self,
        stage_def: StageDefinition,
        status: StageStatus,
        fingerprint: str,
    ) -> dict[str, str]:
        """Stamp artifacts written by this stage and return their final file hashes."""
        hashes: dict[str, str] = {}
        for spec in stage_def.artifacts:
            path = self.workspace.resolve_path(spec.relative_path)
            if path.is_file() and path.stat().st_size:
                payload = self.workspace.read_json(spec.relative_path)
                if payload.get("stage_id") == stage_def.stage_id:
                    payload["provenance"] = {
                        "scan_id": self.workspace.scan_id,
                        "stage_id": stage_def.stage_id,
                        "producer_status": status.value,
                        "input_fingerprint": fingerprint,
                    }
                    self.workspace.write_json_atomic(spec.relative_path, payload)
                hashes[spec.relative_path] = self.workspace.file_sha256(spec.relative_path)
        return hashes

    def _upstream_stage_fingerprints(self, stage_def: StageDefinition) -> dict[str, str]:
        fingerprints: dict[str, str] = {}
        for dependency_id in stage_def.dependencies:
            entry = self.state["stages"].get(dependency_id, {})
            status = str(entry.get("status", StageStatus.PENDING.value))
            if (
                dependency_id in stage_def.optional_dependencies
                and status in {StageStatus.SKIPPED.value, StageStatus.FAILED.value}
            ):
                fingerprints[dependency_id] = f"OPTIONAL_{status}"
            else:
                fingerprints[dependency_id] = str(entry.get("fingerprint", ""))
        return fingerprints

    def compute_stage_fingerprint(self, stage_def: StageDefinition) -> str:
        upstream: dict[str, Any] = {}
        for dependency_id in stage_def.dependencies:
            entry = self.state["stages"].get(dependency_id, {})
            status = str(entry.get("status", StageStatus.PENDING.value))
            if (
                dependency_id in stage_def.optional_dependencies
                and status in {StageStatus.SKIPPED.value, StageStatus.FAILED.value}
            ):
                upstream[dependency_id] = {
                    "status": status,
                    "artifacts": f"OPTIONAL_{status}",
                }
                continue
            dep_definition = self.definitions[dependency_id]
            upstream[dependency_id] = {
                "status": status,
                "fingerprint": str(entry.get("fingerprint", "")),
                "artifacts": {
                    spec.relative_path: (
                        "SHARED_MUTABLE_ARTIFACT"
                        if spec.allowed_stage_ids
                        else self._semantic_artifact_hash(spec.relative_path)
                    )
                    for spec in dep_definition.artifacts
                },
            }

        material = {
            "stage_id": stage_def.stage_id,
            "target": self.target,
            "scope_fingerprint": self.scope_engine.policy.fingerprint(),
            "config": self.config,
            "upstream": upstream,
        }
        return _canonical_hash(material)

    def _can_reuse_completed_stage(self, stage_def: StageDefinition, current_fp: str) -> bool:
        entry = self.state["stages"].get(stage_def.stage_id, {})
        status = entry.get("status")
        reusable_status = status == StageStatus.SUCCESS.value or (
            status == StageStatus.PARTIAL.value and bool(entry.get("reusable_partial", False))
        )
        if not reusable_status or entry.get("fingerprint") != current_fp:
            return False
        recorded_upstreams = entry.get("upstream_fingerprints")
        if recorded_upstreams != self._upstream_stage_fingerprints(stage_def):
            return False
        try:
            validate_stage_artifacts(self.workspace, stage_def, require_producer_state=True)
            recorded_hashes = entry.get("artifact_hashes")
            if not isinstance(recorded_hashes, dict):
                return False
            for spec in stage_def.artifacts:
                expected_hash = recorded_hashes.get(spec.relative_path)
                artifact_path = self.workspace.resolve_path(spec.relative_path)
                if not expected_hash or not artifact_path.is_file():
                    return False
                if self.workspace.file_sha256(spec.relative_path) != expected_hash:
                    return False
            return True
        except (ArtifactValidationError, OSError, ValueError):
            return False

    def _collect_upstream_artifacts(
        self,
        stage_def: StageDefinition,
    ) -> tuple[bool, str, dict[str, dict[str, dict[str, Any]]]]:
        collected: dict[str, dict[str, dict[str, Any]]] = {}
        for dependency_id in stage_def.dependencies:
            entry = self.state["stages"].get(dependency_id, {})
            status = entry.get("status", StageStatus.PENDING.value)
            if (
                dependency_id in stage_def.optional_dependencies
                and status in {StageStatus.SKIPPED.value, StageStatus.FAILED.value}
            ):
                # Optional producers may fail without preventing independent
                # verification/reporting. Their failure remains in scan_state
                # and coverage; no untrusted/stale artifact is consumed.
                continue

            allowed = {StageStatus.SUCCESS.value}
            if stage_def.allow_partial_dependencies:
                allowed.add(StageStatus.PARTIAL.value)
            if status not in allowed:
                return False, f"Upstream dependency {dependency_id!r} has status {status}", {}

            definition = self.definitions[dependency_id]
            try:
                collected[dependency_id] = validate_stage_artifacts(
                    self.workspace, definition, require_producer_state=True
                )
            except ArtifactValidationError as exc:
                return False, f"Upstream dependency {dependency_id!r} artifact invalid: {exc}", {}
        return True, "", collected

    def _expand_stage_selection(
        self,
        requested: set[str] | None,
    ) -> set[str] | None:
        """Include all transitive prerequisites for explicitly selected stages."""
        if requested is None:
            return None

        unknown = requested - set(self.definitions)
        if unknown:
            raise StageExecutionError(
                f"Unknown requested stage IDs: {sorted(unknown)}"
            )

        selected = set(requested)
        pending = list(requested)
        while pending:
            stage_id = pending.pop()
            for dependency_id in self.definitions[stage_id].dependencies:
                if dependency_id not in selected:
                    selected.add(dependency_id)
                    pending.append(dependency_id)
        return selected

    def run(
        self,
        *,
        resume: bool = False,
        only_stages: set[str] | None = None,
    ) -> StageStatus:
        try:
            return self._run_pipeline(resume=resume, only_stages=only_stages)
        except KeyboardInterrupt:
            # Also cover interrupts between runner calls and during orchestration bookkeeping.
            self._cancelled = True
            self.resource_governor.cancel()
            now = datetime.now(timezone.utc).isoformat()
            for stage_id in self.ordered_ids:
                current = self.state["stages"].get(stage_id, {})
                status = current.get("status")
                if status == StageStatus.RUNNING.value:
                    self._record_stage_state(
                        stage_id=stage_id,
                        status=StageStatus.FAILED,
                        fingerprint=str(current.get("fingerprint", "")),
                        upstream_fingerprints=current.get("upstream_fingerprints", {}),
                        summary="Cancelled by user or termination signal",
                        error="cancelled",
                        artifacts=[],
                    )
                elif status == StageStatus.PENDING.value:
                    self._record_stage_state(
                        stage_id=stage_id,
                        status=StageStatus.SKIPPED,
                        fingerprint="",
                        upstream_fingerprints={},
                        summary="Scan cancelled before this stage ran",
                        error="",
                        artifacts=[],
                    )
            self.state["cancelled"] = True
            self.state["overall_status"] = StageStatus.FAILED.value
            self.state["scope_fingerprint"] = self.scope_engine.policy.fingerprint()
            self.state["updated_at"] = now
            self._persist_state()
            return StageStatus.FAILED

    def _run_pipeline(
        self,
        *,
        resume: bool = False,
        only_stages: set[str] | None = None,
    ) -> StageStatus:
        self.state.pop("cancelled", None)
        selected_stages = self._expand_stage_selection(only_stages)
        if self._listeners:
            stage_items = []
            for stage_id in self.ordered_ids:
                if selected_stages is not None and stage_id not in selected_stages:
                    continue
                definition = self.definitions[stage_id]
                known = self.state["stages"].get(stage_id, {})
                stage_items.append({
                    "stage_id": stage_id,
                    "title": definition.title,
                    "phase": definition.phase,
                    "status": known.get("status", "PENDING"),
                    "summary": known.get("summary", ""),
                    "error": known.get("error", ""),
                    "artifacts": list(known.get("artifacts", [])),
                    "duration_sec": known.get("duration_sec", 0.0),
                })
            self._emit({"type": "pipeline_start", "stages": stage_items})
        if only_stages is not None:
            self.workspace.append_jsonl(
                "logs/execution.jsonl",
                {
                    "event": "stage_selection_expanded",
                    "requested_stage_ids": sorted(only_stages),
                    "selected_stage_ids": [
                        stage_id
                        for stage_id in self.ordered_ids
                        if stage_id in (selected_stages or set())
                    ],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
        self.workspace.write_json_atomic("scope_snapshot.json", self.scope_engine.policy.to_dict())
        self.workspace.write_json_atomic(
            "meta/config_snapshot.json",
            {
                "schema_version": "1.0",
                "scan_id": self.workspace.scan_id,
                "target": self.target,
                "baseline_scan_id": str(self.state.get("baseline_scan_id") or "").strip() or None,
                "scope_fingerprint": self.scope_engine.policy.fingerprint(),
                "config_hash": _canonical_hash(self.config),
                "config": _redact_config(json.loads(json.dumps(self.config, default=str))),
                "scope": self.scope_engine.policy.to_dict(),
            },
        )
        shared_auth_manager: Any = None
        active_baseline_id = str(self.state.get("baseline_scan_id") or "").strip() or None

        selected_order = [sid for sid in self.ordered_ids if selected_stages is None or sid in selected_stages]
        for stage_index, stage_id in enumerate(self.ordered_ids):
            if selected_stages is not None and stage_id not in selected_stages:
                continue

            stage_def = self.definitions[stage_id]
            try:
                self.resource_governor.remaining_sec()
            except ResourceLimitExceeded as exc:
                reason = f"Scan resource budget exhausted: {exc}"
                self._record_stage_state(
                    stage_id=stage_id,
                    status=StageStatus.SKIPPED,
                    fingerprint="",
                    upstream_fingerprints={},
                    summary=reason,
                    error="",
                    artifacts=[],
                )
                self.coverage.record_stage_coverage(stage_id, status=StageStatus.SKIPPED.value, reason=reason)
                continue
            current_fp = self.compute_stage_fingerprint(stage_def)
            upstream_fps = self._upstream_stage_fingerprints(stage_def)

            if resume and stage_id != "auth_session_lifecycle" and self._can_reuse_completed_stage(stage_def, current_fp):
                self.workspace.append_jsonl(
                    "logs/execution.jsonl",
                    {
                        "event": "stage_reused",
                        "stage_id": stage_id,
                        "fingerprint": current_fp,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                )
                continue

            deps_ok, dep_reason, upstream_data = self._collect_upstream_artifacts(stage_def)
            if not deps_ok:
                self._record_stage_state(
                    stage_id=stage_id,
                    status=StageStatus.SKIPPED,
                    fingerprint=current_fp,
                    upstream_fingerprints=upstream_fps,
                    summary=dep_reason,
                    error="",
                    artifacts=[],
                )
                self.coverage.record_stage_coverage(stage_id, status=StageStatus.SKIPPED.value, reason=dep_reason)
                continue

            runner = self._runners.get(stage_id)
            if runner is None:
                reason = f"Stage runner for {stage_id!r} is not registered"
                self._record_stage_state(
                    stage_id=stage_id,
                    status=StageStatus.SKIPPED,
                    fingerprint=current_fp,
                    upstream_fingerprints=upstream_fps,
                    summary=reason,
                    error="",
                    artifacts=[],
                )
                self.coverage.record_stage_coverage(stage_id, status=StageStatus.SKIPPED.value, reason=reason)
                continue

            self._record_stage_state(
                stage_id=stage_id,
                status=StageStatus.RUNNING,
                fingerprint=current_fp,
                upstream_fingerprints=upstream_fps,
                summary="Executing",
                error="",
                artifacts=[],
            )

            context = ExecutionContext(
                target=self.target,
                workspace=self.workspace,
                scope_engine=self.scope_engine,
                coverage=self.coverage,
                config=self.config,
                upstream_artifacts=upstream_data,
                auth_manager=shared_auth_manager,
                resource_governor=self.resource_governor,
                baseline_scan_id=active_baseline_id,
                progress_callback=lambda payload, sid=stage_id: self._emit({
                    "type": "stage_progress", "stage_id": sid, **payload
                }),
            )
            try:
                result = runner(context, stage_def)
            except KeyboardInterrupt:
                self._cancelled = True
                self.resource_governor.cancel()
                reason = "Cancelled by user or termination signal"
                self._record_stage_state(
                    stage_id=stage_id,
                    status=StageStatus.FAILED,
                    fingerprint=current_fp,
                    upstream_fingerprints=upstream_fps,
                    summary=reason,
                    error="cancelled",
                    artifacts=[],
                )
                self.coverage.record_stage_coverage(
                    stage_id, status=StageStatus.FAILED.value, reason=reason
                )
                break
            except Exception as exc:
                result = StageResult(
                    stage_id=stage_id,
                    status=StageStatus.FAILED,
                    summary=f"Unhandled stage exception: {type(exc).__name__}",
                    error=scrub_text(str(exc)),
                )
            shared_auth_manager = context.auth_manager

            if not isinstance(result, StageResult) or result.stage_id != stage_id:
                result = StageResult(
                    stage_id=stage_id,
                    status=StageStatus.FAILED,
                    summary="Stage returned an invalid result record",
                    error=f"Expected StageResult for {stage_id!r}",
                )

            if result.status in {StageStatus.FAILED, StageStatus.SKIPPED}:
                self._record_stage_state(
                    stage_id=stage_id,
                    status=result.status,
                    fingerprint=current_fp,
                    upstream_fingerprints=upstream_fps,
                    summary=result.summary or result.status.value,
                    error=result.error if result.status == StageStatus.FAILED else "",
                    artifacts=[],
                )
                self.coverage.record_stage_coverage(
                    stage_id,
                    status=result.status.value,
                    reason=result.error or result.summary,
                )
                continue

            if result.status not in {StageStatus.SUCCESS, StageStatus.PARTIAL}:
                failure = f"Unsupported runner status: {result.status!r}"
                self._record_stage_state(
                    stage_id=stage_id,
                    status=StageStatus.FAILED,
                    fingerprint=current_fp,
                    upstream_fingerprints=upstream_fps,
                    summary="Stage returned unsupported terminal status",
                    error=failure,
                    artifacts=[],
                )
                self.coverage.record_stage_coverage(stage_id, status=StageStatus.FAILED.value, reason=failure)
                continue

            if (
                result.status == StageStatus.SUCCESS
                and int(result.metrics.get("targets_total", 0)) > 0
                and int(result.metrics.get("targets_tested", 0)) == 0
            ):
                result.status = StageStatus.PARTIAL
                result.summary = f"{result.summary} (downgraded: no targets were tested)".strip()

            try:
                validate_stage_artifacts(self.workspace, stage_def)
                validated_paths = [spec.relative_path for spec in stage_def.artifacts]
                artifact_hashes = self._stamp_provenance(stage_def, result.status, current_fp)
                self._record_stage_state(
                    stage_id=stage_id,
                    status=result.status,
                    fingerprint=current_fp,
                    upstream_fingerprints=upstream_fps,
                    reusable_partial=bool(result.reusable_partial),
                    summary=result.summary,
                    error=result.error,
                    artifacts=validated_paths,
                    artifact_hashes=artifact_hashes,
                )
                self.coverage.record_stage_coverage(
                    stage_id,
                    status=result.status.value,
                    targets_total=int(result.metrics.get("targets_total", 0)),
                    targets_tested=int(result.metrics.get("targets_tested", 0)),
                    targets_skipped=int(result.metrics.get("targets_skipped", 0)),
                    reason=result.summary,
                )
            except ArtifactValidationError as exc:
                self._record_stage_state(
                    stage_id=stage_id,
                    status=StageStatus.FAILED,
                    fingerprint=current_fp,
                    upstream_fingerprints=upstream_fps,
                    summary="Artifact schema validation failed",
                    error=scrub_text(str(exc)),
                    artifacts=[],
                )
                self.coverage.record_stage_coverage(stage_id, status=StageStatus.FAILED.value, reason=scrub_text(str(exc)))

        if self._cancelled:
            for pending_id in self.ordered_ids:
                entry = self.state["stages"].get(pending_id, {})
                if entry.get("status") in {StageStatus.PENDING.value, StageStatus.RUNNING.value}:
                    self._record_stage_state(
                        stage_id=pending_id,
                        status=StageStatus.SKIPPED,
                        fingerprint="",
                        upstream_fingerprints={},
                        summary="Scan cancelled before this stage ran",
                        error="",
                        artifacts=[],
                    )
            self.state["cancelled"] = True
        overall = self._compute_overall_status()
        self.state["overall_status"] = overall.value
        self.state["scope_fingerprint"] = self.scope_engine.policy.fingerprint()
        self._persist_state()
        return overall

    def _record_stage_state(
        self,
        *,
        stage_id: str,
        status: StageStatus,
        fingerprint: str,
        upstream_fingerprints: dict[str, str],
        summary: str,
        error: str,
        artifacts: list[str],
        reusable_partial: bool = False,
        artifact_hashes: dict[str, str] | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        summary = scrub_text(summary)
        error = scrub_text(error)
        started_at, started_mono = self._started.get(stage_id, ("", 0.0))
        if status == StageStatus.RUNNING:
            started_at, started_mono = now, time.monotonic()
            self._started[stage_id] = (started_at, started_mono)
        finished = status != StageStatus.RUNNING
        self.state["stages"][stage_id] = {
            "status": status.value,
            "fingerprint": fingerprint,
            "upstream_fingerprints": dict(upstream_fingerprints),
            "reusable_partial": bool(reusable_partial) if status == StageStatus.PARTIAL else False,
            "summary": summary,
            "error": error,
            "artifacts": list(artifacts),
            "started_at": started_at,
            "finished_at": now if finished else "",
            "duration_sec": round(time.monotonic() - started_mono, 3) if finished and started_mono else 0.0,
            "config_hash": _canonical_hash(self.config),
            "artifact_hashes": dict(artifact_hashes or {}),
            "updated_at": now,
        }
        self._persist_state()
        self.workspace.append_jsonl(
            "logs/execution.jsonl",
            {
                "event": "stage_transition",
                "stage_id": stage_id,
                "status": status.value,
                "summary": summary,
                "error": error,
                "timestamp": now,
            },
        )
        if finished:
            self.workspace.append_jsonl(
                "logs/execution.jsonl",
                {
                    "event": "stage_record",
                    "stage_id": stage_id,
                    "status": status.value,
                    "started_at": started_at,
                    "finished_at": now,
                    "duration_sec": self.state["stages"][stage_id]["duration_sec"],
                    "input_fingerprint": fingerprint,
                    "config_hash": _canonical_hash(self.config),
                    "artifacts": list(artifacts),
                    "artifact_hashes": dict(artifact_hashes or {}),
                    "failure_reason": error,
                    "timestamp": now,
                },
            )
        self._emit({
            "type": "stage",
            "stage_id": stage_id,
            "status": status.value,
            "summary": summary,
            "error": error,
            "artifacts": list(artifacts),
            "duration_sec": self.state["stages"][stage_id]["duration_sec"],
            "progress_percent": 100 if finished else 0,
            "reason": summary if finished and status in {StageStatus.PARTIAL, StageStatus.FAILED, StageStatus.SKIPPED} else "",
        })

    def _compute_overall_status(self) -> StageStatus:
        if self._cancelled:
            return StageStatus.FAILED
        return compute_overall_status(
            self.state["stages"].get(stage_id, {}).get("status", StageStatus.PENDING.value)
            for stage_id in self.ordered_ids
        )
