from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.stage_registry import (
    StageDefinition,
    StageResult,
    StageStatus,
    load_validated_stage_artifact,
)
from security_analyzer.deep_checks.authorization_idor import _get_or_init_auth_manager
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.models.finding import Verdict
from security_analyzer.verification.ai_triage import OptionalAiTriage
from security_analyzer.verification.confidence_scorer import ConfidenceScorer
from security_analyzer.verification.cvss import CvssVectorError, calculate_cvss31
from security_analyzer.verification.evidence_store import EvidenceStore
from security_analyzer.verification.finding_deduplicator import (
    ANALYSIS_ARTIFACT_PRODUCERS,
    FindingDeduplicator,
)
from security_analyzer.verification.poc_replayer import DeterministicPocReplayer, ReplayOutcome
from security_analyzer.verification.severity_assessor import SeverityAssessor


def _validate_finding_source(
    ctx: ExecutionContext,
    finding,
    cache: dict[str, dict[str, Any] | None],
) -> bool | None:
    """Validate a finding's declared source artifact against stage provenance."""
    source_path = str(finding.metadata.get("source_artifact", "")).strip()
    if not source_path:
        return None
    producer = ANALYSIS_ARTIFACT_PRODUCERS.get(source_path)
    if producer is None:
        finding.metadata["source_artifact_integrity"] = "UNTRUSTED_SOURCE_PATH"
        return False
    if source_path not in cache:
        producer_stage, allowed_stage_ids = producer
        cache[source_path] = load_validated_stage_artifact(
            ctx.workspace,
            producer_stage,
            source_path,
            allowed_stage_ids=allowed_stage_ids,
        )
    payload = cache[source_path]
    if payload is None:
        finding.metadata["source_artifact_integrity"] = "INVALID_OR_UNRECORDED"
        return False
    try:
        digest = ctx.workspace.file_sha256(source_path)
    except Exception:
        finding.metadata["source_artifact_integrity"] = "UNREADABLE"
        return False
    finding.metadata["source_artifact_sha256"] = digest
    finding.metadata["source_artifact_integrity"] = "VERIFIED"
    return True


def run_evidence_verification(
    ctx: ExecutionContext,
    stage_def: StageDefinition,
) -> StageResult:
    """Stage 13: provenance validation, safe replay, evidence integrity, confidence, severity and optional AI advice."""
    deduplicator = FindingDeduplicator()
    findings = deduplicator.collect_from_workspace(ctx.workspace)

    loaded_artifacts = sorted(
        relative_path
        for relative_path, (producer_stage_id, allowed_stage_ids)
        in ANALYSIS_ARTIFACT_PRODUCERS.items()
        if load_validated_stage_artifact(
            ctx.workspace,
            producer_stage_id,
            relative_path,
            allowed_stage_ids=allowed_stage_ids,
        ) is not None
    )

    inventory = UnifiedEndpointInventory(ctx.workspace)
    auth_mgr = _get_or_init_auth_manager(ctx)
    timeouts = ctx.config.get("timeouts", {})

    replayer = DeterministicPocReplayer(
        workspace=ctx.workspace,
        scope_engine=ctx.scope_engine,
        coverage=ctx.coverage,
        inventory=inventory,
        auth_manager=auth_mgr,
        connect_timeout=float(timeouts.get("http_connect_sec", 10)),
        read_timeout=float(timeouts.get("http_read_sec", 20)),
        resource_governor=ctx.resource_governor,
    )

    replay_records: list[dict[str, Any]] = []
    evidence_catalog: list[dict[str, Any]] = []
    source_cache: dict[str, dict[str, Any] | None] = {}
    incomplete_reasons: list[str] = []
    completed_findings = 0
    store = EvidenceStore(ctx.workspace)

    try:
        for finding in findings:
            try:
                source_valid = _validate_finding_source(
                    ctx,
                    finding,
                    source_cache,
                )
            except Exception as exc:
                source_valid = False
                finding.metadata["source_artifact_integrity"] = f"VALIDATION_ERROR:{type(exc).__name__}"

            if source_valid is False:
                outcome = ReplayOutcome(
                    finding_id=finding.finding_id,
                    replayed=False,
                    verdict=Verdict.NEEDS_HUMAN_REVIEW,
                    reproducible=False,
                    identity_contrast_verified=False,
                    reason="Finding source artifact failed provenance validation; replay was not attempted",
                )
                incomplete_reasons.append(
                    f"{finding.finding_id}: source artifact provenance invalid"
                )
                ctx.coverage.record_skipped_check(
                    stage_def.stage_id,
                    "finding_source_provenance",
                    f"{finding.finding_id}: source artifact provenance invalid",
                )
            else:
                try:
                    outcome = replayer.verify_finding(
                        finding,
                        stage_id=stage_def.stage_id,
                    )
                except Exception as exc:
                    outcome = ReplayOutcome(
                        finding_id=finding.finding_id,
                        replayed=False,
                        verdict=Verdict.INCONCLUSIVE,
                        reproducible=False,
                        identity_contrast_verified=False,
                        reason=f"Verification replay raised {type(exc).__name__}",
                    )
                    incomplete_reasons.append(
                        f"{finding.finding_id}: replay raised {type(exc).__name__}"
                    )
                    ctx.coverage.record_skipped_check(
                        stage_def.stage_id,
                        "finding_replay",
                        f"{finding.finding_id}: {type(exc).__name__}",
                    )

            integrity: dict[str, Any] = {
                "valid": False,
                "reason": "evidence_not_generated",
                "observed_sha256": "",
            }
            if outcome.evidence_record is not None:
                integrity = store.verify_record(
                    outcome.evidence_record,
                    finding_id=finding.finding_id,
                )
                outcome.evidence_integrity = bool(integrity.get("valid"))
                outcome.evidence_record.metadata["integrity_verified"] = outcome.evidence_integrity
                outcome.evidence_record.metadata["integrity_reason"] = integrity.get("reason", "")
                store.record_evidence(
                    outcome.evidence_record,
                    finding_id=finding.finding_id,
                    integrity=integrity,
                )
                evidence_catalog.append(
                    {
                        **outcome.evidence_record.to_dict(),
                        "integrity_verified": outcome.evidence_integrity,
                        "integrity_reason": integrity.get("reason", ""),
                        "verified_sha256": integrity.get("observed_sha256", ""),
                    }
                )

            # A CONFIRMED verdict requires a present, matching evidence artifact.
            if outcome.verdict == Verdict.CONFIRMED and not outcome.evidence_integrity:
                outcome.verdict = Verdict.NEEDS_HUMAN_REVIEW
                outcome.reproducible = False
                outcome.reason = (
                    "Replay appeared positive but its evidence artifact failed integrity validation; "
                    "human review required"
                )

            evidence_completed = (
                outcome.evidence_record is not None
                and outcome.evidence_integrity
                and outcome.verdict != Verdict.INCONCLUSIVE
            )
            if evidence_completed:
                completed_findings += 1
            elif outcome.verdict == Verdict.INCONCLUSIVE or not outcome.replayed:
                incomplete_reasons.append(
                    f"{finding.finding_id}: {outcome.reason[:240]}"
                )
                ctx.coverage.record_skipped_check(
                    stage_def.stage_id,
                    "finding_verification_incomplete",
                    f"{finding.finding_id}: {outcome.reason[:240]}",
                )

            finding.verdict = outcome.verdict
            finding.confidence = ConfidenceScorer.score(
                finding,
                outcome,
                evidence_integrity=(
                    outcome.evidence_integrity
                    if outcome.evidence_record is not None
                    else False
                ),
            )
            finding.metadata["verification"] = {
                "replayed": outcome.replayed,
                "reproducible": outcome.reproducible,
                "identity_contrast_verified": outcome.identity_contrast_verified,
                "evidence_integrity": outcome.evidence_integrity,
                "reason": outcome.reason,
            }
            finding.metadata["severity_assessment"] = SeverityAssessor.assess(finding)

            # Calculate CVSS only from an explicitly supplied complete vector.
            # Scanner severity labels are never converted into an invented vector.
            raw_cvss = finding.metadata.get("cvss")
            cvss_vector = finding.metadata.get("cvss_vector")
            if not cvss_vector and isinstance(raw_cvss, dict):
                cvss_vector = raw_cvss.get("vector")
            if cvss_vector:
                vector_text = str(cvss_vector).strip()
                try:
                    finding.metadata["cvss_assessment"] = calculate_cvss31(vector_text)
                except CvssVectorError as exc:
                    finding.metadata["cvss_assessment"] = {
                        "valid": False,
                        "vector": vector_text[:256],
                        "error": str(exc),
                        "score_type": "CVSS_BASE_SCORE",
                    }

            replay_data = outcome.to_dict()
            replay_records.append(replay_data)
            store.record_replay(replay_data)

        ai_triage = OptionalAiTriage(ctx.config)
        findings, ai_summary = ai_triage.triage_findings(findings)

        for finding in findings:
            # AI advice is metadata only; severity and verdict remain deterministic.
            store.record_finding(finding.to_dict())

        store_summary = store.summary()
        store_summary["database_path"] = EvidenceStore.RELATIVE_PATH
        verdict_counts = {verdict.value: 0 for verdict in Verdict}
        for finding in findings:
            verdict_counts[finding.verdict.value] = (
                verdict_counts.get(finding.verdict.value, 0) + 1
            )

        payload: dict[str, Any] = {
            "schema_version": "1.1",
            "scan_id": ctx.workspace.scan_id,
            "stage_id": stage_def.stage_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "artifacts_ingested": loaded_artifacts,
            "summary": {
                "total_deduplicated_findings": len(findings),
                "verdicts": verdict_counts,
                "evidence_records_count": len(evidence_catalog),
                "verification_completed": completed_findings,
                "verification_incomplete": len(findings) - completed_findings,
                "incomplete_reasons": incomplete_reasons[:100],
                "evidence_store": store_summary,
                "ai_triage": ai_summary,
            },
            "findings": [finding.to_dict() for finding in findings],
            "evidence_records": evidence_catalog,
            "replay_outcomes": replay_records,
        }
        ctx.workspace.write_json_atomic(
            "verification/verified_findings.json",
            payload,
        )
    finally:
        store.close()

    final_status = StageStatus.PARTIAL if incomplete_reasons else StageStatus.SUCCESS
    return StageResult(
        stage_id=stage_def.stage_id,
        status=final_status,
        summary=(
            f"Verified {completed_findings}/{len(findings)} deduplicated finding(s): "
            f"{verdict_counts['CONFIRMED']} CONFIRMED, "
            f"{verdict_counts['NEEDS_HUMAN_REVIEW']} NEEDS_HUMAN_REVIEW, "
            f"{verdict_counts['FALSE_POSITIVE']} FALSE_POSITIVE; "
            f"{store_summary['evidence_verified']} evidence record(s) integrity-verified"
            + (f"; {len(incomplete_reasons)} incomplete verification item(s)" if incomplete_reasons else "")
        ),
        artifacts=["verification/verified_findings.json"],
        metrics={
            "targets_total": len(findings),
            "targets_tested": completed_findings,
            "targets_skipped": max(0, len(findings) - completed_findings),
        },
    )
