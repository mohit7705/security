from __future__ import annotations

from security_analyzer.models.finding import FindingRecord, Verdict
from security_analyzer.verification.poc_replayer import ReplayOutcome


class ConfidenceScorer:
    """Deterministic confidence score grounded in reproducibility and evidence integrity."""

    @staticmethod
    def score(
        finding: FindingRecord,
        outcome: ReplayOutcome,
        *,
        evidence_integrity: bool | None = None,
    ) -> float:
        base = 0.35

        if outcome.reproducible:
            base += 0.35
        elif outcome.replayed:
            base -= 0.10

        if outcome.identity_contrast_verified:
            base += 0.15

        if evidence_integrity is True:
            base += 0.10
        elif evidence_integrity is False:
            base -= 0.25
        elif outcome.evidence_record is not None and outcome.evidence_record.sha256:
            # Compatibility for direct callers; the verification stage always
            # passes an explicit integrity result.
            base += 0.05

        sources = finding.metadata.get("corroborating_sources") or []
        if isinstance(sources, list) and len(set(map(str, sources))) > 1:
            base += min(0.05, 0.025 * (len(set(map(str, sources))) - 1))

        if outcome.verdict == Verdict.FALSE_POSITIVE:
            return round(max(0.05, min(0.25, base)), 2)

        if outcome.verdict == Verdict.NEEDS_HUMAN_REVIEW:
            return round(max(0.30, min(0.79, base)), 2)

        if outcome.verdict == Verdict.INCONCLUSIVE:
            return round(max(0.10, min(0.55, base)), 2)

        if outcome.verdict == Verdict.CONFIRMED and evidence_integrity is False:
            return round(min(0.79, max(0.30, base)), 2)

        return round(max(0.80, min(0.99, base)), 2)
