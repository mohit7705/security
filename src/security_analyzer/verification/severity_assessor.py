from __future__ import annotations

from typing import Any

from security_analyzer.models.finding import FindingRecord, Severity, Verdict


_BASE_RISK = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.5,
}

_VERDICT_FACTOR = {
    Verdict.CONFIRMED: 1.0,
    Verdict.LIKELY: 0.80,
    Verdict.NEEDS_HUMAN_REVIEW: 0.65,
    Verdict.INCONCLUSIVE: 0.45,
    Verdict.FALSE_POSITIVE: 0.0,
}


class SeverityAssessor:
    """Explainable risk score; never silently upgrades scanner-assigned severity."""

    @staticmethod
    def assess(finding: FindingRecord) -> dict[str, Any]:
        confidence = finding.confidence
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            confidence = 0.0
        confidence = max(0.0, min(1.0, float(confidence)))

        base = _BASE_RISK.get(finding.severity, 0.5)
        verdict_factor = _VERDICT_FACTOR.get(finding.verdict, 0.45)
        score = round(base * confidence * verdict_factor, 2)

        if finding.verdict == Verdict.FALSE_POSITIVE:
            band = "SUPPRESSED"
        elif score >= 8.0:
            band = "CRITICAL"
        elif score >= 6.0:
            band = "HIGH"
        elif score >= 3.0:
            band = "MEDIUM"
        elif score >= 1.0:
            band = "LOW"
        else:
            band = "INFO"

        return {
            "source_severity": finding.severity.value,
            "risk_score": score,
            "risk_band": band,
            "confidence": round(confidence, 4),
            "verdict_factor": verdict_factor,
            "method": "internal_ranking_v1",
            "label": "Internal ranking score (0-10). This is NOT a CVSS score.",
            "cvss": None,
            "severity_was_upgraded": False,
        }
