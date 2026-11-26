from __future__ import annotations

import json
from typing import Any

from security_analyzer.utils.redaction import scrub_text

_MD_ESCAPE_CHARS = str.maketrans({
    "\\": "\\\\", "`": "\\`", "*": "\\*", "_": "\\_", "{": "\\{",
    "}": "\\}", "[": "\\[", "]": "\\]", "(": "\\(", ")": "\\)",
    "#": "\\#", "+": "\\+", "-": "\\-", "!": "\\!", "|": "\\|",
    "<": "&lt;", ">": "&gt;", "~": "\\~",
})


def _md_escape(value: Any) -> str:
    cleaned = str(value if value is not None else "").replace("\r", " ").replace("\n", " ").strip()
    return cleaned.translate(_MD_ESCAPE_CHARS)


def _md_cell(value: Any) -> str:
    return _md_escape(value)


def _safe_risk(item: dict[str, Any]) -> str:
    assessment = item.get("risk_assessment") or (item.get("metadata") or {}).get("severity_assessment") or {}
    score = assessment.get("risk_score")
    band = assessment.get("risk_band")
    if score is None:
        return "Not assessed"
    try:
        return f"Internal ranking (not CVSS): {float(score):.2f}/10 ({_md_escape(band or 'unrated')})"
    except (TypeError, ValueError):
        return "Not assessed"


def render_markdown_report(report: dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    coverage = report.get("coverage") or report.get("coverage_summary") or {}
    scope = report.get("scope") or report.get("scope_snapshot") or {}
    if "fingerprint" not in scope and isinstance(scope.get("scope"), dict):
        scope = scope["scope"]

    stages_raw = coverage.get("stages") or {}
    if isinstance(stages_raw, list):
        stages = [
            (str(item.get("stage_id", "unknown")), item)
            for item in stages_raw if isinstance(item, dict)
        ]
    elif isinstance(stages_raw, dict):
        stages = list(stages_raw.items())
    else:
        stages = []

    severity_counts = (
        summary.get("confirmed_by_severity")
        or summary.get("severity_counts")
        or {}
    )
    confirmed = report.get("confirmed_vulnerabilities")
    if confirmed is None:
        confirmed = report.get("confirmed_findings") or []
    review_queue = report.get("review_queue") or []
    potential_findings = report.get("potential_findings") or []
    needs_human_review = report.get("needs_human_review") or []
    human_review_items = needs_human_review if "needs_human_review" in report else review_queue
    suppressed = report.get("suppressed_false_positives") or []
    verified_count = summary.get(
        "evidence_verified_count",
        summary.get("evidence_artifacts_verified", 0),
    )
    invalid_count = summary.get(
        "evidence_invalid_count",
        summary.get("evidence_integrity_failures", 0),
    )

    lines: list[str] = [
        "# Security Assessment Report",
        "",
        f"- **Scan ID:** `{_md_escape(report.get('scan_id', ''))}`",
        f"- **Target:** `{_md_escape(report.get('target', ''))}`",
        f"- **Generated At:** `{_md_escape(report.get('generated_at', ''))}`",
        f"- **Overall Pipeline Status:** `{_md_escape(report.get('overall_pipeline_status', summary.get('overall_status', 'UNKNOWN')))}`",
        f"- **Scope Fingerprint:** `{_md_escape(str(scope.get('fingerprint', ''))[:16])}`",
        "",
        "## 1. Executive Summary",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Total Assets | {coverage.get('total_assets', summary.get('total_assets', 0))} |",
        f"| Total Endpoints | {coverage.get('total_endpoints', summary.get('total_endpoints', 0))} |",
        f"| Unique URLs | {coverage.get('unique_urls', 0)} |",
        f"| Unprobed Endpoints | {coverage.get('unprobed_endpoints', 0)} |",
        f"| Confirmed Findings | {summary.get('confirmed_count', 0)} |",
        f"| Potential Findings (Not Confirmed) | {summary.get('potential_findings_count', 0)} |",
        f"| Findings Requiring Human Review | {summary.get('needs_human_review_count', summary.get('review_queue_count', 0))} |",
        f"| Suppressed False Positives | {summary.get('suppressed_false_positives_count', summary.get('false_positive_count', 0))} |",
        f"| Evidence Artifacts Verified | {verified_count} |",
        f"| Evidence Integrity Failures | {invalid_count} |",
        "",
        "### Severity Breakdown (Confirmed Findings)",
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---:|---:|---:|---:|---:|",
        (
            f"| {severity_counts.get('CRITICAL', 0)} | {severity_counts.get('HIGH', 0)} | "
            f"{severity_counts.get('MEDIUM', 0)} | {severity_counts.get('LOW', 0)} | "
            f"{severity_counts.get('INFO', 0)} |"
        ),
        "",
        "## 2. Scope and Coverage",
        "",
        f"- **Allowed domains:** {_md_escape(', '.join(scope.get('allowed_domains') or []))}",
        f"- **Excluded paths:** {_md_escape(', '.join(scope.get('excluded_paths') or []) or 'None')}",
        f"- **Out-of-scope blocks:** {scope.get('out_of_scope_blocks_count', 0)}",
        "",
        "| Stage | Status | Tested | Total | Skipped | Notes |",
        "|---|---|---:|---:|---:|---|",
    ]

    for stage_id, info in stages:
        lines.append(
            f"| `{_md_escape(stage_id)}` | {_md_cell(info.get('status'))} | "
            f"{info.get('targets_tested', 0)} | {info.get('targets_total', 0)} | "
            f"{info.get('targets_skipped', 0)} | {_md_cell(info.get('error') or info.get('summary') or info.get('reason', ''))} |"
        )
    lines.append("")

    lines.extend(["## 3. Confirmed Vulnerabilities", ""])
    if not confirmed:
        lines.extend(["No confirmed findings were recorded during this scan.", ""])
    else:
        for item in confirmed:
            meta = item.get("metadata") or {}
            location = meta.get("mutated_url") or meta.get("target_url") or meta.get("url") or item.get("endpoint_id", "")
            description = scrub_text(str(item.get("description", item.get("summary", ""))))
            lines.extend([
                f"### [{_md_escape(item.get('severity'))}] {_md_escape(item.get('title'))} (`{_md_escape(item.get('finding_id'))}`)",
                "",
                f"- **Verdict:** `{_md_escape(item.get('verdict'))}` (Confidence: `{item.get('confidence')}`)",
                f"- **Risk assessment:** {_safe_risk(item)}",
                f"- **Category:** `{_md_escape(item.get('category'))}`",
                f"- **Location:** `{_md_escape(location)}`",
                f"- **Description:** {_md_escape(description)}",
            ])
            if item.get("severity_rationale"):
                lines.append(f"- **Severity rationale:** {_md_escape(scrub_text(str(item.get('severity_rationale'))))}")
            if item.get("cvss_assessment"):
                cvss = item.get("cvss_assessment")
                if isinstance(cvss, dict) and cvss.get("score_type") == "CVSS_BASE_SCORE":
                    cvss_label = f"CVSS v{cvss.get('version', '3.1')} Base Score"
                    cvss_value = f"{cvss.get('base_score')} ({cvss.get('base_severity')}) — `{cvss.get('vector', '')}`"
                else:
                    cvss_label = "CVSS source data (not independently calculated)"
                    cvss_value = json.dumps(cvss, sort_keys=True) if isinstance(cvss, (dict, list)) else str(cvss)
                lines.append(f"- **{cvss_label}:** `{_md_escape(cvss_value)}`")
            if item.get("reproduction_steps"):
                steps = item.get("reproduction_steps")
                lines.append(f"- **Reproduction:** {_md_escape(scrub_text(str(steps)))}")
            if item.get("remediation"):
                lines.append(f"- **Remediation:** {_md_escape(scrub_text(str(item.get('remediation'))))}")
            evidence_items = item.get("resolved_evidence") or item.get("evidence") or []
            for evidence in evidence_items:
                digest = evidence.get("verified_sha256") or evidence.get("sha256", "")
                integrity = "VERIFIED" if evidence.get("integrity_verified") else evidence.get("integrity_reason", "UNVERIFIED")
                evidence_text = scrub_text(str(evidence.get("summary") or evidence.get("description") or ""))
                if evidence_text:
                    lines.append(f"- **Evidence details:** {_md_escape(evidence_text)}")
                lines.append(
                    f"- **Evidence:** `{_md_escape(scrub_text(str(evidence.get('artifact_path'))))}` "
                    f"(SHA-256: `{_md_escape(digest)}`, integrity: `{_md_escape(integrity)}`)"
                )
            lines.append("")

    config_items = report.get("confirmed_configuration_issues") or []
    lines.extend(["## 3b. Confirmed Configuration Issues", ""])
    if not config_items:
        lines.extend(["No confirmed configuration observations.", ""])
    for item in config_items:
        urls = ", ".join(str(url) for url in ((item.get("metadata") or {}).get("affected_urls") or [])[:10])
        lines.append(
            f"- **[{_md_escape(item.get('severity'))}]** {_md_escape(item.get('title'))} "
            f"(`{_md_escape(item.get('category'))}`)" + (f" — affected: {_md_escape(urls)}" if urls else "")
        )
    if config_items:
        lines.append("")

    incomplete = report.get("incomplete_coverage") or []
    if incomplete:
        lines.extend(["## 3c. Incomplete Coverage", ""])
        for row in incomplete:
            lines.append(
                f"- `{_md_escape(row.get('stage_id'))}`: {_md_escape(row.get('status'))} — "
                f"{_md_escape(scrub_text(str(row.get('reason', ''))))}"
            )
        lines.append("")

    lines.extend(["## 4. Potential Findings (Not Confirmed)", ""])
    if not potential_findings:
        lines.extend(["No findings currently carry a `LIKELY` verdict.", ""])
    else:
        for item in potential_findings:
            lines.append(
                f"- **[{_md_escape(item.get('severity'))}]** {_md_escape(item.get('title'))} "
                f"(`{_md_escape(item.get('finding_id'))}`) — "
                f"{_md_escape(item.get('category'))}; confidence `{item.get('confidence')}`"
            )
        lines.append("")

    lines.extend(["## 5. Findings Requiring Human Review", ""])
    if not human_review_items:
        lines.extend(["No findings are awaiting manual review.", ""])
    else:
        lines.extend([
            "| ID | Severity | Verdict | Confidence | Risk | Category | Title | Location |",
            "|---|---|---|---:|---|---|---|---|",
        ])
        for item in human_review_items:
            meta = item.get("metadata") or {}
            location = meta.get("mutated_url") or meta.get("target_url") or meta.get("url") or item.get("endpoint_id", "")
            lines.append(
                f"| `{_md_escape(item.get('finding_id'))}` | {_md_cell(item.get('severity'))} | "
                f"{_md_cell(item.get('verdict'))} | {item.get('confidence')} | {_safe_risk(item)} | "
                f"{_md_cell(item.get('category'))} | {_md_cell(item.get('title'))} | "
                f"`{_md_cell(location)}` |"
            )
        lines.append("")

    lines.extend(["## 6. Suppressed False Positives", ""])
    if not suppressed:
        lines.extend(["No findings were suppressed as false positives.", ""])
    else:
        lines.append(
            f"{len(suppressed)} candidate finding(s) were not reproduced or were otherwise classified as false positives."
        )
        lines.append("")
        for item in suppressed[:100]:
            reason = ((item.get("metadata") or {}).get("verification") or {}).get("reason", "No reason recorded")
            lines.append(
                f"- `{_md_escape(item.get('finding_id'))}` — "
                f"{_md_escape(item.get('title'))}: {_md_escape(reason)}"
            )
        lines.append("")

    skipped_checks = coverage.get("skipped_checks") or []
    if skipped_checks:
        lines.extend(["## 7. Skipped Checks and Degraded Coverage", ""])
        for entry in skipped_checks[:100]:
            lines.append(
                f"- `{_md_escape(entry.get('stage_id'))}` / "
                f"`{_md_escape(entry.get('check_name'))}`: {_md_escape(entry.get('reason'))}"
            )
        lines.append("")

    coverage_ledger = report.get("coverage_ledger") or []
    if coverage_ledger:
        lines.extend(["## 8. Coverage Ledger", ""])
        for item in coverage_ledger[:200]:
            details = " / ".join(
                str(item.get(key, "")) for key in ("stage_id", "check_name", "tool")
                if item.get(key)
            )
            reason = scrub_text(str(item.get("reason", "")))
            lines.append(
                f"- **{_md_escape(item.get('kind'))}** {_md_escape(details)} — {_md_escape(reason)}"
            )
        lines.append("")

    environment = report.get("environment") or {}
    tools = environment.get("tools") or {}
    lines.extend(["## 9. Scan Environment", ""])
    lines.append(f"- **Python:** `{_md_escape(environment.get('python', 'unknown'))}`")
    lines.append(f"- **Platform:** `{_md_escape(environment.get('platform', 'unknown'))}`")
    for tool_name, info in sorted(tools.items()):
        if isinstance(info, dict):
            lines.append(f"- **{_md_escape(tool_name)}:** `{_md_escape(info.get('version', 'unknown'))}`")
    if report.get("report_warnings"):
        lines.extend(["", "### Report input warnings", ""])
        for warning in report["report_warnings"]:
            lines.append(
                f"- `{_md_escape(warning.get('artifact'))}`: {_md_escape(warning.get('warning'))}"
            )
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


class MarkdownRenderer:
    """Object-oriented facade used by the reporting pipeline."""

    def render(self, report: dict[str, Any]) -> str:
        return render_markdown_report(report)
