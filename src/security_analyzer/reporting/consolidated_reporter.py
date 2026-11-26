from __future__ import annotations

from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.reporting.html_renderer import HtmlRenderer
from security_analyzer.reporting.markdown_renderer import MarkdownRenderer
from security_analyzer.reporting.report_builder import ReportBuilder


def run_consolidated_reporting(ctx: ExecutionContext, stage_def: StageDefinition) -> StageResult:
    """Stage 14: Generates canonical JSON, Markdown, and self-contained HTML reports inside ./output/<scan_id>/reports/."""
    builder = ReportBuilder(ctx.workspace)
    report_payload = builder.build(stage_id=stage_def.stage_id)

    md_content = MarkdownRenderer().render(report_payload)
    html_content = HtmlRenderer().render(report_payload)

    ctx.workspace.write_json_atomic("reports/security_report.json", report_payload)
    ctx.workspace.write_text_atomic("reports/security_report.md", md_content)
    ctx.workspace.write_text_atomic("reports/security_report.html", html_content)

    summary = report_payload.get("summary") or {}
    return StageResult(
        stage_id=stage_def.stage_id,
        status=StageStatus.SUCCESS,
        summary=(
            f"Generated JSON, Markdown, and HTML reports: "
            f"{summary.get('confirmed_count', 0)} confirmed finding(s), "
            f"{summary.get('review_queue_count', 0)} queued for human review, "
            f"{summary.get('suppressed_false_positives_count', 0)} false positive(s) suppressed"
        ),
        artifacts=[
            "reports/security_report.json",
            "reports/security_report.md",
            "reports/security_report.html",
        ],
        metrics={
            "targets_total": 1,
            "targets_tested": 1,
            "targets_skipped": 0,
        },
    )
