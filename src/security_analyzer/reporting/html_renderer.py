from __future__ import annotations

import html
from typing import Any

from security_analyzer.utils.redaction import scrub_text


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


class HtmlRenderer:
    """Renders a self-contained, XSS-safe single-file HTML assessment report with zero external assets."""

    SEVERITY_COLORS: dict[str, str] = {
        "CRITICAL": "#991b1b",
        "HIGH": "#c2410c",
        "MEDIUM": "#b45309",
        "LOW": "#1d4ed8",
        "INFO": "#374151",
    }

    def render(self, report: dict[str, Any]) -> str:
        summary = report.get("summary") or {}
        scope = report.get("scope") or {}
        coverage = report.get("coverage") or {}
        conf_sev = summary.get("confirmed_by_severity") or {}
        rev_sev = summary.get("needs_human_review_by_severity") or summary.get("review_queue_by_severity") or {}
        potential_sev = summary.get("potential_findings_by_severity") or {}

        sev_rows = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            color = self.SEVERITY_COLORS[sev]
            sev_rows.append(
                f"<tr><td><span class='badge' style='background:{color}'>{_e(sev)}</span></td>"
                f"<td><strong>{int(conf_sev.get(sev, 0))}</strong></td>"
                f"<td>{int(potential_sev.get(sev, 0))}</td>"
                f"<td>{int(rev_sev.get(sev, 0))}</td></tr>"
            )

        stage_rows = []
        for st in coverage.get("stages") or []:
            note = st.get("error") or st.get("summary") or ""
            stage_rows.append(
                f"<tr><td><code>{_e(st.get('stage_id'))}</code></td>"
                f"<td><code>{_e(st.get('status'))}</code></td>"
                f"<td>{int(st.get('targets_tested', 0))} / {int(st.get('targets_total', 0))}</td>"
                f"<td>{_e(note)}</td></tr>"
            )

        _vulns = report.get("confirmed_vulnerabilities")
        confirmed_cards = self._render_finding_cards(_vulns if _vulns is not None else (report.get("confirmed_findings") or []), empty_msg="No confirmed vulnerabilities were identified within the authorized scope.")
        config_cards = self._render_finding_cards(report.get("confirmed_configuration_issues") or [], empty_msg="No confirmed configuration observations.")
        potential_cards = self._render_finding_cards(
            report.get("potential_findings") or [],
            empty_msg="No potential findings are currently classified as likely.",
        )
        review_items = report.get("needs_human_review") if "needs_human_review" in report else report.get("review_queue")
        review_cards = self._render_finding_cards(
            review_items or [],
            empty_msg="No unconfirmed items are queued for human review.",
        )
        coverage_rows = []
        for item in report.get("coverage_ledger") or []:
            detail = " / ".join(
                str(item.get(key, "")) for key in ("stage_id", "check_name", "tool")
                if item.get(key)
            )
            coverage_rows.append(
                f"<tr><td>{_e(item.get('kind'))}</td><td>{_e(detail)}</td><td>{_e(item.get('reason'))}</td></tr>"
            )
        coverage_ledger_html = (
            "<table><thead><tr><th>Type</th><th>Area</th><th>Reason</th></tr></thead>"
            f"<tbody>{''.join(coverage_rows)}</tbody></table>"
            if coverage_rows else "<p>No additional coverage gaps were recorded.</p>"
        )
        environment = report.get("environment") or {}
        tool_rows = []
        for name, info in sorted((environment.get("tools") or {}).items()):
            if isinstance(info, dict):
                tool_rows.append(f"<tr><td>{_e(name)}</td><td>{_e(info.get('version'))}</td></tr>")
        environment_html = (
            "<table><thead><tr><th>Tool</th><th>Detected version</th></tr></thead>"
            f"<tbody>{''.join(tool_rows)}</tbody></table>"
            if tool_rows else "<p>No external tool version metadata was captured.</p>"
        )

        fp_section = ""
        false_positives = report.get("suppressed_false_positives") or []
        if false_positives:
            fp_rows = []
            for fp in false_positives:
                reason = ((fp.get("metadata") or {}).get("verification") or {}).get("reason", "Did not reproduce on replay")
                fp_rows.append(
                    f"<tr><td><code>{_e(fp.get('finding_id'))}</code></td>"
                    f"<td><code>{_e(fp.get('category'))}</code></td>"
                    f"<td>{_e(fp.get('title'))}</td>"
                    f"<td>{_e(reason)}</td></tr>"
                )
            fp_section = f"""
            <section>
              <h2>5. Suppressed False Positives (Audit Appendix)</h2>
              <table>
                <thead><tr><th>Finding ID</th><th>Category</th><th>Title</th><th>Replay Rejection Reason</th></tr></thead>
                <tbody>{''.join(fp_rows)}</tbody>
              </table>
            </section>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Security Assessment Report — {_e(report.get('target'))}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #111827; background: #f9fafb; margin: 0; padding: 2rem; line-height: 1.5; }}
    .container {{ max-width: 1080px; margin: 0 auto; background: #ffffff; padding: 2rem 2.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    h1 {{ margin-top: 0; font-size: 1.65rem; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.75rem; }}
    h2 {{ margin-top: 2rem; font-size: 1.25rem; color: #1f2937; border-bottom: 1px solid #e5e7eb; padding-bottom: 0.4rem; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.75rem; background: #f3f4f6; padding: 1rem; border-radius: 6px; font-size: 0.9rem; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 0.75rem; font-size: 0.9rem; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 0.55rem 0.75rem; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; font-weight: 600; }}
    code {{ background: #f3f4f6; padding: 0.12rem 0.35rem; border-radius: 4px; font-size: 0.85em; word-break: break-all; }}
    .badge {{ display: inline-block; color: #fff; font-weight: 600; font-size: 0.75rem; padding: 0.18rem 0.55rem; border-radius: 999px; }}
    .card {{ border: 1px solid #e5e7eb; border-radius: 6px; padding: 1rem 1.25rem; margin-top: 1rem; background: #fff; }}
    .card-header {{ display: flex; align-items: center; gap: 0.65rem; margin-bottom: 0.5rem; }}
    .card-title {{ font-weight: 600; font-size: 1.02rem; }}
    .kv {{ margin: 0.3rem 0; font-size: 0.9rem; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Security Assessment Report — <code>{_e(report.get('target'))}</code></h1>
    <div class="meta-grid">
      <div><strong>Scan ID:</strong><br /><code>{_e(report.get('scan_id'))}</code></div>
      <div><strong>Generated (UTC):</strong><br /><code>{_e(report.get('generated_at'))}</code></div>
      <div><strong>Pipeline Status:</strong><br /><code>{_e(report.get('overall_pipeline_status'))}</code></div>
      <div><strong>Scope Fingerprint:</strong><br /><code>{_e(scope.get('fingerprint'))}</code></div>
    </div>

    <section>
      <h2>1. Executive Summary</h2>
      <table>
        <thead><tr><th>Severity</th><th>Confirmed Findings</th><th>Potential</th><th>Needs Human Review</th></tr></thead>
        <tbody>
          {''.join(sev_rows)}
          <tr>
            <td><strong>Total</strong></td>
            <td><strong>{int(summary.get('confirmed_count', 0))}</strong></td>
            <td><strong>{int(summary.get('potential_findings_count', 0))}</strong></td>
            <td><strong>{int(summary.get('needs_human_review_count', summary.get('review_queue_count', 0)))}</strong></td>
          </tr>
        </tbody>
      </table>
      <p>Suppressed false positives: <strong>{int(summary.get('suppressed_false_positives_count', 0))}</strong> |
         Cryptographic evidence records: <strong>{int(summary.get('evidence_records_count', 0))}</strong> |
         Evidence verified: <strong>{int(summary.get('evidence_verified_count', 0))}</strong> |
         Integrity failures: <strong>{int(summary.get('evidence_invalid_count', 0))}</strong></p>
    </section>

    <section>
      <h2>2. Scope &amp; Assessment Coverage</h2>
      <p class="kv"><strong>Allowed Domains:</strong> <code>{_e(', '.join(scope.get('allowed_domains') or []))}</code></p>
      <p class="kv"><strong>Excluded Paths:</strong> <code>{_e(', '.join(scope.get('excluded_paths') or []) or 'None')}</code></p>
      <p class="kv"><strong>Out-of-Scope Requests Blocked:</strong> {int(scope.get('out_of_scope_blocks_count', 0))}</p>
      <p class="kv"><strong>Attack Surface Inventoried:</strong> {int(coverage.get('total_assets', 0))} asset(s),
         {int(coverage.get('total_endpoints', 0))} endpoint(s) ({int(coverage.get('reachable_endpoints', 0))} reachable,
         {int(coverage.get('authenticated_endpoints', 0))} authenticated; {int(coverage.get('unique_urls', 0))} unique URL(s),
         {int(coverage.get('unprobed_endpoints', 0))} unprobed)</p>
      <table>
        <thead><tr><th>Stage ID</th><th>Status</th><th>Tested / Total</th><th>Summary</th></tr></thead>
        <tbody>{''.join(stage_rows)}</tbody>
      </table>
    </section>

    <section>
      <h2>3. Confirmed Vulnerabilities</h2>
      {confirmed_cards}
    </section>

    <section>
      <h2>3b. Confirmed Configuration Issues</h2>
      {config_cards}
    </section>

    <section>
      <h2>4. Potential Findings (Not Confirmed)</h2>
      {potential_cards}
    </section>

    <section>
      <h2>5. Findings Requiring Human Review</h2>
      {review_cards}
    </section>

    <section>
      <h2>6. Coverage Ledger</h2>
      {coverage_ledger_html}
    </section>

    <section>
      <h2>7. Scan Environment</h2>
      <p class="kv"><strong>Python:</strong> {_e(environment.get('python', 'unknown'))} |
         <strong>Platform:</strong> {_e(environment.get('platform', 'unknown'))}</p>
      {environment_html}
    </section>

    {fp_section}
  </div>
</body>
</html>
"""

    def _render_finding_cards(self, items: list[dict[str, Any]], *, empty_msg: str) -> str:
        if not items:
            return f"<p>{_e(empty_msg)}</p>"

        cards: list[str] = []
        for item in items:
            sev = str(item.get("severity", "INFO")).upper()
            color = self.SEVERITY_COLORS.get(sev, "#374151")
            meta = item.get("metadata") or {}
            ver_info = meta.get("verification") or {}
            target_url = meta.get("mutated_url") or meta.get("target_url") or meta.get("url") or item.get("endpoint_id", "")

            ev_lines = []
            for ev in item.get("resolved_evidence") or []:
                sha = ev.get("verified_sha256") or ev.get("sha256", "")
                evidence_text = scrub_text(str(ev.get("summary") or ev.get("description") or ""))
                if evidence_text:
                    ev_lines.append(f"<div class='kv'><strong>Evidence details:</strong> {_e(evidence_text)}</div>")
                ev_lines.append(
                    f"<div class='kv'><strong>Evidence:</strong> <code>{_e(scrub_text(str(ev.get('artifact_path'))))}</code> "
                    f"(SHA-256: <code>{_e(sha)}</code>; integrity: "
                    f"<strong>{'VERIFIED' if ev.get('integrity_verified') else _e(ev.get('integrity_reason', 'UNVERIFIED'))}</strong>)</div>"
                )

            proof_html = (
                f"<div class='kv'><strong>Verification Proof:</strong> {_e(scrub_text(str(ver_info['reason'])))}</div>"
                if ver_info.get("reason")
                else ""
            )
            risk = item.get("risk_assessment") or meta.get("severity_assessment") or {}
            risk_html = (
                f"<div class='kv'><strong>Internal ranking (not CVSS):</strong> "
                f"{float(risk.get('risk_score', 0.0)):.2f}/10 "
                f"({_e(risk.get('risk_band', 'UNASSESSED'))})</div>"
                if risk
                else ""
            )
            rationale_html = (
                f"<div class='kv'><strong>Severity rationale:</strong> {_e(scrub_text(str(item.get('severity_rationale'))))}</div>"
                if item.get("severity_rationale")
                else ""
            )
            cvss = item.get("cvss_assessment")
            if isinstance(cvss, dict) and cvss.get("score_type") == "CVSS_BASE_SCORE":
                cvss_html = (
                    f"<div class='kv'><strong>CVSS v{_e(cvss.get('version', '3.1'))} Base Score:</strong> "
                    f"{_e(cvss.get('base_score'))} ({_e(cvss.get('base_severity'))}) "
                    f"<code>{_e(cvss.get('vector'))}</code></div>"
                )
            else:
                cvss_html = (
                    f"<div class='kv'><strong>CVSS source data (not independently calculated):</strong> {_e(cvss)}</div>"
                    if cvss is not None
                    else ""
                )
            reproduction = item.get("reproduction_steps")
            reproduction_html = (
                f"<div class='kv'><strong>Reproduction:</strong> {_e(scrub_text(str(reproduction)))}</div>"
                if reproduction
                else ""
            )
            rem_html = (
                f"<div class='kv'><strong>Remediation:</strong> {_e(scrub_text(str(item.get('remediation'))))}</div>"
                if item.get("remediation")
                else ""
            )

            cards.append(
                f"""
                <div class="card">
                  <div class="card-header">
                    <span class="badge" style="background:{color}">{_e(sev)}</span>
                    <span class="card-title">{_e(item.get('title'))}</span>
                  </div>
                  <div class="kv"><strong>Finding ID:</strong> <code>{_e(item.get('finding_id'))}</code> |
                    <strong>Category:</strong> <code>{_e(item.get('category'))}</code> |
                    <strong>Verdict:</strong> <code>{_e(item.get('verdict'))}</code> ({float(item.get('confidence', 0.0)):.2f})</div>
                  <div class="kv"><strong>Target:</strong> <code>{_e(target_url)}</code> |
                    <strong>Identity:</strong> <code>{_e(item.get('identity_id', 'anonymous'))}</code></div>
                  <div class="kv"><strong>Description:</strong> {_e(scrub_text(str(item.get('description') or item.get('summary') or '')))}</div>
                  {proof_html}
                  {risk_html}
                  {rationale_html}
                  {cvss_html}
                  {reproduction_html}
                  {''.join(ev_lines)}
                  {rem_html}
                </div>
                """
            )
        return "\n".join(cards)
