from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from security_analyzer.core.stage_registry import (
    StageStatus,
    compute_overall_status,
    load_validated_stage_artifact,
)
from security_analyzer.core.workspace import WorkspaceManager
from security_analyzer.models.finding import Severity, Verdict
from security_analyzer.verification.finding_deduplicator import SEVERITY_RANK


class ReportBuilder:
    """Aggregates verified findings, evidence hashes, inventory, and coverage into reports/security_report.json."""

    def __init__(
        self,
        workspace: WorkspaceManager,
        *,
        baseline_scan_id: str | None = None,
    ) -> None:
        self.workspace = workspace
        self.baseline_scan_id = (baseline_scan_id or "").strip() or None
        self._read_warnings: list[dict[str, str]] = []

    @staticmethod
    def _classify_findings(
        findings: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Return potential, human-review and false-positive lifecycle groups."""
        potential: list[dict[str, Any]] = []
        human_review: list[dict[str, Any]] = []
        false_positives: list[dict[str, Any]] = []
        for finding in findings:
            verdict = str(finding.get("verdict", Verdict.NEEDS_HUMAN_REVIEW.value)).upper()
            if verdict == Verdict.FALSE_POSITIVE.value:
                false_positives.append(finding)
            elif verdict == Verdict.LIKELY.value:
                potential.append(finding)
            elif verdict != Verdict.CONFIRMED.value:
                # Unknown/legacy verdicts remain visible for manual review.
                human_review.append(finding)
        return potential, human_review, false_positives

    def _read_optional_json(self, relative_path: str) -> dict[str, Any]:
        target = self.workspace.resolve_path(relative_path)
        if not target.exists() or target.stat().st_size == 0:
            return {}
        try:
            return self.workspace.read_json(relative_path)
        except Exception as exc:
            self._read_warnings.append({
                "artifact": relative_path,
                "warning": f"unreadable_json:{type(exc).__name__}",
            })
            return {}

    def _read_validated_json(
        self,
        producer_stage_id: str,
        relative_path: str,
        *,
        allowed_stage_ids: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        payload = load_validated_stage_artifact(
            self.workspace,
            producer_stage_id,
            relative_path,
            allowed_stage_ids=allowed_stage_ids,
        )
        if payload is not None:
            return payload
        try:
            artifact_path = self.workspace.resolve_path(relative_path)
            state = self.workspace.read_json("scan_state.json") if self.workspace.state_file.is_file() else {}
            producer_state = (state.get("stages") or {}).get(producer_stage_id, {})
            producer_status = producer_state.get("status") if isinstance(producer_state, dict) else ""
            if artifact_path.exists() or producer_status in {
                StageStatus.SUCCESS.value,
                StageStatus.PARTIAL.value,
            }:
                self._read_warnings.append({
                    "artifact": relative_path,
                    "warning": (
                        "artifact_provenance_validation_failed"
                        if artifact_path.exists()
                        else "expected_artifact_missing_for_completed_stage"
                    ),
                })
        except Exception as exc:
            self._read_warnings.append({
                "artifact": relative_path,
                "warning": f"artifact_validation_error:{type(exc).__name__}",
            })
        return {}

    @staticmethod
    def _severity_breakdown(findings: list[dict[str, Any]]) -> dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for item in findings:
            sev = str(item.get("severity", "INFO")).upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    @staticmethod
    def _is_config_observation(finding: dict[str, Any]) -> bool:
        category = str(finding.get("category", "")).lower()
        return category.startswith("missing_") or category.startswith("tls_") or category == "deprecated_tls_protocol"

    @staticmethod
    def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            findings,
            key=lambda f: (
                -SEVERITY_RANK.get(str(f.get("severity", "INFO")).upper(), 0),
                -float((f.get("metadata") or {}).get("severity_assessment", {}).get("risk_score", 0.0)),
                -float(f.get("confidence", 0.0)),
                str(f.get("category", "")),
                str(f.get("title", "")),
            ),
        )

    @staticmethod
    def _extract_inventory_sets(
        inventory_payload: dict[str, Any],
    ) -> tuple[set[str], set[tuple[str, str]], set[tuple[str, int]], set[tuple[str, str]]]:
        hosts: set[str] = set()
        endpoints: set[tuple[str, str]] = set()
        ports: set[tuple[str, int]] = set()
        techs: set[tuple[str, str]] = set()

        for asset in inventory_payload.get("assets") or []:
            if not isinstance(asset, dict):
                continue
            hostname = str(asset.get("hostname") or "").strip().lower()
            if not hostname:
                continue
            hosts.add(hostname)
            for p in asset.get("ports") or []:
                try:
                    ports.add((hostname, int(p)))
                except (TypeError, ValueError):
                    continue
            for t in asset.get("technologies") or []:
                tech_str = str(t).strip()
                if tech_str:
                    techs.add((hostname, tech_str))

        for ep in inventory_payload.get("endpoints") or []:
            if not isinstance(ep, dict) or ep.get("excluded"):
                continue
            method = str(ep.get("method") or "GET").upper()
            url = str(ep.get("canonical_url") or ep.get("url") or "").strip()
            if url:
                endpoints.add((method, url))

        return hosts, endpoints, ports, techs

    @staticmethod
    def _finding_signature(finding: dict[str, Any]) -> tuple[str, str, str]:
        meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        dedup_key = str(meta.get("dedup_key") or "").strip()
        if dedup_key:
            return ("dedup", dedup_key, str(finding.get("category") or ""))
        return (
            str(finding.get("category") or ""),
            str(finding.get("asset_id") or ""),
            str(finding.get("title") or ""),
        )

    def _compute_baseline_diff(
        self,
        *,
        baseline_id: str | None,
        current_inventory: dict[str, Any],
        current_findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if not baseline_id:
            return {"baseline_available": False, "baseline_scan_id": None}

        try:
            baseline_ws = WorkspaceManager(
                project_root=self.workspace.project_root,
                output_root_name=self.workspace.output_root.name,
            )
            baseline_ws.load_scan(baseline_id)
        except Exception as exc:
            return {
                "baseline_available": False,
                "baseline_scan_id": baseline_id,
                "error": f"Baseline scan unreadable: {type(exc).__name__}",
            }

        base_inv_path = baseline_ws.resolve_path("inventory/unified_endpoints.json")
        base_inventory = (
            baseline_ws.read_json("inventory/unified_endpoints.json")
            if base_inv_path.is_file() and base_inv_path.stat().st_size > 0
            else {}
        )

        base_findings_list: list[dict[str, Any]] = []
        base_verified_path = baseline_ws.resolve_path("verification/verified_findings.json")
        if base_verified_path.is_file() and base_verified_path.stat().st_size > 0:
            base_verified = baseline_ws.read_json("verification/verified_findings.json")
            base_findings_list = [
                f for f in (base_verified.get("findings") or []) if isinstance(f, dict)
            ]

        cur_hosts, cur_eps, cur_ports, cur_techs = self._extract_inventory_sets(current_inventory)
        base_hosts, base_eps, base_ports, base_techs = self._extract_inventory_sets(base_inventory)

        new_hosts = sorted(cur_hosts - base_hosts)
        removed_hosts = sorted(base_hosts - cur_hosts)
        new_endpoints = [
            {"method": method, "url": url}
            for method, url in sorted(cur_eps - base_eps)[:500]
        ]
        new_open_ports = [
            {"hostname": host, "port": port}
            for host, port in sorted(cur_ports - base_ports)[:200]
        ]
        new_technologies = [
            {"hostname": host, "technology": tech}
            for host, tech in sorted(cur_techs - base_techs)[:200]
        ]

        base_sigs = {self._finding_signature(f) for f in base_findings_list}
        cur_sigs = {self._finding_signature(f) for f in current_findings}
        new_findings = [
            {
                "finding_id": f.get("finding_id", ""),
                "title": f.get("title", ""),
                "category": f.get("category", ""),
                "severity": f.get("severity", "INFO"),
                "verdict": f.get("verdict", ""),
                "asset_id": f.get("asset_id", ""),
            }
            for f in current_findings
            if self._finding_signature(f) not in base_sigs
        ]
        resolved_count = len(base_sigs - cur_sigs)

        return {
            "baseline_available": True,
            "baseline_scan_id": baseline_id,
            "summary": {
                "new_hosts_count": len(new_hosts),
                "removed_hosts_count": len(removed_hosts),
                "new_endpoints_count": len(cur_eps - base_eps),
                "new_open_ports_count": len(cur_ports - base_ports),
                "new_technologies_count": len(cur_techs - base_techs),
                "new_findings_count": len(new_findings),
                "resolved_findings_count": resolved_count,
            },
            "new_hosts": new_hosts[:250],
            "removed_hosts": removed_hosts[:250],
            "new_endpoints": new_endpoints,
            "new_open_ports": new_open_ports,
            "new_technologies": new_technologies,
            "new_findings": new_findings[:250],
        }

    def build(self, *, stage_id: str = "consolidated_reporting") -> dict[str, Any]:
        self._read_warnings = []
        scan_state = self._read_optional_json("scan_state.json")
        scope_snapshot = self._read_optional_json("scope_snapshot.json")
        coverage_summary = self._read_optional_json("coverage_summary.json")
        config_snapshot = self._read_optional_json("meta/config_snapshot.json")
        environment_snapshot = self._read_optional_json("meta/environment_snapshot.json")
        inventory = self._read_validated_json(
            "redirect_analysis",
            "inventory/unified_endpoints.json",
            allowed_stage_ids=("domain_enumeration", "browser_capture", "directory_discovery", "http_probing", "redirect_analysis", "api_js_intelligence"),
        )
        auth_sessions = self._read_validated_json(
            "auth_session_lifecycle", "analysis/auth_sessions.json"
        )
        tls_posture = self._read_validated_json(
            "online_security_checks", "analysis/tls_posture.json"
        )
        dns_infra = self._read_validated_json(
            "server_dns_checks", "analysis/dns_infrastructure.json"
        )
        verified_art = self._read_validated_json(
            "evidence_verification", "verification/verified_findings.json"
        )

        all_findings: list[dict[str, Any]] = [
            f for f in (verified_art.get("findings") or []) if isinstance(f, dict)
        ]
        evidence_by_id: dict[str, dict[str, Any]] = {}
        for ev in verified_art.get("evidence_records") or []:
            if isinstance(ev, dict) and ev.get("evidence_id"):
                ev_copy = dict(ev)
                rel_art = str(ev_copy.get("artifact_path", ""))
                if rel_art:
                    try:
                        art_path = self.workspace.resolve_path(rel_art)
                        ev_copy["artifact_exists"] = art_path.is_file()
                        if art_path.is_file():
                            observed_sha = self.workspace.file_sha256(rel_art)
                            artifact_payload = self.workspace.read_json(rel_art)
                            digest_matches = observed_sha == str(ev_copy.get("sha256", ""))
                            scan_matches = artifact_payload.get("scan_id") == self.workspace.scan_id
                            evidence_id = str(ev_copy.get("evidence_id", ""))
                            evidence_id_matches = (
                                not evidence_id
                                or not artifact_payload.get("evidence_id")
                                or artifact_payload.get("evidence_id") == evidence_id
                            )
                            ev_copy["verified_sha256"] = observed_sha
                            ev_copy["integrity_verified"] = bool(
                                digest_matches and scan_matches and evidence_id_matches
                            )
                            ev_copy["integrity_reason"] = (
                                "verified"
                                if ev_copy["integrity_verified"]
                                else "digest_or_envelope_mismatch"
                            )
                        else:
                            ev_copy["integrity_verified"] = False
                            ev_copy["integrity_reason"] = "artifact_missing"
                    except Exception:
                        ev_copy["artifact_exists"] = False
                        ev_copy["integrity_verified"] = False
                        ev_copy["integrity_reason"] = "artifact_unreadable"
                evidence_by_id[str(ev_copy["evidence_id"])] = ev_copy

        confirmed: list[dict[str, Any]] = []
        enriched_findings: list[dict[str, Any]] = []
        for finding in all_findings:
            enriched = dict(finding)
            attached_evidence = [
                evidence_by_id[eid]
                for eid in (enriched.get("evidence_ids") or [])
                if eid in evidence_by_id
            ]
            enriched["resolved_evidence"] = attached_evidence
            metadata = enriched.get("metadata") if isinstance(enriched.get("metadata"), dict) else {}
            enriched["risk_assessment"] = metadata.get("severity_assessment", {})
            enriched["cvss_assessment"] = (
                metadata.get("cvss_assessment")
                or metadata.get("cvss")
                or (enriched["risk_assessment"].get("cvss") if isinstance(enriched["risk_assessment"], dict) else None)
            )
            enriched["severity_rationale"] = (
                metadata.get("severity_rationale")
                or (enriched["risk_assessment"].get("rationale") if isinstance(enriched["risk_assessment"], dict) else None)
            )
            enriched["reproduction_steps"] = (
                metadata.get("reproduction_steps")
                or metadata.get("reproduction")
                or []
            )

            enriched_findings.append(enriched)
            verdict_str = str(enriched.get("verdict", Verdict.NEEDS_HUMAN_REVIEW.value)).upper()
            if verdict_str == Verdict.CONFIRMED.value:
                confirmed.append(enriched)

        potential_findings, needs_human_review, false_positives = self._classify_findings(enriched_findings)
        confirmed = self._sort_findings(confirmed)
        potential_findings = self._sort_findings(potential_findings)
        needs_human_review = self._sort_findings(needs_human_review)
        review_queue = self._sort_findings(potential_findings + needs_human_review)
        confirmed_config = [f for f in confirmed if self._is_config_observation(f)]
        confirmed_vulns = [f for f in confirmed if not self._is_config_observation(f)]
        review_queue = self._sort_findings(review_queue)
        false_positives = self._sort_findings(false_positives)

        resolved_baseline_id = (
            self.baseline_scan_id
            or str(scan_state.get("baseline_scan_id") or "").strip()
            or str(config_snapshot.get("baseline_scan_id") or "").strip()
            or None
        )
        baseline_diff = self._compute_baseline_diff(
            baseline_id=resolved_baseline_id,
            current_inventory=inventory,
            current_findings=enriched_findings,
        )

        stages_state = {
            key: (dict(value) if isinstance(value, dict) else value)
            for key, value in (scan_state.get("stages") or {}).items()
        }
        own_state = stages_state.get(stage_id)
        if isinstance(own_state, dict) and own_state.get("status") in {
            StageStatus.RUNNING.value,
            StageStatus.PENDING.value,
        }:
            own_state["status"] = StageStatus.SUCCESS.value
        final_overall = (
            compute_overall_status(
                entry.get("status", StageStatus.PENDING.value)
                for entry in stages_state.values()
                if isinstance(entry, dict)
            ).value
            if stages_state
            else scan_state.get("overall_status", "UNKNOWN")
        )
        stage_execution_table: list[dict[str, Any]] = []
        for s_id, s_info in stages_state.items():
            if not isinstance(s_info, dict):
                continue
            cov_info = (coverage_summary.get("stages") or {}).get(s_id, {})
            stage_execution_table.append(
                {
                    "stage_id": s_id,
                    "status": s_info.get("status", "UNKNOWN"),
                    "summary": s_info.get("summary", ""),
                    "error": s_info.get("error", ""),
                    "targets_total": cov_info.get("targets_total", 0),
                    "targets_tested": cov_info.get("targets_tested", 0),
                    "targets_skipped": cov_info.get("targets_skipped", 0),
                }
            )

        inv_summary = inventory.get("summary") or {}
        coverage_ledger: list[dict[str, Any]] = []
        for row in stage_execution_table:
            if row["status"] != StageStatus.SUCCESS.value:
                coverage_ledger.append({
                    "kind": "stage_incomplete",
                    "stage_id": row["stage_id"],
                    "status": row["status"],
                    "reason": row["error"] or row["summary"] or "Stage did not complete successfully",
                })
        for skipped in coverage_summary.get("skipped_checks") or []:
            if isinstance(skipped, dict):
                coverage_ledger.append({
                    "kind": "check_skipped",
                    "stage_id": skipped.get("stage_id", ""),
                    "check_name": skipped.get("check_name", ""),
                    "reason": skipped.get("reason", "No reason recorded"),
                })
        unprobed = int(inv_summary.get("unprobed_endpoints", 0) or 0)
        if unprobed:
            coverage_ledger.append({
                "kind": "endpoints_unprobed",
                "count": unprobed,
                "reason": "Endpoints exist in inventory but have no completed probe result",
            })
        tool_versions = environment_snapshot.get("tools") or {}
        report_environment = {
            "schema_version": environment_snapshot.get("schema_version", ""),
            "python": environment_snapshot.get("python", ""),
            "implementation": environment_snapshot.get("implementation", ""),
            "platform": environment_snapshot.get("platform", ""),
            "packages": environment_snapshot.get("packages", {}),
            "installed_packages": environment_snapshot.get("installed_packages", {}),
            "tools": {
                name: {
                    "version": info.get("version", "unknown"),
                    "binary_found_on_path": bool(info.get("path")),
                }
                for name, info in tool_versions.items()
                if isinstance(info, dict)
            },
            "nuclei_templates": {
                "file_count": (environment_snapshot.get("nuclei_templates") or {}).get("file_count", 0),
                "content_sha256": (environment_snapshot.get("nuclei_templates") or {}).get("content_sha256", "absent"),
                "complete": (environment_snapshot.get("nuclei_templates") or {}).get("complete", False),
            },
            "settings_sha256": environment_snapshot.get("settings_sha256", ""),
        }
        for tool_name, tool_info in tool_versions.items():
            if isinstance(tool_info, dict) and (
                not tool_info.get("path") or str(tool_info.get("version", "")).startswith("not-installed")
            ):
                coverage_ledger.append({
                    "kind": "tool_unavailable",
                    "tool": tool_name,
                    "reason": tool_info.get("version", "not-installed"),
                })

        report: dict[str, Any] = {
            "schema_version": "1.0",
            "scan_id": self.workspace.scan_id,
            "stage_id": stage_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": scan_state.get("target", ""),
            "overall_pipeline_status": final_overall,
            "configuration": {
                "schema_version": config_snapshot.get("schema_version", ""),
                "config_hash": config_snapshot.get("config_hash", ""),
                "scope_fingerprint": config_snapshot.get("scope_fingerprint", ""),
                "snapshot_available": bool(config_snapshot),
            },
            "environment": report_environment,
            "report_warnings": list(self._read_warnings),
            "scope": {
                "allowed_domains": scope_snapshot.get("allowed_domains", []),
                "include_subdomains": scope_snapshot.get("include_subdomains", True),
                "allowed_ports": scope_snapshot.get("allowed_ports", []),
                "excluded_paths": scope_snapshot.get("excluded_paths", []),
                "fingerprint": scope_snapshot.get("fingerprint", ""),
                "out_of_scope_blocks_count": len(coverage_summary.get("out_of_scope_blocks") or []),
            },
            "coverage": {
                "total_assets": inv_summary.get("total_assets", 0),
                "total_endpoints": inv_summary.get("total_endpoints", 0),
                "unique_urls": inv_summary.get("unique_urls", 0),
                "unprobed_endpoints": inv_summary.get("unprobed_endpoints", 0),
                "reachable_endpoints": inv_summary.get("reachable_endpoints", 0),
                "authenticated_endpoints": inv_summary.get("authenticated_endpoints", 0),
                "identities_evaluated": auth_sessions.get("total_identities", 0),
                "authenticated_identities": auth_sessions.get("authenticated_identities", 0),
                "request_failures_count": len(coverage_summary.get("request_failures") or []),
                "skipped_checks": coverage_summary.get("skipped_checks") or [],
                "stages": stage_execution_table,
            },
            "summary": {
                "confirmed_count": len(confirmed),
                "confirmed_vulnerability_count": len(confirmed_vulns),
                "confirmed_configuration_count": len(confirmed_config),
                "confirmed_by_severity": self._severity_breakdown(confirmed),
                "potential_findings_count": len(potential_findings),
                "potential_findings_by_severity": self._severity_breakdown(potential_findings),
                "needs_human_review_count": len(needs_human_review),
                "needs_human_review_by_severity": self._severity_breakdown(needs_human_review),
                "review_queue_count": len(review_queue),
                "review_queue_by_severity": self._severity_breakdown(review_queue),
                "suppressed_false_positives_count": len(false_positives),
                "evidence_records_count": len(evidence_by_id),
                "evidence_verified_count": sum(
                    1 for item in evidence_by_id.values()
                    if item.get("integrity_verified") is True
                ),
                "evidence_invalid_count": sum(
                    1 for item in evidence_by_id.values()
                    if item.get("integrity_verified") is not True
                ),
                "evidence_store": (verified_art.get("summary") or {}).get("evidence_store", {}),
                "ai_triage": (verified_art.get("summary") or {}).get("ai_triage", {"executed": False}),
            },
            "baseline_diff": baseline_diff,
            "confirmed_findings": confirmed,
            "confirmed_vulnerabilities": confirmed_vulns,
            "confirmed_configuration_issues": confirmed_config,
            "potential_findings": potential_findings,
            "needs_human_review": needs_human_review,
            "review_queue": review_queue,
            "suppressed_false_positives": false_positives,
            "coverage_ledger": coverage_ledger,
            "incomplete_coverage": [
                {"stage_id": row["stage_id"], "status": row["status"], "reason": row["error"] or row["summary"]}
                for row in stage_execution_table
                if row["status"] not in {"SUCCESS"}
            ],
            "posture_snapshots": {
                "tls_endpoints_checked": len(tls_posture.get("results") or []),
                "dns_assets_checked": len(dns_infra.get("records") or []),
            },
        }
        return report