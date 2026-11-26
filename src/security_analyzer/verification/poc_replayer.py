from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import re
from typing import Any

import requests

from security_analyzer.authentication.auth_manager import AuthManager
from security_analyzer.core.coverage_tracker import CoverageTracker
from security_analyzer.core.exceptions import ScopeViolationError
from security_analyzer.core.scope_engine import ScopeEngine
from security_analyzer.core.resource_governor import ResourceGovernor
from security_analyzer.core.workspace import WorkspaceManager
from security_analyzer.deep_checks.response_diff import (
    ResponseFingerprint,
    is_substantive_success,
    json_shape_similarity,
)
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.models.evidence import EvidenceRecord
from security_analyzer.verification.evidence_store import sanitize_evidence_value
from security_analyzer.models.finding import FindingRecord, Verdict
from security_analyzer.utils.request_safety import DESTRUCTIVE_PATH_RE


POSTURE_CATEGORIES = {
    "deprecated_tls_protocol", "tls_legacy_protocol", "tls_certificate_validation_error",
    "tls_certificate_invalid", "tls_certificate_expired", "tls_certificate_expiring_soon",
    "missing_strict_transport_security", "missing_content_security_policy",
    "missing_x_content_type_options", "missing_referrer_policy",
    "missing_clickjacking_protection", "missing_rate_limit_headers",
}


@dataclass
class ReplayOutcome:
    finding_id: str
    replayed: bool
    verdict: Verdict
    reproducible: bool
    identity_contrast_verified: bool
    reason: str
    evidence_record: EvidenceRecord | None = None
    telemetry: dict[str, Any] = field(default_factory=dict)
    evidence_integrity: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        if self.evidence_record is not None:
            data["evidence_record"] = self.evidence_record.to_dict()
        return data


class DeterministicPocReplayer:
    """Re-executes safe, read-only verification probes and writes cryptographic EvidenceRecords."""

    def __init__(
        self,
        *,
        workspace: WorkspaceManager,
        scope_engine: ScopeEngine,
        coverage: CoverageTracker,
        inventory: UnifiedEndpointInventory,
        auth_manager: AuthManager | None,
        connect_timeout: float = 10.0,
        read_timeout: float = 20.0,
        resource_governor: ResourceGovernor | None = None,
    ) -> None:
        self.workspace = workspace
        self.scope_engine = scope_engine
        self.coverage = coverage
        self.inventory = inventory
        self.auth_manager = auth_manager
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.resource_governor = resource_governor
        self._endpoint_url_by_id = {ep.endpoint_id: ep.url for ep in inventory.all_endpoints()}

    def _client_for_identity(self, identity_id: str):
        if self.auth_manager is not None:
            try:
                ident_ctx = self.auth_manager.get_context(identity_id)
                return ident_ctx.create_http_client(
                    self.scope_engine,
                    coverage=self.coverage,
                    connect_timeout=self.connect_timeout,
                    read_timeout=self.read_timeout,
                    max_redirects=0,
                    governor=self.resource_governor,
                )
            except Exception:
                pass
        from security_analyzer.utils.http_client import ScopedHttpClient

        return ScopedHttpClient(
            self.scope_engine,
            coverage=self.coverage,
            connect_timeout=self.connect_timeout,
            read_timeout=self.read_timeout,
            max_redirects=0,
            governor=self.resource_governor,
        )

    def _resolve_target_url(self, finding: FindingRecord) -> str:
        meta = finding.metadata
        for key in ("mutated_url", "tested_url", "matched_at", "target_url", "url"):
            val = str(meta.get(key, "")).strip()
            if val.startswith(("http://", "https://")):
                return val
        return self._endpoint_url_by_id.get(finding.endpoint_id, "")

    def _persist_evidence(
        self,
        finding: FindingRecord,
        evidence_type: str,
        summary: str,
        telemetry: dict[str, Any],
    ) -> EvidenceRecord:
        rel_path = f"verification/evidence/{finding.finding_id}.json"
        ev = EvidenceRecord(
            artifact_path=rel_path,
            evidence_type=evidence_type,
            summary=str(sanitize_evidence_value(summary))[:1000],
            metadata={
                "finding_id": finding.finding_id,
                "category": finding.category,
            },
        )
        payload = {
            "schema_version": "1.1",
            "scan_id": self.workspace.scan_id,
            "finding_id": finding.finding_id,
            "evidence_id": ev.evidence_id,
            "category": finding.category,
            "evidence_type": evidence_type,
            "recorded_at": ev.created_at,
            "summary": ev.summary,
            "telemetry": sanitize_evidence_value(telemetry),
        }
        self.workspace.write_json_atomic(rel_path, payload)
        ev.sha256 = self.workspace.file_sha256(rel_path)
        if ev.evidence_id not in finding.evidence_ids:
            finding.evidence_ids.append(ev.evidence_id)
        return ev

    def verify_finding(self, finding: FindingRecord, *, stage_id: str = "evidence_verification") -> ReplayOutcome:
        cat = finding.category.lower()
        target_url = self._resolve_target_url(finding)

        if target_url:
            decision = self.scope_engine.evaluate_url(target_url, check_dns=True)
            if not decision.allowed:
                self.coverage.record_out_of_scope(
                    stage_id, target_url, decision.reason
                )
                return ReplayOutcome(
                    finding_id=finding.finding_id,
                    replayed=False,
                    verdict=Verdict.INCONCLUSIVE,
                    reproducible=False,
                    identity_contrast_verified=False,
                    reason="Replay target failed DNS-validated scope verification",
                )
            target_url = decision.normalized_url

        # Guardrail: Never replay state-mutating or logout paths
        if target_url and DESTRUCTIVE_PATH_RE.search(target_url):
            ev = self._persist_evidence(
                finding,
                "safety_blocked_replay",
                "Replay skipped because target path matches destructive/logout safety filter",
                {"target_url": target_url},
            )
            return ReplayOutcome(
                finding_id=finding.finding_id,
                replayed=False,
                verdict=Verdict.NEEDS_HUMAN_REVIEW,
                reproducible=False,
                identity_contrast_verified=False,
                reason="Blocked destructive/logout path from automated replay",
                evidence_record=ev,
            )

        # 1. Horizontal IDOR / BOLA deterministic multi-identity replay
        if cat == "idor_bola":
            return self._replay_idor(finding, target_url, stage_id=stage_id)

        # 2. Missing Authentication Enforcement replay
        if cat == "broken_authentication_enforcement":
            return self._replay_broken_auth(finding, target_url, stage_id=stage_id)

        # 3. Header / Path Override Bypass replay
        if cat == "access_control_header_bypass":
            return self._replay_header_bypass(finding, target_url, stage_id=stage_id)

        # 4. CORS origin reflection replay
        if cat in {"cors_origin_reflection", "cors_wildcard_with_credentials"}:
            return self._replay_cors(finding, target_url, stage_id=stage_id)

        # 5. GraphQL introspection replay
        if cat == "graphql_introspection_enabled":
            return self._replay_graphql_introspection(finding, target_url, stage_id=stage_id)

        # Secret-like strings are leads only. Never use a candidate secret value.
        if cat == "hardcoded_secret_in_js":
            return self._replay_secret_indicator(finding, target_url, stage_id=stage_id)

        # 6. Exposed static artifact / OpenAPI spec / source map / Nuclei GET replay
        if cat in {"exposed_api_specification", "exposed_source_map"} or cat.startswith("nuclei:"):
            return self._replay_http_exposure(finding, target_url, stage_id=stage_id)

        # 7. Pagination / boundary 500 error replay
        if cat == "unhandled_boundary_exception":
            return self._replay_boundary_error(finding, target_url, stage_id=stage_id)

        # 8. Deterministic passive/posture findings (TLS, missing security headers) vs heuristic surfaces
        source_art = str(finding.metadata.get("source_artifact", ""))
        if cat in POSTURE_CATEGORIES:
            if finding.metadata.get("source_artifact_integrity") != "VERIFIED":
                ev = self._persist_evidence(
                    finding,
                    "unverified_posture_observation",
                    "Posture observation lacks verified producer-artifact provenance",
                    {"source_artifact": source_art, "target_url": target_url},
                )
                return ReplayOutcome(
                    finding.finding_id,
                    False,
                    Verdict.NEEDS_HUMAN_REVIEW,
                    False,
                    False,
                    "Posture observation cannot be confirmed without verified source-artifact provenance",
                    evidence_record=ev,
                )
            if cat == "missing_rate_limit_headers":
                ev = self._persist_evidence(
                    finding,
                    "passive_header_observation",
                    "Rate-limit header absence requires human/load validation",
                    {"source_artifact": source_art, "target_url": target_url},
                )
                return ReplayOutcome(
                    finding_id=finding.finding_id,
                    replayed=False,
                    verdict=Verdict.NEEDS_HUMAN_REVIEW,
                    reproducible=True,
                    identity_contrast_verified=False,
                    reason="Passive header absence recorded; requires controlled rate-limit test",
                    evidence_record=ev,
                )

            ev = self._persist_evidence(
                finding,
                "posture_artifact_verified",
                f"Verified deterministic posture finding from {source_art}",
                {"source_artifact": source_art, "target_url": target_url},
            )
            return ReplayOutcome(
                finding_id=finding.finding_id,
                replayed=False,
                verdict=Verdict.CONFIRMED,
                reproducible=True,
                identity_contrast_verified=False,
                reason="Confirmed configuration observation (deterministic header/protocol posture; not an exploit)",
                evidence_record=ev,
            )

        # Schema-only or workflow heuristics (mass_assignment_surface, workflow_step_bypass)
        ev = self._persist_evidence(
            finding,
            "heuristic_surface_evidence",
            "Heuristic/schema surface preserved for human review without mutating state",
            {"source_artifact": source_art, "target_url": target_url},
        )
        return ReplayOutcome(
            finding_id=finding.finding_id,
            replayed=False,
            verdict=Verdict.NEEDS_HUMAN_REVIEW,
            reproducible=False,
            identity_contrast_verified=False,
            reason="Non-destructive policy preserves schema/workflow finding for human review",
            evidence_record=ev,
        )

    def _replay_idor(self, finding: FindingRecord, mutated_url: str, *, stage_id: str) -> ReplayOutcome:
        meta = finding.metadata
        owner_id = str(meta.get("owner_identity", ""))
        attacker_id = str(meta.get("attacker_identity") or finding.identity_id)
        if not mutated_url or not owner_id or not attacker_id:
            return ReplayOutcome(finding.finding_id, False, Verdict.INCONCLUSIVE, False, False, "Missing IDOR replay metadata")

        owner_client = self._client_for_identity(owner_id)
        attacker_client = self._client_for_identity(attacker_id)
        anon_client = self._client_for_identity("anonymous")

        try:
            owner_resp = owner_client.get(mutated_url, stage_id=stage_id)
            att_resp = attacker_client.get(mutated_url, stage_id=stage_id)
            anon_resp = anon_client.get(mutated_url, stage_id=stage_id)
        except (ScopeViolationError, requests.RequestException) as exc:
            return ReplayOutcome(
                finding.finding_id,
                True,
                Verdict.INCONCLUSIVE,
                False,
                False,
                f"Replay request error: {type(exc).__name__}",
            )

        owner_fp = ResponseFingerprint.from_response(identity_id=owner_id, url=mutated_url, method="GET", response=owner_resp)
        att_fp = ResponseFingerprint.from_response(identity_id=attacker_id, url=mutated_url, method="GET", response=att_resp)
        anon_fp = ResponseFingerprint.from_response(identity_id="anonymous", url=mutated_url, method="GET", response=anon_resp)

        similarity = json_shape_similarity(owner_fp, att_fp)
        anon_blocked = anon_fp.status_code in {401, 403, 404} or anon_fp.looks_like_login_page
        telemetry = {
            "mutated_url": mutated_url,
            "owner": owner_fp.to_dict(),
            "attacker": att_fp.to_dict(),
            "anonymous": anon_fp.to_dict(),
            "json_shape_similarity": similarity,
            "anonymous_blocked": anon_blocked,
        }
        ev = self._persist_evidence(
            finding,
            "idor_differential_replay",
            f"IDOR replay on {mutated_url}: attacker={att_fp.status_code}, anon={anon_fp.status_code}, similarity={similarity}",
            telemetry,
        )

        # Server errors and throttling are not evidence that access control works.
        if any(fp.status_code in {429} or fp.status_code >= 500 for fp in (owner_fp, att_fp, anon_fp)):
            return ReplayOutcome(
                finding.finding_id,
                True,
                Verdict.INCONCLUSIVE,
                False,
                False,
                "IDOR replay encountered throttling or a server error; no security verdict assigned",
                evidence_record=ev,
                telemetry=telemetry,
            )

        owner_available = is_substantive_success(owner_fp)
        attacker_access = is_substantive_success(att_fp)
        confirmed = (
            owner_available
            and attacker_access
            and att_fp.is_json
            and similarity >= 0.80
            and owner_fp.normalized_body_sha256 == att_fp.normalized_body_sha256
            and anon_blocked
        )

        if confirmed:
            return ReplayOutcome(
                finding.finding_id,
                True,
                Verdict.CONFIRMED,
                True,
                True,
                f"Confirmed horizontal IDOR: {attacker_id!r} retrieved object with {similarity * 100:.0f}% structural match while anonymous was blocked ({anon_fp.status_code})",
                evidence_record=ev,
                telemetry=telemetry,
            )

        deterministic_denial = (
            owner_available
            and att_fp.status_code in {401, 403, 404}
            and anon_blocked
        )
        return ReplayOutcome(
            finding.finding_id,
            True,
            Verdict.FALSE_POSITIVE if deterministic_denial else Verdict.NEEDS_HUMAN_REVIEW,
            False,
            False,
            (
                f"Attacker identity was denied on replay (HTTP {att_fp.status_code})"
                if deterministic_denial
                else "Replay did not establish cross-identity access or a deterministic denial; human review required"
            ),
            evidence_record=ev,
            telemetry=telemetry,
        )

    def _replay_broken_auth(self, finding: FindingRecord, target_url: str, *, stage_id: str) -> ReplayOutcome:
        auth_id = str(finding.metadata.get("authenticated_identity", ""))
        if not target_url or not auth_id:
            return ReplayOutcome(finding.finding_id, False, Verdict.INCONCLUSIVE, False, False, "Missing auth replay metadata")

        anon_client = self._client_for_identity("anonymous")
        auth_client = self._client_for_identity(auth_id)

        try:
            anon_resp = anon_client.get(target_url, stage_id=stage_id)
            auth_resp = auth_client.get(target_url, stage_id=stage_id)
        except (ScopeViolationError, requests.RequestException) as exc:
            return ReplayOutcome(finding.finding_id, True, Verdict.INCONCLUSIVE, False, False, f"Replay error: {exc}")

        anon_fp = ResponseFingerprint.from_response(identity_id="anonymous", url=target_url, method="GET", response=anon_resp)
        auth_fp = ResponseFingerprint.from_response(identity_id=auth_id, url=target_url, method="GET", response=auth_resp)
        if any(fp.status_code == 429 or fp.status_code >= 500 for fp in (anon_fp, auth_fp)):
            return ReplayOutcome(
                finding.finding_id,
                True,
                Verdict.INCONCLUSIVE,
                False,
                False,
                "Authentication replay encountered throttling or a server error",
            )
        similarity = json_shape_similarity(anon_fp, auth_fp)
        confirmed = (
            is_substantive_success(anon_fp)
            and is_substantive_success(auth_fp)
            and similarity >= 0.85
            and anon_fp.normalized_body_sha256 == auth_fp.normalized_body_sha256
        )

        telemetry = {
            "url": target_url,
            "anonymous": anon_fp.to_dict(),
            "authenticated": auth_fp.to_dict(),
            "structural_similarity": similarity,
        }
        ev = self._persist_evidence(
            finding,
            "broken_auth_differential_replay",
            f"Broken auth replay on {target_url}: anon={anon_fp.status_code}, auth={auth_fp.status_code}, similarity={similarity}",
            telemetry,
        )

        verdict = Verdict.CONFIRMED if confirmed else Verdict.FALSE_POSITIVE
        reason = (
            f"Confirmed unauthenticated access to protected route ({similarity * 100:.0f}% parity with {auth_id!r})"
            if confirmed
            else f"Endpoint enforced authentication on replay (anon={anon_fp.status_code})"
        )
        return ReplayOutcome(finding.finding_id, True, verdict, confirmed, confirmed, reason, evidence_record=ev, telemetry=telemetry)

    def _replay_header_bypass(self, finding: FindingRecord, target_url: str, *, stage_id: str) -> ReplayOutcome:
        vector = str(finding.metadata.get("vector", ""))
        ep_url = self._endpoint_url_by_id.get(finding.endpoint_id) or target_url
        if not ep_url or not vector:
            return ReplayOutcome(finding.finding_id, False, Verdict.INCONCLUSIVE, False, False, "Missing header bypass metadata")

        from urllib.parse import urlsplit

        parsed = urlsplit(ep_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"

        if vector in {"X-Original-URL", "X-Rewrite-URL"}:
            probe_url = f"{origin}/"
            extra_headers = {vector: path}
        else:
            probe_url = ep_url
            extra_headers = {vector: "127.0.0.1"}

        anon_client = self._client_for_identity("anonymous")
        auth_id = str(finding.metadata.get("authenticated_identity", ""))
        if not auth_id:
            return ReplayOutcome(
                finding.finding_id,
                False,
                Verdict.INCONCLUSIVE,
                False,
                False,
                "Header-bypass replay requires a declared authenticated baseline identity",
            )
        try:
            direct_resp = anon_client.get(ep_url, stage_id=stage_id)
            bypass_resp = anon_client.get(probe_url, stage_id=stage_id, headers=extra_headers)
            auth_resp = self._client_for_identity(auth_id).get(ep_url, stage_id=stage_id) if auth_id else None
        except (ScopeViolationError, requests.RequestException) as exc:
            return ReplayOutcome(finding.finding_id, True, Verdict.INCONCLUSIVE, False, False, f"Replay error: {exc}")

        direct_fp = ResponseFingerprint.from_response(identity_id="anonymous", url=ep_url, method="GET", response=direct_resp)
        bypass_fp = ResponseFingerprint.from_response(identity_id="anonymous", url=probe_url, method="GET", response=bypass_resp)
        auth_fp = (
            ResponseFingerprint.from_response(identity_id=auth_id, url=ep_url, method="GET", response=auth_resp)
            if auth_resp is not None
            else None
        )
        confirmed = (
            direct_fp.status_code in {401, 403}
            and auth_fp is not None
            and is_substantive_success(bypass_fp)
            and bypass_fp.normalized_body_sha256 == auth_fp.normalized_body_sha256
        )

        telemetry = {
            "vector": vector,
            "direct": direct_fp.to_dict(),
            "bypass_probe": bypass_fp.to_dict(),
            "authenticated_baseline": auth_fp.to_dict() if auth_fp else None,
        }
        ev = self._persist_evidence(
            finding,
            "header_bypass_replay",
            f"Header bypass ({vector}) replay: direct={direct_fp.status_code}, probe={bypass_fp.status_code}",
            telemetry,
        )

        verdict = Verdict.CONFIRMED if confirmed else Verdict.FALSE_POSITIVE
        reason = (
            f"Confirmed {vector} bypass (direct={direct_fp.status_code} -> probe={bypass_fp.status_code})"
            if confirmed
            else f"Header bypass did not reproduce (direct={direct_fp.status_code}, probe={bypass_fp.status_code})"
        )
        return ReplayOutcome(finding.finding_id, True, verdict, confirmed, False, reason, evidence_record=ev, telemetry=telemetry)

    def _replay_cors(self, finding: FindingRecord, target_url: str, *, stage_id: str) -> ReplayOutcome:
        if not target_url:
            return ReplayOutcome(finding.finding_id, False, Verdict.INCONCLUSIVE, False, False, "Missing URL for CORS replay")

        client = self._client_for_identity("anonymous")
        probe_origin = "https://untrusted-origin.example"
        try:
            resp = client.get(target_url, stage_id=stage_id, headers={"Origin": probe_origin})
        except (ScopeViolationError, requests.RequestException) as exc:
            return ReplayOutcome(finding.finding_id, True, Verdict.INCONCLUSIVE, False, False, f"CORS replay error: {exc}")

        if resp.status_code == 429 or resp.status_code >= 500:
            return ReplayOutcome(
                finding.finding_id,
                True,
                Verdict.INCONCLUSIVE,
                False,
                False,
                f"CORS replay returned HTTP {resp.status_code}; no verdict assigned",
            )
        lower_hdrs = {k.lower(): v for k, v in resp.headers.items()}
        acao = lower_hdrs.get("access-control-allow-origin", "").strip()
        acac = lower_hdrs.get("access-control-allow-credentials", "").strip().lower()
        confirmed = (acao == probe_origin) or (acao == "*" and acac == "true")

        telemetry = {
            "url": target_url,
            "status_code": resp.status_code,
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
        }
        ev = self._persist_evidence(
            finding,
            "cors_replay",
            f"CORS replay on {target_url}: ACAO={acao!r}, ACAC={acac!r}",
            telemetry,
        )
        if confirmed:
            verdict = Verdict.NEEDS_HUMAN_REVIEW
            reason = (
                "Origin reflection reproduced, but Python replay cannot establish "
                "browser-enforced credential behavior or sensitive-response readability"
            )
            telemetry["requires_browser_validation"] = True
        else:
            verdict = Verdict.FALSE_POSITIVE
            reason = "CORS origin reflection did not reproduce"
        return ReplayOutcome(
            finding.finding_id, True, verdict, False, False,
            reason, evidence_record=ev, telemetry=telemetry
        )

    def _replay_graphql_introspection(self, finding: FindingRecord, target_url: str, *, stage_id: str) -> ReplayOutcome:
        if not target_url:
            return ReplayOutcome(finding.finding_id, False, Verdict.INCONCLUSIVE, False, False, "Missing GraphQL URL")

        client = self._client_for_identity("anonymous")
        try:
            resp = client.get(
                target_url,
                stage_id=stage_id,
                params={"query": "{__schema{queryType{name}}}"},
                headers={"Accept": "application/json"},
            )
            data = resp.json() if resp.status_code == 200 else {}
            if resp.status_code == 429 or resp.status_code >= 500:
                return ReplayOutcome(
                    finding.finding_id,
                    True,
                    Verdict.INCONCLUSIVE,
                    False,
                    False,
                    f"GraphQL replay returned HTTP {resp.status_code}; no verdict assigned",
                )
        except Exception as exc:
            return ReplayOutcome(
                finding.finding_id,
                True,
                Verdict.INCONCLUSIVE,
                False,
                False,
                f"GraphQL replay error: {type(exc).__name__}",
            )

        confirmed = isinstance(data, dict) and isinstance((data.get("data") or {}).get("__schema"), dict)
        telemetry = {"url": target_url, "status_code": resp.status_code, "schema_returned": confirmed}
        ev = self._persist_evidence(
            finding,
            "graphql_introspection_replay",
            f"GraphQL introspection replay on {target_url}: schema_returned={confirmed}",
            telemetry,
        )
        verdict = Verdict.CONFIRMED if confirmed else Verdict.FALSE_POSITIVE
        reason = "Confirmed GraphQL introspection enabled on replay" if confirmed else "GraphQL introspection blocked on replay"
        return ReplayOutcome(finding.finding_id, True, verdict, confirmed, False, reason, evidence_record=ev, telemetry=telemetry)

    def _replay_secret_indicator(self, finding: FindingRecord, target_url: str, *, stage_id: str) -> ReplayOutcome:
        """A secret-like pattern in a public file is a lead; its validity is never tested."""
        if not target_url:
            return ReplayOutcome(finding.finding_id, False, Verdict.INCONCLUSIVE, False, False, "Missing URL for secret indicator replay")
        client = self._client_for_identity(finding.identity_id)
        try:
            resp = client.get(target_url, stage_id=stage_id)
        except (ScopeViolationError, requests.RequestException) as exc:
            return ReplayOutcome(finding.finding_id, True, Verdict.INCONCLUSIVE, False, False, f"Replay error: {type(exc).__name__}")
        fp = ResponseFingerprint.from_response(identity_id=finding.identity_id, url=target_url, method="GET", response=resp)
        ev = self._persist_evidence(
            finding,
            "secret_indicator_replay",
            f"File still served: status={fp.status_code}, bytes={fp.content_length}. The secret value was not used or tested.",
            {"url": target_url, "response": fp.to_dict()},
        )
        if fp.status_code in {401, 403, 404, 410}:
            verdict, reason = Verdict.FALSE_POSITIVE, f"File no longer accessible (HTTP {fp.status_code})"
        elif is_substantive_success(fp):
            verdict = Verdict.NEEDS_HUMAN_REVIEW
            reason = "File is publicly served, but secret validity is not established; a human must classify the secret (it is never used automatically)"
        else:
            verdict, reason = Verdict.INCONCLUSIVE, f"Replay returned HTTP {fp.status_code}"
        return ReplayOutcome(finding.finding_id, True, verdict, False, False, reason, evidence_record=ev, telemetry={"url": target_url})

    def _replay_http_exposure(self, finding: FindingRecord, target_url: str, *, stage_id: str) -> ReplayOutcome:
        if not target_url:
            return ReplayOutcome(finding.finding_id, False, Verdict.INCONCLUSIVE, False, False, "Missing URL for exposure replay")

        client = self._client_for_identity(finding.identity_id)
        try:
            resp = client.get(target_url, stage_id=stage_id)
        except (ScopeViolationError, requests.RequestException) as exc:
            return ReplayOutcome(finding.finding_id, True, Verdict.INCONCLUSIVE, False, False, f"Exposure replay error: {type(exc).__name__}")

        fp = ResponseFingerprint.from_response(identity_id=finding.identity_id, url=target_url, method="GET", response=resp)
        body = bytes(getattr(resp, "content", b"") or b"")[:2 * 1024 * 1024]
        content_type = str(getattr(resp, "headers", {}).get("Content-Type", "")).lower()
        body_text = body.decode("utf-8", errors="replace")
        category = finding.category.lower()
        validated_exposure = False
        validation_detail = "response did not match a recognized exposed-artifact contract"

        if category == "exposed_source_map":
            try:
                source_map = json.loads(body_text)
                embedded = source_map.get("sourcesContent") if isinstance(source_map, dict) else None
                validated_exposure = (
                    isinstance(source_map, dict)
                    and isinstance(embedded, list)
                    and any(isinstance(item, str) and item.strip() for item in embedded)
                )
                validation_detail = (
                    "valid source map contains embedded source content"
                    if validated_exposure
                    else "source map did not contain embedded source content"
                )
            except (ValueError, TypeError):
                validation_detail = "response was not valid source-map JSON"
        elif category == "exposed_api_specification":
            try:
                spec = json.loads(body_text)
                validated_exposure = (
                    isinstance(spec, dict)
                    and (isinstance(spec.get("openapi"), str) or isinstance(spec.get("swagger"), str))
                )
            except (ValueError, TypeError):
                validated_exposure = bool(
                    re.search(r"(?im)^\\s*(?:openapi|swagger)\\s*:\\s*['\\\"]?\\d", body_text)
                )
            validation_detail = (
                "response contains an OpenAPI/Swagger specification marker"
                if validated_exposure
                else "response did not contain an OpenAPI/Swagger specification marker"
            )

        telemetry = {
            "url": target_url,
            "response": fp.to_dict(),
            "content_type": content_type[:160],
            "body_bytes_examined": len(body),
            "artifact_contract": category,
            "artifact_contract_valid": validated_exposure,
            "validation_detail": validation_detail,
        }
        ev = self._persist_evidence(
            finding,
            "http_exposure_replay",
            f"HTTP GET replay on {target_url}: status={fp.status_code}, bytes={fp.content_length}; {validation_detail}",
            telemetry,
        )

        if fp.status_code == 429 or fp.status_code >= 500:
            verdict = Verdict.INCONCLUSIVE
            reason = f"Replay returned HTTP {fp.status_code}; availability/throttling prevents a security verdict"
            reproducible = False
        elif fp.status_code in {401, 403, 404, 410}:
            verdict = Verdict.FALSE_POSITIVE
            reason = f"Resource was not accessible on replay (HTTP {fp.status_code})"
            reproducible = False
        elif fp.status_code in {200, 206} and validated_exposure:
            verdict = Verdict.CONFIRMED
            reason = f"Confirmed exposed {category} content ({validation_detail})"
            reproducible = True
        elif category in {"exposed_api_specification", "exposed_source_map"}:
            verdict = Verdict.FALSE_POSITIVE
            reason = f"HTTP resource was reachable but did not satisfy the {category} content contract"
            reproducible = False
        else:
            verdict = Verdict.NEEDS_HUMAN_REVIEW
            reason = "Generic scanner match cannot be confirmed by an HTTP status alone"
            reproducible = False

        return ReplayOutcome(
            finding.finding_id,
            True,
            verdict,
            reproducible,
            False,
            reason,
            evidence_record=ev,
            telemetry=telemetry,
        )

    def _replay_boundary_error(self, finding: FindingRecord, target_url: str, *, stage_id: str) -> ReplayOutcome:
        if not target_url:
            return ReplayOutcome(finding.finding_id, False, Verdict.INCONCLUSIVE, False, False, "Missing URL for boundary replay")

        client = self._client_for_identity(finding.identity_id)
        try:
            first = client.get(target_url, stage_id=stage_id)
            second = client.get(target_url, stage_id=stage_id)
        except (ScopeViolationError, requests.RequestException) as exc:
            return ReplayOutcome(
                finding.finding_id,
                True,
                Verdict.INCONCLUSIVE,
                False,
                False,
                f"Boundary replay error: {type(exc).__name__}",
            )

        first_fp = ResponseFingerprint.from_response(
            identity_id=finding.identity_id,
            url=target_url,
            method="GET",
            response=first,
        )
        second_fp = ResponseFingerprint.from_response(
            identity_id=finding.identity_id,
            url=target_url,
            method="GET",
            response=second,
        )
        reproducible = (
            first_fp.status_code >= 500
            and second_fp.status_code >= 500
            and first_fp.status_code == second_fp.status_code
        )
        telemetry = {
            "url": target_url,
            "attempts": [first_fp.to_dict(), second_fp.to_dict()],
        }
        ev = self._persist_evidence(
            finding,
            "boundary_error_replay",
            f"Boundary replay statuses: {first_fp.status_code}, {second_fp.status_code}",
            telemetry,
        )

        if reproducible:
            verdict = Verdict.NEEDS_HUMAN_REVIEW
            reason = (
                f"Repeated HTTP {first_fp.status_code} boundary error observed; "
                "causal security impact is not established by status repetition alone"
            )
        elif first_fp.status_code == 429 or second_fp.status_code == 429 or first_fp.status_code >= 500 or second_fp.status_code >= 500:
            verdict = Verdict.INCONCLUSIVE
            reason = "Boundary error was not stable across two attempts; human review required"
        else:
            verdict = Verdict.FALSE_POSITIVE
            reason = f"Boundary error did not recur (HTTP {first_fp.status_code}, {second_fp.status_code})"

        return ReplayOutcome(
            finding.finding_id,
            True,
            verdict,
            reproducible,
            False,
            reason,
            evidence_record=ev,
            telemetry=telemetry,
        )
