from __future__ import annotations

import hashlib
import math
import re
from typing import Any
from urllib.parse import urlsplit

from security_analyzer.core.stage_registry import load_validated_stage_artifact
from security_analyzer.core.workspace import WorkspaceManager
from security_analyzer.models.asset import make_asset_id
from security_analyzer.models.finding import FindingRecord, Severity, Verdict



ANALYSIS_ARTIFACT_PRODUCERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "analysis/authorization_matrix.json": ("authorization_idor", ()),
    "analysis/business_logic.json": ("business_logic_checks", ()),
    "analysis/nuclei_findings.json": ("nuclei_assessment", ()),
    "analysis/security_headers.json": ("security_review", ()),
    "analysis/tls_posture.json": ("online_security_checks", ()),
    "analysis/dns_infrastructure.json": ("server_dns_checks", ()),
    "analysis/api_catalog.json": ("api_js_intelligence", ()),
    "analysis/javascript_intel.json": ("api_js_intelligence", ()),
}

SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL.value: 5,
    Severity.HIGH.value: 4,
    Severity.MEDIUM.value: 3,
    Severity.LOW.value: 2,
    Severity.INFO.value: 1,
}

_JS_REMEDIATION = {
    "hardcoded_secret_in_js": (
        "Treat the value as exposed: have the owner confirm whether it is real, rotate it if it is, "
        "and move secrets out of client-side code into server-side configuration or a secrets manager."
    ),
    "exposed_source_map": "Do not publish source maps in production, or restrict them to authenticated developers.",
    "exposed_api_specification": "Restrict internal API specifications to authenticated users or remove them from production.",
}


def _parse_severity(raw: str) -> Severity:
    try:
        return Severity(raw.strip().upper())
    except ValueError:
        return Severity.INFO


def _parse_verdict(raw: str) -> Verdict:
    try:
        return Verdict(raw.strip().upper())
    except ValueError:
        return Verdict.LIKELY


def _parse_confidence(raw: Any, default: float = 0.6) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        return default
    if not math.isfinite(value):
        return default
    return max(0.0, min(1.0, value))


def _canonical_location_key(url_or_host: str) -> str:
    raw = str(url_or_host or "").strip()
    if "://" not in raw:
        return raw.lower().rstrip("/")
    try:
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        path = (parsed.path or "/").rstrip("/") or "/"
        return f"{parsed.scheme.lower()}://{host}:{port}{path}"
    except ValueError:
        return raw[:512].lower()


def _safe_finding_id(raw_id: Any, *, source: str, fallback_material: str) -> str:
    candidate = str(raw_id or "").strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", candidate):
        return candidate
    digest = hashlib.sha256(
        f"{source}|{candidate}|{fallback_material}".encode("utf-8", errors="replace")
    ).hexdigest()[:20]
    return f"find_{digest}"


class FindingDeduplicator:
    """Normalizes and deduplicates findings emitted across all analysis artifacts."""

    @staticmethod
    def _is_host_level(category: str) -> bool:
        cat = category.strip().lower()
        return cat.startswith("missing_") or cat.startswith("tls_") or cat == "deprecated_tls_protocol"

    @staticmethod
    def compute_dedup_key(
        *,
        category: str,
        target_location: str,
        vector_hint: str = "",
        identity_id: str = "anonymous",
    ) -> str:
        location = _canonical_location_key(target_location)
        if FindingDeduplicator._is_host_level(category) and "://" in location:
            parsed = urlsplit(location)
            hostname = parsed.hostname or ""
            if ":" in hostname:
                hostname = f"[{hostname}]"
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            location = f"{parsed.scheme.lower()}://{hostname}:{port}"
        material = f"{category.strip().lower()}|{location}|{vector_hint.strip().lower()}|{identity_id.strip().lower()}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]

    def collect_from_workspace(self, workspace: WorkspaceManager) -> list[FindingRecord]:
        """Collect only artifacts whose recorded producer completed in this scan."""
        validated: dict[str, dict[str, Any]] = {}
        for relative_path, (producer_stage_id, allowed_stage_ids) in ANALYSIS_ARTIFACT_PRODUCERS.items():
            payload = load_validated_stage_artifact(
                workspace,
                producer_stage_id,
                relative_path,
                allowed_stage_ids=allowed_stage_ids,
            )
            if payload is not None:
                validated[relative_path] = payload
        return self.collect_and_deduplicate(validated)

    def collect_and_deduplicate(
        self,
        analysis_artifacts: dict[str, dict[str, Any]],
    ) -> list[FindingRecord]:
        raw_records: list[FindingRecord] = []

        # 1. Findings already shaped as FindingRecord dicts (authorization_matrix, business_logic, nuclei, dns_infrastructure)
        for source_file in (
            "analysis/authorization_matrix.json",
            "analysis/business_logic.json",
            "analysis/nuclei_findings.json",
            "analysis/dns_infrastructure.json",
        ):
            payload = analysis_artifacts.get(source_file) or {}
            for item in payload.get("findings") or []:
                if not isinstance(item, dict):
                    continue
                raw_meta = item.get("metadata")
                meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
                meta.setdefault("source_artifact", source_file)
                if source_file == "analysis/nuclei_findings.json":
                    nuclei_location = str(
                        item.get("location")
                        or item.get("matched_at")
                        or item.get("matched-at")
                        or ""
                    )
                    if nuclei_location:
                        meta.setdefault("target_url", nuclei_location)
                    if item.get("template_id"):
                        meta.setdefault("template_id", str(item.get("template_id"))[:160])
                    if item.get("matcher_name"):
                        meta.setdefault("matcher_name", str(item.get("matcher_name"))[:120])
                    if isinstance(item.get("extracted_results"), list):
                        meta.setdefault("extracted_results", item["extracted_results"][:10])
                elif source_file == "analysis/dns_infrastructure.json":
                    dns_location = str(item.get("location") or meta.get("url") or "")
                    if dns_location:
                        meta.setdefault("target_url", dns_location)
                safe_title = str(item.get("title", "Untitled Finding"))[:300]
                safe_category = str(item.get("category", "uncategorized"))[:120]
                safe_endpoint = str(item.get("endpoint_id") or "ep_unknown")[:128]
                raw_evidence_ids = item.get("evidence_ids")
                evidence_ids = (
                    [str(value)[:128] for value in raw_evidence_ids[:100] if isinstance(value, (str, int))]
                    if isinstance(raw_evidence_ids, list)
                    else []
                )
                raw_location = str(meta.get("target_url") or meta.get("mutated_url") or safe_endpoint)[:512]
                raw_finding_id = _safe_finding_id(
                    item.get("finding_id"),
                    source=source_file,
                    fallback_material=f"{safe_category}|{raw_location}|{safe_title}",
                )
                raw_records.append(
                    FindingRecord(
                        finding_id=raw_finding_id,
                        title=safe_title,
                        category=safe_category,
                        severity=_parse_severity(str(item.get("severity", "INFO"))),
                        verdict=_parse_verdict(str(item.get("verdict", "LIKELY"))),
                        confidence=_parse_confidence(item.get("confidence", 0.6)),
                        asset_id=str(item.get("asset_id") or make_asset_id("target")),
                        endpoint_id=safe_endpoint,
                        identity_id=str(item.get("identity_id") or "anonymous"),
                        description=str(item.get("description", "")),
                        remediation=str(item.get("remediation", "")),
                        evidence_ids=evidence_ids,
                        scanner_source=str(item.get("scanner_source") or source_file),
                        metadata=meta,
                    )
                )

        # 2. Findings from security_headers.json
        headers_art = analysis_artifacts.get("analysis/security_headers.json") or {}
        for item in headers_art.get("findings") or []:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", ""))
            host = (urlsplit(url).hostname or "target").lower()
            raw_records.append(
                FindingRecord(
                    title=str(item.get("title", "Security Header Observation")),
                    category=str(item.get("category", "security_header")),
                    severity=_parse_severity(str(item.get("severity", "INFO"))),
                    verdict=Verdict.LIKELY,
                    confidence=0.85,
                    asset_id=make_asset_id(host),
                    endpoint_id=str(item.get("endpoint_id") or "ep_header"),
                    identity_id="anonymous",
                    description=str(item.get("evidence", "")),
                    remediation="Configure recommended HTTP security headers and strict CORS origin allow-lists.",
                    scanner_source="header_exposure_scanner",
                    metadata={
                        "url": url,
                        "source_artifact": "analysis/security_headers.json",
                    },
                )
            )

        # 3. Findings from tls_posture.json (supports both per-host 'issues' and 'findings' from native + testssl.sh)
        tls_art = analysis_artifacts.get("analysis/tls_posture.json") or {}
        for host_res in tls_art.get("results") or []:
            if not isinstance(host_res, dict):
                continue
            host = str(host_res.get("hostname", "target")).lower()
            port = int(host_res.get("port", 443))
            tls_url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
            host_issues = list(host_res.get("issues") or []) + list(host_res.get("findings") or [])
            for issue in host_issues:
                if not isinstance(issue, dict):
                    continue
                issue_source = str(issue.get("source") or "tls_posture_scanner")
                raw_records.append(
                    FindingRecord(
                        title=str(issue.get("title", "TLS Posture Issue")),
                        category=str(issue.get("category", "tls_posture")),
                        severity=_parse_severity(str(issue.get("severity", "MEDIUM"))),
                        verdict=Verdict.CONFIRMED,
                        confidence=0.95,
                        asset_id=make_asset_id(host),
                        endpoint_id=f"tls_{host}_{port}",
                        identity_id="anonymous",
                        description=str(issue.get("details") or issue.get("evidence") or ""),
                        remediation="Disable TLS 1.0/1.1, enforce TLS 1.2/1.3 with AEAD ciphers, and maintain valid X.509 certificates.",
                        scanner_source=issue_source,
                        metadata={
                            "url": str(issue.get("location") or tls_url),
                            "hostname": host,
                            "port": port,
                            "negotiated_protocol": host_res.get("negotiated_protocol") or host_res.get("protocol_version") or "",
                            "source_artifact": "analysis/tls_posture.json",
                        },
                    )
                )

        # 4. Findings from api_catalog.json & javascript_intel.json
        for source_file in ("analysis/api_catalog.json", "analysis/javascript_intel.json"):
            art = analysis_artifacts.get(source_file) or {}
            for item in art.get("findings") or []:
                if not isinstance(item, dict):
                    continue
                url = str(item.get("url", ""))
                host = (urlsplit(url).hostname or "target").lower()
                raw_records.append(
                    FindingRecord(
                        title=str(item.get("title", "API/JS Exposure")),
                        category=str(item.get("category", "api_exposure")),
                        severity=_parse_severity(str(item.get("severity", "INFO"))),
                        verdict=Verdict.LIKELY,
                        confidence=0.80,
                        asset_id=make_asset_id(host),
                        endpoint_id=f"api_{hashlib.sha256(url.encode('utf-8')).hexdigest()[:12]}",
                        identity_id="anonymous",
                        description=str(item.get("details", "")),
                        remediation=_JS_REMEDIATION.get(
                            str(item.get("category", "")),
                            "Restrict public access to internal specifications, source maps, and schema introspection in production.",
                        ),
                        scanner_source="api_js_intelligence",
                        metadata={
                            "url": url,
                            "source_artifact": source_file,
                        },
                    )
                )

        # Deduplicate and merge corroborating findings
        merged: dict[str, FindingRecord] = {}
        for rec in raw_records:
            meta = rec.metadata
            target_loc = str(
                meta.get("mutated_url")
                or meta.get("tested_url")
                or meta.get("matched_at")
                or meta.get("url")
                or rec.endpoint_id
            )
            vector_hint = str(
                meta.get("parameter_location")
                or meta.get("vector")
                or meta.get("template_id")
                or meta.get("parameter")
                or ""
            )
            dedup_key = self.compute_dedup_key(
                category=rec.category,
                target_location=target_loc,
                vector_hint=vector_hint,
                identity_id=rec.identity_id,
            )
            meta["dedup_key"] = dedup_key
            if not isinstance(meta.get("affected_urls"), list):
                meta["affected_urls"] = []
            if target_loc and target_loc not in meta["affected_urls"]:
                meta["affected_urls"].append(target_loc)
            meta.setdefault("target_url", target_loc)
            meta.setdefault("corroborating_sources", [rec.scanner_source])

            existing = merged.get(dedup_key)
            if existing is not None:
                prior_urls = existing.metadata.get("affected_urls", [])
                urls = list(prior_urls) if isinstance(prior_urls, list) else []
                for url in meta.get("affected_urls", []):
                    if url not in urls:
                        urls.append(url)
                existing.metadata["affected_urls"] = urls
            if existing is None:
                # Scanner-generated UUIDs change between runs. The canonical
                # deduplication key is derived from category, normalized
                # location, vector and identity, so it provides a stable
                # scan-independent finding identifier.
                source_finding_id = rec.finding_id
                rec.finding_id = f"find_{dedup_key[:20]}"
                if source_finding_id and source_finding_id != rec.finding_id:
                    rec.metadata.setdefault("source_finding_ids", [])
                    if source_finding_id not in rec.metadata["source_finding_ids"]:
                        rec.metadata["source_finding_ids"].append(source_finding_id)
                merged[dedup_key] = rec
                continue

            # Merge duplicate: keep highest severity, highest confidence, and combine sources
            if SEVERITY_RANK.get(rec.severity.value, 0) > SEVERITY_RANK.get(existing.severity.value, 0):
                existing.severity = rec.severity
            if rec.confidence > existing.confidence:
                existing.confidence = rec.confidence

            sources = set(existing.metadata.get("corroborating_sources", []))
            sources.add(rec.scanner_source)
            existing.metadata["corroborating_sources"] = sorted(sources)
            for ev_id in rec.evidence_ids:
                if ev_id not in existing.evidence_ids:
                    existing.evidence_ids.append(ev_id)

        return sorted(
            merged.values(),
            key=lambda f: (-SEVERITY_RANK.get(f.severity.value, 0), f.category, f.title),
        )