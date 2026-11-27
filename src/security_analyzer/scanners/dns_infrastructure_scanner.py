from __future__ import annotations

import ipaddress
import re
import shutil
import time
from datetime import datetime, timezone
from typing import Any

from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.models.asset import make_asset_id
from security_analyzer.models.finding import FindingRecord, Severity, Verdict


_DOMAIN_RE = re.compile(
    r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$"
)

_WHOIS_REGISTRAR_RE = re.compile(r"(?im)^\s*Registrar:\s*(.+?)\s*$")
_WHOIS_CREATED_RE = re.compile(
    r"(?im)^\s*(?:Creation Date|Created On|Registered on|Registration Time):\s*(.+?)\s*$"
)
_WHOIS_EXPIRY_RE = re.compile(
    r"(?im)^\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|Expiration Date|Expires on):\s*(.+?)\s*$"
)
_WHOIS_UPDATED_RE = re.compile(
    r"(?im)^\s*(?:Updated Date|Last Updated On|Last Modified):\s*(.+?)\s*$"
)
_WHOIS_NS_RE = re.compile(r"(?im)^\s*Name Server:\s*([A-Za-z0-9.-]+)\s*$")
_WHOIS_DNSSEC_RE = re.compile(r"(?im)^\s*DNSSEC:\s*(.+?)\s*$")

_TAKEOVER_PROVIDER_SUFFIXES: tuple[tuple[str, str], ...] = (
    (".s3.amazonaws.com", "AWS S3"),
    (".s3-website-", "AWS S3 Website"),
    (".s3-website.", "AWS S3 Website"),
    (".github.io", "GitHub Pages"),
    (".herokuapp.com", "Heroku"),
    (".herokudns.com", "Heroku"),
    (".azurewebsites.net", "Microsoft Azure App Service"),
    (".cloudapp.azure.com", "Microsoft Azure CloudApp"),
    (".cloudapp.net", "Microsoft Azure CloudApp"),
    (".trafficmanager.net", "Microsoft Azure Traffic Manager"),
    (".blob.core.windows.net", "Microsoft Azure Blob Storage"),
    (".vercel.app", "Vercel"),
    (".cname.vercel-dns.com", "Vercel"),
    (".netlify.app", "Netlify"),
    (".netlify.com", "Netlify"),
    (".fastly.net", "Fastly"),
    (".fastlylb.net", "Fastly"),
    (".myshopify.com", "Shopify"),
    (".shops.myshopify.com", "Shopify"),
    (".ghost.io", "Ghost"),
    (".pantheonsite.io", "Pantheon"),
    (".zendesk.com", "Zendesk"),
    (".surge.sh", "Surge.sh"),
    (".bitbucket.io", "Bitbucket Pages"),
    (".readthedocshosted.com", "Read the Docs"),
    (".statuspage.io", "Atlassian Statuspage"),
)

_TAKEOVER_BODY_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("NoSuchBucket", "AWS S3"),
    ("There isn't a GitHub Pages site here.", "GitHub Pages"),
    ("No such app", "Heroku"),
    ("herokucdn.com/error-pages/no-such-app.html", "Heroku"),
    ("Fastly error: unknown domain:", "Fastly"),
    ("The specified bucket does not exist", "Cloud Object Storage"),
    ("Sorry, this shop is currently unavailable.", "Shopify"),
    ("Repository not found", "Bitbucket Pages"),
    ("Project doesnt exist... yet!", "Surge.sh"),
)


_CLOUD_STORAGE_PROVIDERS = {"aws s3", "aws s3 website", "microsoft azure blob storage"}


def _banner_matches_cname(banner_provider: str, cname_provider: str) -> bool:
    """A page-text signature only counts if it is consistent with the CNAME's provider."""
    if not banner_provider:
        return False
    if not cname_provider:
        return False
    b, c = banner_provider.lower(), cname_provider.lower()
    if b == c or b in c or c in b:
        return True
    if b == "cloud object storage" and c in _CLOUD_STORAGE_PROVIDERS:
        return True
    return bool(set(b.split()) & set(c.split()) - {"microsoft", "azure", "aws", "pages", "app", "service"})


def _scope_url_for_host(hostname: str, scope_engine) -> str:
    host = (hostname or "").strip().lower().rstrip(".")
    if not host or not _DOMAIN_RE.fullmatch(host):
        raise ValueError("Invalid DNS hostname")

    allowed_schemes = scope_engine.policy.allowed_schemes
    allowed_ports = scope_engine.policy.allowed_ports
    scheme = "https" if "https" in allowed_schemes else "http"
    default_port = 443 if scheme == "https" else 80
    port = default_port if default_port in allowed_ports else (
        allowed_ports[0] if allowed_ports else default_port
    )
    if port not in allowed_ports and allowed_ports:
        raise ValueError("No permitted port available for DNS scope validation")
    authority = f"{host}:{port}" if port != default_port else host
    return f"{scheme}://{authority}/"


def _resolve_scoped_host(hostname: str, scope_engine) -> tuple[list[str], str]:
    """Resolve only through ScopeEngine, which validates every returned address."""
    try:
        url = _scope_url_for_host(hostname, scope_engine)
        decision = scope_engine.evaluate_url(url, check_dns=True)
    except (TypeError, ValueError) as exc:
        return [], str(exc)

    if not decision.allowed:
        return [], decision.reason

    safe_ips: list[str] = []
    for raw_ip in decision.resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        safe_ips.append(str(ip_obj))
    return sorted(set(safe_ips)), ""


def _query_txt_records(
    domain: str,
    governor=None,
    *,
    scope_engine=None,
    timeout_sec: float = 8.0,
) -> tuple[list[str], str]:
    """Run a bounded TXT query only after validating the queried DNS name."""
    dig_bin = shutil.which("dig")
    if not dig_bin:
        return [], "dig binary is not installed"
    if governor is None:
        return [], "shared ResourceGovernor unavailable; unbounded dig execution forbidden"
    if scope_engine is None:
        return [], "scope engine unavailable"

    clean_domain = (domain or "").strip().lower().rstrip(".")
    if not _DOMAIN_RE.fullmatch(clean_domain):
        if clean_domain.startswith("_dmarc."):
            parent_domain = clean_domain[len("_dmarc."):]
            if not _DOMAIN_RE.fullmatch(parent_domain):
                return [], "invalid DMARC query name"
        else:
            return [], "invalid DNS query name"
    else:
        parent_domain = clean_domain

    _, scope_error = _resolve_scoped_host(parent_domain, scope_engine)
    if scope_error:
        return [], f"DNS query blocked by scope validation: {scope_error}"

    try:
        result = governor.run_process(
            [dig_bin, "+time=3", "+tries=1", "+short", "TXT", clean_domain],
            timeout_sec=timeout_sec,
        )
    except ResourceLimitExceeded as exc:
        return [], f"resource budget exhausted: {exc}"
    except OSError as exc:
        return [], f"dig execution failed: {type(exc).__name__}"

    if result.timed_out:
        return [], "dig timed out"
    if result.output_truncated:
        return [], "dig output exceeded configured process-output limit"
    if result.returncode != 0:
        return [], f"dig exited with code {result.returncode}"

    records = [
        line.strip().strip('"')
        for line in (result.stdout or "").splitlines()
        if line.strip()
    ]
    return records[:100], ""


def _query_cname_records(
    hostname: str,
    governor=None,
    *,
    scope_engine=None,
    timeout_sec: float = 8.0,
) -> tuple[list[str], str]:
    """Run a bounded CNAME query for an in-scope hostname to detect dangling cloud aliases."""
    dig_bin = shutil.which("dig")
    if not dig_bin:
        return [], "dig binary is not installed"
    if governor is None:
        return [], "shared ResourceGovernor unavailable; unbounded dig execution forbidden"
    if scope_engine is None:
        return [], "scope engine unavailable"

    clean_host = (hostname or "").strip().lower().rstrip(".")
    if not clean_host or clean_host == "localhost" or "." not in clean_host:
        return [], "non-public hostname"
    try:
        ipaddress.ip_address(clean_host)
        return [], "IP literals are skipped for CNAME lookup"
    except ValueError:
        pass
    if not _DOMAIN_RE.fullmatch(clean_host):
        return [], "invalid CNAME hostname"

    try:
        url = _scope_url_for_host(clean_host, scope_engine)
        decision = scope_engine.evaluate_url(url, check_dns=False)
    except (TypeError, ValueError) as exc:
        return [], str(exc)

    if not decision.allowed:
        return [], f"CNAME query blocked by scope validation: {decision.reason}"

    try:
        result = governor.run_process(
            [dig_bin, "+time=3", "+tries=1", "+short", "CNAME", clean_host],
            timeout_sec=timeout_sec,
        )
    except ResourceLimitExceeded as exc:
        return [], f"resource budget exhausted: {exc}"
    except OSError as exc:
        return [], f"dig CNAME execution failed: {type(exc).__name__}"

    if result.timed_out:
        return [], "dig CNAME timed out"
    if result.output_truncated:
        return [], "dig CNAME output exceeded configured process-output limit"
    if result.returncode != 0:
        return [], f"dig CNAME exited with code {result.returncode}"

    cnames = [
        line.strip().rstrip(".").lower()
        for line in (result.stdout or "").splitlines()
        if line.strip() and _DOMAIN_RE.fullmatch(line.strip())
    ]
    return cnames[:20], ""


def _match_takeover_provider(cname_target: str) -> str:
    target = cname_target.strip().lower().rstrip(".")
    for suffix, provider in _TAKEOVER_PROVIDER_SUFFIXES:
        if suffix in target or target.endswith(suffix):
            return provider
    return ""


def _load_http_probe_snippets(workspace) -> dict[str, str]:
    """Read optional discovery/http_probes.json snippets per host without sending traffic."""
    snippets: dict[str, str] = {}
    probe_path = workspace.resolve_path("discovery/http_probes.json")
    if not probe_path.is_file() or probe_path.stat().st_size == 0:
        return snippets
    try:
        payload = workspace.read_json("discovery/http_probes.json")
    except Exception:
        return snippets
    for entry in payload.get("probes") or []:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or "")
        if "://" not in url:
            continue
        host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
        combined = " ".join(
            str(entry.get(k) or "")
            for k in ("title", "body_preview", "server", "error")
        )
        if combined.strip():
            snippets[host] = f"{snippets.get(host, '')} {combined}".strip()[:2000]
    return snippets


def _parse_whois_output(raw_text: str) -> dict[str, Any]:
    registrar_m = _WHOIS_REGISTRAR_RE.search(raw_text)
    created_m = _WHOIS_CREATED_RE.search(raw_text)
    expiry_m = _WHOIS_EXPIRY_RE.search(raw_text)
    updated_m = _WHOIS_UPDATED_RE.search(raw_text)
    dnssec_m = _WHOIS_DNSSEC_RE.search(raw_text)
    nameservers = sorted({
        match.group(1).strip().lower().rstrip(".")
        for match in _WHOIS_NS_RE.finditer(raw_text)
        if match.group(1).strip()
    })[:20]

    return {
        "registrar": (registrar_m.group(1)[:200] if registrar_m else ""),
        "creation_date": (created_m.group(1)[:64] if created_m else ""),
        "expiry_date": (expiry_m.group(1)[:64] if expiry_m else ""),
        "updated_date": (updated_m.group(1)[:64] if updated_m else ""),
        "dnssec": (dnssec_m.group(1)[:64] if dnssec_m else ""),
        "name_servers": nameservers,
    }


def _query_whois_record(
    domain: str,
    governor=None,
    *,
    scope_engine=None,
    timeout_sec: float = 10.0,
) -> tuple[dict[str, Any], str]:
    """Refuse raw WHOIS TCP/43 until a scoped protocol proxy is implemented."""
    return {}, (
        "WHOIS skipped: raw TCP/43 is not supported by the scoped HTTP proxy; "
        "direct scanner egress is disabled"
    )


def run_server_dns_checks(
    ctx: ExecutionContext,
    stage_def: StageDefinition,
) -> StageResult:
    """Inspect DNS, CNAME takeover posture, and WHOIS policy for discovered in-scope assets."""
    inventory = UnifiedEndpointInventory(ctx.workspace)
    assets = inventory.all_assets()
    records: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    dig_available = shutil.which("dig") is not None
    whois_available = shutil.which("whois") is not None
    resolution_failures = 0
    notes: list[str] = []
    timeouts = ctx.config.get("timeouts", {})
    max_assets = int(
        ctx.config.get("limits", {}).get("max_urls_per_stage", 2500)
    )
    selected_assets = assets[:max_assets]
    tested = 0
    whois_cache: dict[str, tuple[dict[str, Any], str]] = {}
    whois_used_any = False
    probe_snippets = _load_http_probe_snippets(ctx.workspace)
    degraded = False
    txt_cache: dict[str, tuple[list[str], str]] = {}
    email_reported: set[str] = set()
    txt_error_hosts = 0
    deadline_skipped = 0
    deadline = time.monotonic() + float(timeouts.get("dns_stage_sec", 600))

    def _cached_txt(name: str) -> tuple[list[str], str]:
        # Every subdomain shares its root domain's SPF/DMARC: query once, not once per host.
        if name not in txt_cache:
            txt_cache[name] = _query_txt_records(
                name,
                ctx.resource_governor,
                scope_engine=ctx.scope_engine,
                timeout_sec=float(timeouts.get("dns_sec", 8.0)),
            )
        return txt_cache[name]

    if not assets:
        degraded = True
        notes.append("No inventoried assets were available for DNS checks")
    if whois_available:
        whois_transport_reason = (
            "WHOIS skipped: raw TCP/43 is not supported by the scoped HTTP proxy; "
            "direct scanner egress is disabled"
        )
        notes.append(whois_transport_reason)
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "whois_transport", whois_transport_reason
        )

    for idx, asset in enumerate(selected_assets):
        if time.monotonic() >= deadline:
            deadline_skipped = len(selected_assets) - idx
            degraded = True
            notes.append(f"DNS checks stopped: stage time budget reached ({deadline_skipped} asset(s) not checked)")
            ctx.coverage.record_skipped_check(stage_def.stage_id, "dns_stage_budget", notes[-1])
            break
        host = asset.hostname
        ips, resolve_error = _resolve_scoped_host(host, ctx.scope_engine)
        if resolve_error:
            resolution_failures += 1
            ctx.coverage.record_skipped_check(
                stage_def.stage_id,
                "dns_resolution",
                f"{host}: {resolve_error}",
            )
        else:
            tested += 1
            ctx.coverage.record_target_tested(
                stage_def.stage_id,
                f"https://{host}/",
                metadata={"resolved_ips": ips},
            )

        cname_records: list[str] = []
        cname_error = ""
        if dig_available and ctx.resource_governor is not None:
            cname_records, cname_error = _query_cname_records(
                host,
                ctx.resource_governor,
                scope_engine=ctx.scope_engine,
                timeout_sec=float(timeouts.get("dns_sec", 8.0)),
            )

        takeover_provider = ""
        for cname_target in cname_records:
            provider = _match_takeover_provider(cname_target)
            if provider:
                takeover_provider = provider
                break

        host_snippet = probe_snippets.get(host.lower(), "")
        matched_banner_provider = ""
        for signature, provider in _TAKEOVER_BODY_SIGNATURES:
            if signature.lower() in host_snippet.lower():
                matched_banner_provider = provider
                break

        if matched_banner_provider and not _banner_matches_cname(matched_banner_provider, takeover_provider):
            matched_banner_provider = ""  # signature text on an unrelated provider is not evidence

        if cname_records and (resolve_error != "" or matched_banner_provider):
            provider_label = matched_banner_provider or takeover_provider or "external CNAME target"
            findings.append(
                FindingRecord(
                    title=f"Potential subdomain takeover on {host} ({provider_label})",
                    category="subdomain_takeover_dangling_cname",
                    severity=Severity.HIGH,
                    verdict=Verdict.CONFIRMED if matched_banner_provider else Verdict.LIKELY,
                    confidence=0.95 if matched_banner_provider else 0.85,
                    asset_id=make_asset_id(host),
                    endpoint_id=f"dns_cname_{host}",
                    identity_id="anonymous",
                    description=(
                        f"Subdomain {host} resolves via CNAME to {cname_records} ({provider_label}), "
                        + (
                            f"and HTTP probe output matched unclaimed service signature for {matched_banner_provider}."
                            if matched_banner_provider
                            else f"but final DNS resolution failed ({resolve_error}), indicating a dangling alias."
                        )
                    ),
                    remediation=(
                        "Remove the dangling DNS CNAME record or claim the corresponding resource on the target cloud provider."
                    ),
                    scanner_source="dns_infrastructure_scanner",
                    metadata={
                        "url": f"https://{host}/",
                        "hostname": host,
                        "cname_chain": cname_records,
                        "provider": provider_label,
                        "resolution_error": resolve_error,
                    },
                ).to_dict()
            )
        elif cname_records and takeover_provider and host.lower() != (asset.root_domain or "").lower():
            findings.append(
                FindingRecord(
                    title=f"Cloud CNAME alias review surface on {host} ({takeover_provider})",
                    category="subdomain_takeover_surface",
                    severity=Severity.MEDIUM,
                    verdict=Verdict.NEEDS_HUMAN_REVIEW,
                    confidence=0.65,
                    asset_id=make_asset_id(host),
                    endpoint_id=f"dns_cname_{host}",
                    identity_id="anonymous",
                    description=(
                        f"Subdomain {host} points via CNAME to {cname_records} ({takeover_provider}). "
                        "Verify that the upstream cloud resource is actively claimed under your organization."
                    ),
                    remediation=(
                        "Audit the CNAME target in your DNS zone and verify ownership of the mapped cloud service."
                    ),
                    scanner_source="dns_infrastructure_scanner",
                    metadata={
                        "url": f"https://{host}/",
                        "hostname": host,
                        "cname_chain": cname_records,
                        "provider": takeover_provider,
                    },
                ).to_dict()
            )

        txt_records: list[str] = []
        dmarc_records: list[str] = []
        txt_errors: list[str] = []

        if dig_available and resolve_error == "":
            txt_records, txt_error = _cached_txt(asset.root_domain or host)
            if txt_error:
                txt_errors.append(f"SPF TXT: {txt_error}")

            dmarc_records, dmarc_error = _cached_txt(f"_dmarc.{asset.root_domain or host}")
            if dmarc_error:
                txt_errors.append(f"DMARC TXT: {dmarc_error}")

        whois_info: dict[str, Any] = {}
        whois_error = ""
        if whois_available and resolve_error == "":
            whois_domain = (asset.root_domain or host).strip().lower().rstrip(".")
            if whois_domain not in whois_cache:
                whois_cache[whois_domain] = _query_whois_record(
                    whois_domain,
                    ctx.resource_governor,
                    scope_engine=ctx.scope_engine,
                    timeout_sec=float(timeouts.get("whois_sec", max(float(timeouts.get("dns_sec", 8.0)), 10.0))),
                )
            whois_info, whois_error = whois_cache[whois_domain]
            if whois_info and not whois_error:
                whois_used_any = True

        has_spf = any("v=spf1" in record.lower() for record in txt_records)
        has_dmarc = any("v=dmarc1" in record.lower() for record in dmarc_records)

        # SPF/DMARC were collected but never reported. Emit one observation per root domain.
        mail_domain = (asset.root_domain or host).lower()
        if dig_available and resolve_error == "" and not txt_errors and mail_domain not in email_reported:
            email_reported.add(mail_domain)
            for missing, category, severity, title, text in (
                (not has_spf, "missing_spf_record", Severity.INFO,
                 f"No SPF record published for {mail_domain}",
                 "No TXT record beginning with v=spf1 was returned. If the domain sends or should never send email, publish an SPF policy."),
                (not has_dmarc, "missing_dmarc_record", Severity.LOW,
                 f"No DMARC record published for {mail_domain}",
                 "No _dmarc TXT record with v=DMARC1 was returned, so receivers have no policy for spoofed mail."),
            ):
                if not missing:
                    continue
                findings.append(
                    FindingRecord(
                        title=title,
                        category=category,
                        severity=severity,
                        verdict=Verdict.LIKELY,
                        confidence=0.7,
                        asset_id=make_asset_id(mail_domain),
                        endpoint_id=f"dns_txt_{mail_domain}",
                        identity_id="anonymous",
                        description=text,
                        remediation="Publish a SPF record and a DMARC policy (start with p=none and reporting, then enforce).",
                        scanner_source="dns_infrastructure_scanner",
                        metadata={"hostname": mail_domain, "url": f"https://{mail_domain}/"},
                    ).to_dict()
                )

        records.append({
            "hostname": host,
            "root_domain": asset.root_domain,
            "resolved_ips": ips,
            "cname_records": cname_records,
            "takeover_provider": takeover_provider,
            "resolution_error": resolve_error,
            "technologies": asset.technologies,
            "dns_txt_checked": bool(dig_available and not txt_errors and resolve_error == ""),
            "has_spf": has_spf if dig_available and not txt_errors else None,
            "has_dmarc": has_dmarc if dig_available and not txt_errors else None,
            "txt_errors": txt_errors,
            "whois_checked": bool(whois_available and not whois_error and resolve_error == ""),
            "whois": whois_info,
            "whois_error": whois_error,
        })

        if txt_errors:
            txt_error_hosts += 1
            notes.extend(
                m for m in (f"{asset.root_domain or host}: {error}" for error in txt_errors) if m not in notes
            )

        if (
            "resource budget exhausted" in cname_error
            or any("resource budget exhausted" in error for error in txt_errors)
            or "resource budget exhausted" in whois_error
        ):
            if "resource budget exhausted" in cname_error:
                notes.append(f"{host}: CNAME: {cname_error}")
            degraded = True
            break

    if not dig_available:
        reason = "dig is not installed; SPF/DMARC TXT checks were skipped"
        notes.append(reason)
        ctx.coverage.record_skipped_check(stage_def.stage_id, "dig", reason)
        degraded = True
    elif ctx.resource_governor is None:
        reason = "shared ResourceGovernor unavailable; SPF/DMARC TXT checks were skipped"
        notes.append(reason)
        ctx.coverage.record_skipped_check(stage_def.stage_id, "dig_resource_governor", reason)
        degraded = True

    if not whois_available:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id, "whois", "whois is not installed; domain registration lookup skipped"
        )

    if len(assets) > len(selected_assets):
        notes.append(
            f"Asset processing capped at {len(selected_assets)} of {len(assets)} by max_urls_per_stage"
        )

    tools_used = []
    if dig_available and ctx.resource_governor is not None:
        tools_used.append("dig")
    if whois_used_any:
        tools_used.append("whois")

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "external_tools_used": tools_used,
        "records": records,
        "findings": findings,
        "notes": notes,
    }
    ctx.workspace.write_json_atomic("analysis/dns_infrastructure.json", payload)

    skipped = max(0, len(assets) - tested)
    # Dead subdomains and the (always skipped) WHOIS transport are expected, informational notes.
    too_many_txt_errors = tested > 0 and txt_error_hosts > tested * 0.5
    status = (
        StageStatus.PARTIAL
        if degraded or tested == 0 or too_many_txt_errors
        else StageStatus.SUCCESS
    )
    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Checked {tested}/{len(selected_assets)} asset(s); "
            f"{resolution_failures} DNS resolution failure(s); "
            f"{len(findings)} takeover finding(s)"
            + (f"; {'; '.join(notes)}" if notes else "")
        ),
        artifacts=["analysis/dns_infrastructure.json"],
        metrics={
            "targets_total": len(assets),
            "targets_tested": tested,
            "targets_skipped": skipped,
            "deadline_skipped": deadline_skipped,
            "email_auth_domains_checked": len(email_reported),
        },
    )