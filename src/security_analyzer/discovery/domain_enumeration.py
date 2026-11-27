from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.egress import is_trusted_scope_proxy
from security_analyzer.core.resource_governor import ResourceLimitExceeded
from security_analyzer.core.scope_engine import _dns_delegated_to_proxy
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus
from security_analyzer.discovery.endpoint_normalizer import normalize_endpoint
from security_analyzer.discovery.inventory_store import UnifiedEndpointInventory
from security_analyzer.models.asset import AssetRecord, make_asset_id


# Sensible per-tool defaults when settings.yaml has no "<tool>_sec" key (FIX 5).
_DEFAULT_TOOL_TIMEOUTS = {"subfinder": 120, "assetfinder": 120, "amass": 300, "bbot": 300, "findomain": 300, "crtsh": 120}


def _scope_aware_proxy_env(tool_name: str) -> tuple[dict[str, str] | None, str]:
    """Passive enumerators query public sources, not the target, so run them
    WITHOUT the target scope proxy (it blocks every third-party source).
    Results are still scope-filtered later in this stage."""  # QUIVER_PATCH_STEP1
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    return env, ""


def _run_external_tool(
    tool_name: str,
    command: list[str],
    timeout_sec: int,
    governor,
) -> tuple[bool, str, str]:
    """Execute a discovery binary under the shared process/resource governor."""

    if governor is None:
        return (
            False,
            "",
            f"{tool_name} skipped: shared ResourceGovernor is unavailable",
        )

    env, reason = _scope_aware_proxy_env(tool_name)

    if env is None:
        return False, "", reason

    try:
        proc = governor.run_process(
            command,
            timeout_sec=timeout_sec,
            env=env,
        )

    except ResourceLimitExceeded:
        return (
            False,
            "",
            f"{tool_name} exceeded its configured time/resource budget "
            f"({timeout_sec}s)",
        )

    except OSError as exc:
        return (
            False,
            "",
            f"{tool_name} execution failed: {type(exc).__name__}",
        )

    # Keep whatever the tool printed before it was stopped, so callers can
    # salvage partial results (FIX 4).
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    if proc.timed_out:
        return False, stdout, f"{tool_name} timed out after {timeout_sec}s"

    if proc.output_truncated:
        return (
            False,
            stdout,
            f"{tool_name} output exceeded the configured process-output limit",
        )

    if proc.returncode != 0:
        # Keep the tail: startup banners (notably BBOT's) often precede the
        # actionable CLI error, so truncating the beginning hides the cause.
        detail = (stderr.strip() or stdout.strip())[-500:]
        detail = " ".join(detail.split())
        if not detail:
            detail = f"exit code {proc.returncode}"
        return (
            False,
            stdout,
            f"{tool_name} returned non-zero status ({proc.returncode}): {detail}",
        )

    return True, stdout, ""


def _normalize_discovered_host(value: object) -> str | None:
    """Extract a hostname from a scanner result without trusting its scope."""

    if not isinstance(value, str):
        return None

    candidate = value.strip().lower().rstrip(".")

    if not candidate:
        return None

    if candidate.startswith("*."):
        candidate = candidate[2:]

    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    else:
        candidate = candidate.split("/", 1)[0].split(":", 1)[0]

    candidate = candidate.strip().rstrip(".")

    if (
        not candidate
        or len(candidate) > 253
        or any(ch.isspace() for ch in candidate)
    ):
        return None

    if candidate.startswith(".") or ".." in candidate:
        return None

    return candidate


def _hosts_from_lines(stdout: str) -> list[str]:
    """Parse one-host-per-line tool output (first token of each line)."""
    found: set[str] = set()
    for line in stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        host = _normalize_discovered_host(parts[0])
        if host:
            found.add(host)
    return sorted(found)


def _finish_line_tool(ok: bool, stdout: str, error: str) -> tuple[bool, list[str], str]:
    """Return hosts; on timeout/truncation keep partial hosts as a warning."""
    hosts = _hosts_from_lines(stdout) if stdout else []
    if ok:
        return True, hosts, ""
    if hosts:
        return True, hosts, f"partial results kept: {error}"
    return False, [], error


@lru_cache(maxsize=1)
def _amass_supports_legacy_flags(binary: str) -> bool:
    """Detect the complete Amass v3 flag pair used by the legacy runner.

    Checking only ``-passive`` is unsafe: some builds expose that flag while
    rejecting ``-json``. The legacy command is selected only when both flags
    are advertised by the installed binary.
    """
    try:
        out = subprocess.run(
            [binary, "enum", "-h"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        help_text = f"{out.stdout or ''}\n{out.stderr or ''}"
        return "-passive" in help_text and "-json" in help_text
    except (OSError, subprocess.SubprocessError):
        return False


def _run_subfinder(
    root_domain: str,
    timeout_sec: int,
    governor=None,
) -> tuple[bool, list[str], str]:

    binary = shutil.which("subfinder")

    if not binary:
        return False, [], "subfinder binary not installed"

    if governor is None:
        return (
            False,
            [],
            "subfinder skipped: shared ResourceGovernor is unavailable",
        )

    env, reason = _scope_aware_proxy_env("subfinder")

    if env is None:
        return False, [], reason

    command = [
        binary,
        "-d", root_domain,
        "-silent",
    ]

    ok, stdout, error = _run_external_tool(
        "subfinder",
        command,
        timeout_sec,
        governor,
    )

    return _finish_line_tool(ok, stdout, error)


def _run_assetfinder(
    root_domain: str,
    timeout_sec: int,
    governor=None,
) -> tuple[bool, list[str], str]:

    binary = shutil.which("assetfinder")

    if not binary:
        return False, [], "assetfinder binary not installed"

    command = [
        binary,
        "--subs-only",
        root_domain,
    ]

    ok, stdout, error = _run_external_tool(
        "assetfinder",
        command,
        timeout_sec,
        governor,
    )

    return _finish_line_tool(ok, stdout, error)


def _run_amass(
    root_domain: str,
    timeout_sec: int,
    governor=None,
) -> tuple[bool, list[str], str]:

    binary = shutil.which("amass")

    if not binary:
        return False, [], "amass binary not installed"

    legacy = _amass_supports_legacy_flags(binary)

    with tempfile.TemporaryDirectory(
        prefix="security-analyzer-amass-"
    ) as temp_dir:

        if legacy:
            # amass v3: passive mode + JSON file output.
            output_path = Path(temp_dir) / "amass.json"
            command = [binary, "enum", "-passive", "-d", root_domain,
                       "-json", str(output_path)]
        else:
            # amass v4: no -passive/-json. Results go to a local DB (-dir);
            # -timeout is in MINUTES. Names are printed and also read back
            # with `amass subs -names`.
            output_path = None
            command = [binary, "enum", "-d", root_domain, "-dir", temp_dir,
                       "-nocolor", "-timeout", str(max(1, int(timeout_sec) // 60))]

        ok, stdout, error = _run_external_tool("amass", command, timeout_sec, governor)

        found: set[str] = set(_hosts_from_lines(stdout)) if not legacy else set()

        if legacy and output_path is not None and output_path.is_file():
            try:
                raw = output_path.read_text(encoding="utf-8", errors="replace")
                for line in raw.splitlines():
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(record, dict):
                        host = _normalize_discovered_host(
                            record.get("name") or record.get("domain"))
                        if host:
                            found.add(host)
            except OSError:
                pass

        followup_error = ""
        if not legacy and ok:
            ok2, subs_out, err2 = _run_external_tool(
                "amass",
                [binary, "subs", "-d", root_domain, "-names", "-dir", temp_dir, "-nocolor"],
                min(60, int(timeout_sec)),
                governor,
            )
            if ok2:
                found.update(_hosts_from_lines(subs_out))
            else:
                followup_error = f"Amass enum completed but 'amass subs' failed: {err2}"

        if found:
            warnings = [item for item in (error if not ok else "", followup_error) if item]
            return True, sorted(found), "; ".join(warnings)
        if not ok:
            return False, [], error
        if followup_error:
            return False, [], followup_error
        return False, [], "amass completed but returned no hostnames"


def _run_bbot(
    root_domain: str,
    timeout_sec: int,
    governor=None,
) -> tuple[bool, list[str], str]:

    binary = shutil.which("bbot")

    if not binary:
        return False, [], "bbot binary not installed"

    # Use the subdomain-enum preset and parse JSON events from stdout.
    with tempfile.TemporaryDirectory(
        prefix="security-analyzer-bbot-"
    ) as temp_dir:

        command = [
            binary,
            "-t", root_domain,
            "-f", "subdomain-enum",
            "-om", "json",
            "-o", temp_dir,
            "--yes",
            "--no-color",
        ]

        ok, stdout, error = _run_external_tool(
            "bbot",
            command,
            timeout_sec,
            governor,
        )

        found: set[str] = set()

        def _collect_event(event: object) -> None:
            if not isinstance(event, dict):
                return
            if str(event.get("type", "")).upper() != "DNS_NAME":
                return
            data = event.get("data")
            if isinstance(data, dict):
                data = data.get("host") or data.get("hostname") or data.get("name")
            host = _normalize_discovered_host(data)
            if host:
                found.add(host)

        def _collect(text: str) -> None:
            if not text.strip():
                return
            # Support both a JSON document/array and JSONL/NDJSON event streams.
            try:
                document = json.loads(text)
            except json.JSONDecodeError:
                document = None
            if isinstance(document, list):
                for event in document:
                    _collect_event(event)
                return
            if isinstance(document, dict):
                _collect_event(document)
                return
            for line in text.splitlines():
                try:
                    _collect_event(json.loads(line))
                except json.JSONDecodeError:
                    continue

        # BBOT output modules can create output.json, output.ndjson, or a
        # similarly named JSON file inside the scan-specific output directory.
        for out_file in Path(temp_dir).rglob("*"):
            if not out_file.is_file() or out_file.suffix.lower() not in {".json", ".jsonl", ".ndjson"}:
                continue
            try:
                _collect(out_file.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
        _collect(stdout)

        if found:
            return True, sorted(found), ("" if ok else f"partial results kept: {error}")
        if not ok:
            return False, [], error
        return False, [], "bbot completed successfully but produced no parseable DNS_NAME events"


def _run_findomain(root_domain, timeout_sec, governor=None):
    binary = shutil.which("findomain")
    if not binary:
        return False, [], "findomain binary not installed"
    ok, stdout, error = _run_external_tool(
        "findomain", [binary, "-t", root_domain, "-q"], timeout_sec, governor)
    return _finish_line_tool(ok, stdout, error)


def _run_crtsh(root_domain, timeout_sec, governor=None):
    import time
    import urllib.request
    req = urllib.request.Request(
        f"https://crt.sh/?q=%25.{root_domain}&output=json",
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
    )
    last = "crt.sh returned no data"
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=min(timeout_sec, 120)) as resp:
                entries = json.loads(resp.read().decode(errors="ignore"))
            names = set()
            for entry in entries:
                for n in str(entry.get("name_value", "")).splitlines():
                    names.add(n.strip().lstrip("*."))
            return True, _hosts_from_lines("\n".join(sorted(names))), ""
        except Exception as exc:
            last = f"crt.sh failed: {type(exc).__name__}: {exc}"
            time.sleep(3)
    return False, [], last


def run_domain_enumeration(
    ctx: ExecutionContext,
    stage_def: StageDefinition,
) -> StageResult:

    check_dns = True

    seed_url = ctx.scope_engine.enforce_url(
        ctx.target,
        check_dns=check_dns,
    )

    parsed_seed = urlsplit(seed_url)

    seed_host = (
        parsed_seed.hostname or ""
    ).lower().rstrip(".")

    seed_port = parsed_seed.port or (
        443 if parsed_seed.scheme == "https" else 80
    )

    candidate_hosts: dict[str, set[str]] = {
        seed_host: {"target_seed"}
    }

    tools_used: set[str] = set()
    attempted_tools: set[str] = set()
    failed_tools: set[str] = set()
    partial_tools: set[str] = set()
    tool_stats: dict[str, dict[str, object]] = {}
    notes: list[str] = []

    enumeration_tools = (
        ("subfinder", _run_subfinder),
        ("amass", _run_amass),
        ("assetfinder", _run_assetfinder),
        ("bbot", _run_bbot),
        ("findomain", _run_findomain),
        ("crtsh", _run_crtsh),
    )

    if (
        ctx.scope_engine.policy.include_subdomains
        and ctx.scope_engine.policy.allowed_domains
    ):

        timeout_cfg = ctx.config.get("timeouts", {})

        for root_domain in ctx.scope_engine.policy.allowed_domains:

            for tool_name, runner in enumeration_tools:

                timeout_sec = int(
                    timeout_cfg.get(
                        f"{tool_name}_sec",
                        _DEFAULT_TOOL_TIMEOUTS.get(
                            tool_name, timeout_cfg.get("subfinder_sec", 120)
                        ),
                    )
                )

                attempted_tools.add(tool_name)
                ok, hosts, reason = runner(
                    root_domain,
                    timeout_sec,
                    ctx.resource_governor,
                )
                stats = tool_stats.setdefault(
                    tool_name,
                    {"attempts": 0, "successful_runs": 0, "failed_runs": 0,
                     "partial_runs": 0, "discovered_hosts": set()},
                )
                stats["attempts"] = int(stats["attempts"]) + 1

                if ok:

                    tools_used.add(tool_name)
                    stats["successful_runs"] = int(stats["successful_runs"]) + 1
                    if reason:
                        partial_tools.add(tool_name)
                        stats["partial_runs"] = int(stats["partial_runs"]) + 1
                    discovered_for_tool = stats["discovered_hosts"]
                    if isinstance(discovered_for_tool, set):
                        discovered_for_tool.update(hosts)

                    for host in hosts:
                        candidate_hosts.setdefault(
                            host,
                            set(),
                        ).add(tool_name)

                    if reason:  # ok, but with a warning (partial results)
                        notes.append(f"{tool_name} ({root_domain}): {reason}")

                else:

                    # A missing optional binary is a coverage note, not a failure.
                    flaky_api = tool_name == "crtsh" and bool(tools_used)  # crt.sh 5xx is a note
                    if "not installed" not in reason.lower() and not flaky_api:
                        failed_tools.add(tool_name)
                    stats["failed_runs"] = int(stats["failed_runs"]) + 1
                    note = (
                        f"{tool_name} ({root_domain}): {reason}"
                    )

                    notes.append(note)

                    ctx.coverage.record_skipped_check(
                        stage_def.stage_id,
                        f"{tool_name}:{root_domain}",
                        reason,
                    )

    else:

        reason = (
            "Subdomain enumeration skipped because "
            "include_subdomains is false or only CIDRs are configured"
        )

        notes.append(reason)

        for tool_name, _runner in enumeration_tools:

            ctx.coverage.record_skipped_check(
                stage_def.stage_id,
                tool_name,
                reason,
            )

    inventory = UnifiedEndpointInventory(ctx.workspace)

    assets: list[AssetRecord] = []

    max_urls = int(
        ctx.config.get(
            "limits",
            {},
        ).get(
            "max_urls_per_stage",
            2500,
        )
    )

    for host in sorted(candidate_hosts.keys())[:max_urls]:

        probe_url = f"{parsed_seed.scheme}://{host}"

        if (
            parsed_seed.scheme == "http"
            and seed_port != 80
        ) or (
            parsed_seed.scheme == "https"
            and seed_port != 443
        ):
            probe_url += f":{seed_port}"

        probe_url += "/"

        # Every enumerator result is DNS-validated and scope-checked here.
        decision = ctx.scope_engine.evaluate_url(
            probe_url,
            check_dns=check_dns,
        )

        if not decision.allowed:

            ctx.coverage.record_out_of_scope(
                stage_def.stage_id,
                probe_url,
                decision.reason,
            )

            continue

        resolved_ips = list(decision.resolved_ips)

        # In Docker the scanner has no DNS: the egress proxy resolves and validates IPs,
        # so an empty IP list is expected there and must not drop every host.
        if not resolved_ips and not _dns_delegated_to_proxy():

            ctx.coverage.record_out_of_scope(
                stage_def.stage_id,
                probe_url,
                "No DNS-validated IP address available",
            )

            continue

        sources = sorted(candidate_hosts[host])

        root_domain = next(
            (
                domain
                for domain in sorted(
                    ctx.scope_engine.policy.allowed_domains,
                    key=len,
                    reverse=True,
                )
                if (
                    host == domain
                    or host.endswith("." + domain)
                )
            ),
            host,
        )

        asset = AssetRecord(
            asset_id=make_asset_id(host),
            hostname=host,
            root_domain=root_domain,
            ip_addresses=resolved_ips,
            ports=[seed_port],
            in_scope=True,
            sources=sources,
        )

        assets.append(asset)

        inventory.upsert_asset(
            host,
            root_domain=root_domain,
            ip_addresses=resolved_ips,
            ports=[seed_port],
            source=sources[0],
            in_scope=True,
        )

        ctx.coverage.record_target_tested(
            stage_def.stage_id,
            decision.normalized_url,
        )

        ep = normalize_endpoint(
            decision.normalized_url,
            scope_engine=ctx.scope_engine,
            source=sources[0],
            check_dns=check_dns,
        )

        if ep is not None:

            for src in sources[1:]:
                ep.sources.append(src)

            inventory.upsert_endpoint(ep)

    inventory.save(stage_id=stage_def.stage_id)

    payload = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed_target": seed_url,
        "subfinder_used": "subfinder" in tools_used,  # legacy key, kept for compatibility
        "enumeration_tools_used": sorted(tools_used),
        "enumeration_tools": {
            name: {
                "attempts": int(stats["attempts"]),
                "successful_runs": int(stats["successful_runs"]),
                "failed_runs": int(stats["failed_runs"]),
                "partial_runs": int(stats["partial_runs"]),
                "discovered_hosts": len(stats["discovered_hosts"]),
            }
            for name, stats in sorted(tool_stats.items())
        },
        "notes": notes,
        "hosts": [
            asset.to_dict()
            for asset in assets
        ],
    }

    ctx.workspace.write_json_atomic(
        "discovery/subdomains.json",
        payload,
    )

    subdomains_not_requested = not (
        ctx.scope_engine.policy.include_subdomains
        and ctx.scope_engine.policy.allowed_domains
    )

    # A successful seed asset must not mask failed enumerators. The stage is
    # SUCCESS only when enumeration was not requested, or every attempted
    # enumerator completed without an execution/parse failure and at least one
    # in-scope asset was retained. Partial results remain usable downstream,
    # but the stage must be visibly PARTIAL.
    status = (
        StageStatus.SUCCESS
        if assets and (subdomains_not_requested or (attempted_tools and not failed_tools and not partial_tools))
        else StageStatus.PARTIAL
    )

    summary = (
        f"Enumerated {len(assets)} in-scope host(s) "
        f"using {', '.join(sorted(tools_used))}"
        if tools_used
        else
        "Seeded target host(s); subdomain enumeration was not requested"
        if subdomains_not_requested and assets
        else (
            f"Seeded {len(assets)} in-scope host(s) "
            "(all external enumeration tools unavailable/skipped)"
        )
    )

    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=summary,
        artifacts=[
            "discovery/subdomains.json",
            "inventory/unified_endpoints.json",
            "inventory/contributions/domain_enumeration.json",
        ],
        reusable_partial=(
            status == StageStatus.PARTIAL
            and not tools_used
            and all(
                "not installed" in note.lower()
                or "skipped because include_subdomains" in note.lower()
                or "only cidrs are configured" in note.lower()
                for note in notes
            )
        ),
        metrics={
            "targets_total": len(candidate_hosts),
            "targets_tested": len(assets),
            "targets_skipped": max(
                0,
                len(candidate_hosts) - len(assets),
            ),
            "enumeration_tools_used": len(tools_used),
            "enumeration_tools_attempted": len(attempted_tools),
            "enumeration_tools_failed": len(failed_tools),
            "enumeration_tools_failed_names": sorted(failed_tools),
            "enumeration_tools_partial": len(partial_tools),
            "enumeration_tools_partial_names": sorted(partial_tools),
        },
    )
