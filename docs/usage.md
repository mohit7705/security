# Usage and operational guide

## Installation

Supported runtime: Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Optional browser capture:

```bash
python -m pip install -e ".[browser]"
playwright install chromium
```

Check capabilities before scanning:

```bash
quiver doctor --profile core-only
quiver doctor --profile browser-enabled
quiver doctor --profile full-scanner
```

A ready `core-only` profile is not evidence that optional scanners or Chromium
are installed. Use `full-scanner` only after installing the external tools
required by the configured scanner profile.

## Scope and configuration

1. Edit `config/scope.yaml` with only explicitly authorized hosts, schemes,
   ports and paths.
2. Review `config/settings.yaml` and keep resource limits conservative.
3. For authentication, copy `config/auth_profiles.example.yaml` to
   `config/auth_profiles.yaml`, declare separate test identities and
   explicit owned resource IDs, and inject credentials through environment
   variables or a protected secret manager.
4. Never commit `.env`, `config/auth_profiles.yaml`, tokens, cookies, browser
   storage state, private keys or scan output.

Private/loopback targets require an explicit `allow_private_ips` scope
configuration and the relevant browser lab-mode setting. Do not enable those
settings for public assessments.

## CLI

```bash
quiver --version
quiver stages
quiver doctor --profile core-only

quiver scan \
  --target https://example.com \
  --scope config/scope.yaml \
  --settings config/settings.yaml

quiver resume --scan-id <scan_id>
quiver status --scan-id <scan_id>
quiver report --scan-id <scan_id>
```

For authenticated testing add `--auth-profiles config/auth_profiles.yaml`.
For selected-stage resume, repeat `--stage STAGE_ID`; transitive prerequisites
are included automatically.

`scan`, `resume`, `status` and `report` accept `--output-root`. Use the same
root for the lifetime of a scan, for example:

```bash
quiver scan --target https://example.com \
  --scope config/scope.yaml --output-root custom-scans
quiver status --scan-id <scan_id> --output-root custom-scans
quiver report --scan-id <scan_id> --output-root custom-scans
```

Exit codes: `0` successful completion, `2` partial completion or CLI/workspace
error, `1` failed scan or doctor readiness, and `130` cancellation. Read
`scan_state.json`, `coverage_summary.json` and the generated report; do not
infer full coverage from a zero exit code alone.

## Evidence, reports and retention

Each scan is stored under `<output-root>/<scan_id>/`. The report includes the
scope fingerprint, redacted configuration fingerprint, environment and
available tool versions, finding lifecycle groups, evidence integrity
results, and a coverage ledger.

The report distinguishes:
- Confirmed vulnerabilities.
- Confirmed configuration issues.
- Potential findings (`LIKELY`).
- Needs-human-review items (`NEEDS_HUMAN_REVIEW` and `INCONCLUSIVE`).
- Suppressed false positives.
- Incomplete stages, skipped checks, unprobed endpoints and unavailable tools.

Internal risk ranking is separate from CVSS. A CVSS v3.1 Base score is
calculated only when finding metadata contains a complete CVSS v3.1 vector.
Scanner severity labels are never converted into invented CVSS vectors.
CVSS v4.0 and Temporal/Environmental scoring are not implemented.

Cleanup is dry-run by default:

```bash
quiver cleanup --older-than-days 30
quiver cleanup --older-than-days 30 --execute
```

The cleanup audit log records candidates and deletions. Back up scan evidence
and authentication state using an approved protected backup process before
executing retention cleanup.

## Docker and CI

Review `deploy/README.md` before enabling host-level egress rules. Docker
Compose isolates the analyzer behind the scope-aware egress proxy; verify the
proxy is healthy before executing scans.

The GitHub workflow runs the automated suites, wheel build/install checks and
Docker/Compose smoke checks. An explicit manual workflow input is required to
run the optional local OWASP Juice Shop lab scan. CI never scans arbitrary
external targets and never uploads authentication state or secret folders.

## Benchmarking

- `scripts/benchmark_local.py` performs offline synthetic microbenchmarks.
- `scripts/benchmark_lab.py` scores a completed report against a versioned
  ground-truth manifest. It does not launch scanners or contact a target.

See `../benchmarks/README.md`. Publish lab metrics only with the target
application version, manifest, scope, tool/template versions and scan
configuration recorded.
