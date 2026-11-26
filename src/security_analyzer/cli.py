from __future__ import annotations

import argparse
import importlib.metadata
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any

from security_analyzer.core.exceptions import SecurityAnalyzerError
from security_analyzer.core.stage_registry import STAGE_DEFINITIONS
from security_analyzer.core.workspace import WorkspaceManager
from security_analyzer.main import execute_scan, load_settings, resume_scan, run_doctor
from security_analyzer.utils.redaction import scrub_text


def _version() -> str:
    try:
        return importlib.metadata.version("security-analyzer")
    except importlib.metadata.PackageNotFoundError:
        return "0.1.0"


def _prog_name() -> str:
    invoked = Path(sys.argv[0]).name if sys.argv and sys.argv[0] else ""
    if invoked in {"quiver", "attack", "security-analyzer"}:
        return invoked
    return "quiver"


def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-u",
        "--target",
        required=True,
        help="Seed target URL to assess (e.g. https://app.example.com)",
    )
    parser.add_argument(
        "-s",
        "--scope",
        type=Path,
        default=Path("config/scope.yaml"),
        help="Authorized scope policy YAML/JSON file (default: config/scope.yaml)",
    )
    parser.add_argument(
        "--settings",
        type=Path,
        default=Path("config/settings.yaml"),
        help="Pipeline settings and rate-limit config (default: config/settings.yaml)",
    )
    parser.add_argument(
        "--auth-profiles",
        type=Path,
        default=None,
        help="Optional authenticated session/token profiles for multi-role IDOR & JWT checks",
    )
    parser.add_argument(
        "--output-root",
        default=None,
        help="Directory where scan workspaces are stored (default: output)",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        metavar="BASELINE_SCAN_ID",
        help="Prior scan ID to diff new subdomains, endpoints, ports, and findings against",
    )


def build_parser() -> argparse.ArgumentParser:
    description = (
        "Quiver — Scope-enforced, evidence-driven web application security pipeline.\n\n"
        "What Quiver can do:\n"
        "  1. Asset & Subdomain Recon   : Passive/active domain discovery & dangling CNAME takeover checks\n"
        "  2. Endpoint & JS Discovery   : Deduplicated path probing, headless browser crawl, OpenAPI/JS secret mining\n"
        "  3. Auth & Session Auditing   : Multi-role IDOR/BOLA matrix, token refresh, and JWT security checks\n"
        "  4. Non-Destructive Probing   : Read-only parameter reflection/redirect canaries, TLS & security headers\n"
        "  5. Verification & Reporting  : SHA-256 evidence hashing, deduplication, baseline diffing & JSON/MD/HTML reports"
    )
    epilog = (
        "How to run:\n"
        "  quiver -u https://example.com/                         Quick scan (scope defaults to config/scope.yaml)\n"
        "  quiver -u https://example.com/ -s config/scope.yaml    Quick scan with an explicit scope file\n"
        "  quiver https://example.com/                            Bare URL shorthand\n"
        "  Docker: alias quiver='docker compose exec security-analyzer quiver'  then use the same commands\n"
        "\n"
        "Options for a scan:\n"
        "  -u, --target URL        Target to assess (must be inside the scope file)\n"
        "  -s, --scope FILE        Authorized scope policy (default: config/scope.yaml)\n"
        "      --settings FILE     Pipeline settings (default: config/settings.yaml)\n"
        "      --auth-profiles F   Authenticated test identities for IDOR/authorization checks\n"
        "      --output-root DIR   Where scan results are stored (default: output)\n"
        "      --baseline SCAN_ID  Compare against an earlier scan\n"
        "\n"
        "Other commands:\n"
        "  quiver -h | --help | -help                             Show this help message\n"
        "  quiver -v | --version                                  Show the version\n"
        "  quiver scan --target https://example.com --scope config/scope.yaml   (same as 'attack')\n"
        "  quiver resume --scan-id <SCAN_ID> --stage consolidated_reporting\n"
        "  quiver status --scan-id <SCAN_ID>                      Progress and coverage\n"
        "  quiver report --scan-id <SCAN_ID>                      Regenerate JSON/MD/HTML reports\n"
        "  quiver diff --scan-id <NEW_SCAN_ID> --baseline <OLD_SCAN_ID>\n"
        "  quiver stages                                          List all pipeline stages & dependencies\n"
        "  quiver doctor --profile full-scanner                   Verify installed tools & environment\n"
        "  quiver cleanup --older-than-days 30 [--execute]        Delete old scans (dry run by default)\n"
        "\n"
        "Reports are written to output/<scan_id>/reports/ (security_report.html / .md / .json).\n"
        "Only scan systems you are explicitly authorized to test."
    )
    parser = argparse.ArgumentParser(
        prog=_prog_name(),
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"quiver {_version()}",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    doctor_p = sub.add_parser(
        "doctor",
        help="Validate configuration, proxy settings, and external tool readiness",
    )
    doctor_p.add_argument(
        "--profile",
        choices=("core-only", "browser-enabled", "full-scanner"),
        default="core-only",
    )
    doctor_p.add_argument(
        "--settings",
        type=Path,
        default=Path("config/settings.yaml"),
    )

    attack_p = sub.add_parser(
        "attack",
        help="Start a new authorized security assessment against --target",
    )
    _add_scan_arguments(attack_p)

    scan_p = sub.add_parser(
        "scan",
        help="Alias for 'attack' to start a new authorized assessment",
    )
    _add_scan_arguments(scan_p)

    resume_p = sub.add_parser(
        "resume",
        help="Resume an existing scan; selected stages automatically include prerequisites",
    )
    resume_p.add_argument("--scan-id", required=True)
    resume_p.add_argument("--scope", type=Path, default=Path("config/scope.yaml"))
    resume_p.add_argument("--settings", type=Path, default=Path("config/settings.yaml"))
    resume_p.add_argument("--auth-profiles", type=Path, default=None)
    resume_p.add_argument("--output-root", default=None)
    resume_p.add_argument(
        "--baseline",
        default=None,
        metavar="BASELINE_SCAN_ID",
        help="Optional prior scan ID to diff new subdomains, endpoints, ports, and findings against",
    )
    resume_p.add_argument(
        "--stage",
        action="append",
        default=[],
        metavar="STAGE_ID",
        help="Run a stage and all of its transitive prerequisites; repeatable",
    )

    status_p = sub.add_parser(
        "status",
        help="Show scan stage states, metrics, and coverage summary",
    )
    status_p.add_argument("--scan-id", required=True)
    status_p.add_argument("--settings", type=Path, default=Path("config/settings.yaml"))
    status_p.add_argument("--output-root", default=None)

    report_p = sub.add_parser(
        "report",
        help="Regenerate JSON, Markdown, and HTML reports from scan artifacts",
    )
    report_p.add_argument("--scan-id", required=True)
    report_p.add_argument("--settings", type=Path, default=Path("config/settings.yaml"))
    report_p.add_argument("--output-root", default=None)
    report_p.add_argument(
        "--baseline",
        default=None,
        metavar="BASELINE_SCAN_ID",
        help="Optional prior scan ID to compute continuous-monitoring deltas in the report",
    )

    diff_p = sub.add_parser(
        "diff",
        help="Compare a scan against a baseline scan to detect newly exposed assets and findings",
    )
    diff_p.add_argument("--scan-id", required=True)
    diff_p.add_argument("--baseline", required=True, metavar="BASELINE_SCAN_ID")
    diff_p.add_argument("--settings", type=Path, default=Path("config/settings.yaml"))
    diff_p.add_argument("--output-root", default=None)

    cleanup_p = sub.add_parser(
        "cleanup",
        help="Delete expired scan data and secrets (dry run unless --execute)",
    )
    cleanup_p.add_argument("--older-than-days", type=int, required=True)
    cleanup_p.add_argument("--output-root", default="output")
    cleanup_p.add_argument("--secrets-root", default="secrets")
    cleanup_p.add_argument(
        "--execute",
        action="store_true",
        help="Actually delete. Without this flag nothing is removed.",
    )

    sub.add_parser(
        "stages",
        help="List all registered pipeline stages and their dependencies",
    )

    return parser


def _workspace_for_scan(
    scan_id: str,
    settings_path: Path,
    output_root: str | None,
) -> WorkspaceManager:
    settings = load_settings(settings_path)
    selected_root = output_root or str(settings.get("output_root", "output"))
    workspace = WorkspaceManager(output_root_name=selected_root)
    workspace.load_scan(scan_id)
    return workspace


def _build_report_payload(
    workspace: WorkspaceManager,
    baseline_scan_id: str | None = None,
) -> dict[str, Any]:
    from security_analyzer.reporting import ReportBuilder

    sig = inspect.signature(ReportBuilder.__init__)
    if "baseline_scan_id" in sig.parameters:
        return ReportBuilder(
            workspace,
            baseline_scan_id=baseline_scan_id,
        ).build()
    return ReportBuilder(workspace).build()


def _run_status(args: argparse.Namespace) -> int:
    workspace = _workspace_for_scan(
        args.scan_id,
        args.settings,
        args.output_root,
    )
    state = workspace.read_json("scan_state.json")
    coverage = (
        workspace.read_json("coverage_summary.json")
        if workspace.coverage_file.is_file()
        else {}
    )
    print(
        json.dumps(
            {
                "scan_id": workspace.scan_id,
                "scan_dir": str(workspace.scan_dir),
                "overall_status": state.get("overall_status", "UNKNOWN"),
                "state": state,
                "coverage": coverage,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _run_report(args: argparse.Namespace) -> int:
    from security_analyzer.reporting import (
        HtmlRenderer,
        MarkdownRenderer,
    )

    workspace = _workspace_for_scan(
        args.scan_id,
        args.settings,
        args.output_root,
    )
    baseline_id = getattr(args, "baseline", None)
    if not baseline_id and workspace.state_file.is_file():
        state = workspace.read_json("scan_state.json")
        baseline_id = str(state.get("baseline_scan_id") or "").strip() or None
    if baseline_id:
        _workspace_for_scan(
            baseline_id,
            args.settings,
            args.output_root,
        )

    payload = _build_report_payload(
        workspace,
        baseline_scan_id=baseline_id,
    )
    workspace.write_json_atomic(
        "reports/security_report.json",
        payload,
    )
    workspace.write_text_atomic(
        "reports/security_report.md",
        MarkdownRenderer().render(payload),
    )
    workspace.write_text_atomic(
        "reports/security_report.html",
        HtmlRenderer().render(payload),
    )
    print(
        json.dumps(
            {
                "scan_id": workspace.scan_id,
                "baseline_scan_id": baseline_id,
                "reports": [
                    "reports/security_report.json",
                    "reports/security_report.md",
                    "reports/security_report.html",
                ],
                "summary": payload.get("summary", {}),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _run_diff(args: argparse.Namespace) -> int:
    workspace = _workspace_for_scan(
        args.scan_id,
        args.settings,
        args.output_root,
    )
    _workspace_for_scan(
        args.baseline,
        args.settings,
        args.output_root,
    )
    payload = _build_report_payload(
        workspace,
        baseline_scan_id=args.baseline,
    )
    diff_section = payload.get("baseline_diff", {})
    workspace.write_json_atomic(
        "reports/baseline_diff.json",
        diff_section,
    )
    print(
        json.dumps(
            {
                "scan_id": workspace.scan_id,
                "baseline_scan_id": args.baseline,
                "artifact": "reports/baseline_diff.json",
                "baseline_diff": diff_section,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _run_stages() -> int:
    payload: list[dict[str, Any]] = []
    for definition in STAGE_DEFINITIONS:
        payload.append(
            {
                "stage_id": definition.stage_id,
                "title": definition.title,
                "phase": definition.phase,
                "dependencies": list(definition.dependencies),
                "optional_dependencies": list(definition.optional_dependencies),
                "artifacts": [
                    artifact.relative_path
                    for artifact in definition.artifacts
                ],
            }
        )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _install_cancel_handlers() -> None:
    """Convert SIGTERM into an interrupt handled by the pipeline orchestrator."""
    import signal
    import threading

    if threading.current_thread() is not threading.main_thread():
        return

    def raise_interrupt(_signum, _frame):
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, raise_interrupt)
    except (ValueError, OSError):
        pass


def _normalize_argv(argv: list[str] | None) -> list[str]:
    invoked = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    raw = list(sys.argv[1:] if argv is None else argv)

    # Accept the single-dash spelling `quiver -help` as an alias for --help.
    raw = ["--help" if item == "-help" else item for item in raw]

    # Support direct `attack --target ...` or `attack -h` invocation without repeating `attack`.
    if invoked == "attack" and (
        not raw
        or raw[0] not in {
            "doctor",
            "scan",
            "attack",
            "resume",
            "status",
            "report",
            "diff",
            "cleanup",
            "stages",
        }
    ):
        return ["attack", *raw]

    # Support bare URL shorthand: `quiver https://example.com --scope ...`.
    if raw and not raw[0].startswith("-") and raw[0] not in {
        "doctor",
        "scan",
        "attack",
        "resume",
        "status",
        "report",
        "diff",
        "cleanup",
        "stages",
    }:
        return ["attack", "--target", *raw]

    # Support flag-first shorthand: `quiver -u https://example.com -s config/scope.yaml`.
    if raw and raw[0].startswith("-") and raw[0] not in {"-h", "--help", "-v", "--version"}:
        return ["attack", *raw]

    return raw


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    normalized_argv = _normalize_argv(argv)
    args = parser.parse_args(normalized_argv)

    if args.command in {"scan", "attack", "resume"}:
        _install_cancel_handlers()

    try:
        if args.command == "doctor":
            report = run_doctor(
                profile=args.profile,
                settings_path=args.settings,
            )
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if report["ready"] else 1

        if args.command in {"scan", "attack"}:
            code, state = execute_scan(
                target=args.target,
                scope_path=args.scope,
                settings_path=args.settings,
                auth_profiles_path=args.auth_profiles,
                output_root=args.output_root,
                baseline_scan_id=args.baseline,
            )
            print(json.dumps(state, indent=2, sort_keys=True))
            return code

        if args.command == "resume":
            requested_stages = set(args.stage) if args.stage else None
            code, state = resume_scan(
                scan_id=args.scan_id,
                scope_path=args.scope,
                settings_path=args.settings,
                auth_profiles_path=args.auth_profiles,
                only_stages=requested_stages,
                output_root=args.output_root,
                baseline_scan_id=args.baseline,
            )
            print(json.dumps(state, indent=2, sort_keys=True))
            return code

        if args.command == "status":
            return _run_status(args)

        if args.command == "report":
            return _run_report(args)

        if args.command == "diff":
            return _run_diff(args)

        if args.command == "cleanup":
            from security_analyzer.core.retention import cleanup_expired

            summary = cleanup_expired(
                Path(args.output_root),
                Path(args.secrets_root),
                args.older_than_days,
                execute=args.execute,
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0

        if args.command == "stages":
            return _run_stages()

        parser.error(f"Unsupported command: {args.command}")
        return 2

    except SecurityAnalyzerError as exc:
        print(
            json.dumps(
                {
                    "error": scrub_text(str(exc)),
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {
                    "error": scrub_text(str(exc)),
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())