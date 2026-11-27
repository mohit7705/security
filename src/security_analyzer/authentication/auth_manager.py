from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_analyzer.authentication.identity_context import (
    AuthMethod,
    IdentityContext,
    load_auth_profiles,
)
from security_analyzer.authentication.session_manager import SessionManager
from security_analyzer.authentication.storage_state_store import StorageStateStore
from security_analyzer.core.coverage_tracker import CoverageTracker
from security_analyzer.core.exceptions import ConfigurationError
from security_analyzer.core.orchestrator import ExecutionContext
from security_analyzer.core.scope_engine import ScopeEngine
from security_analyzer.core.resource_governor import ResourceGovernor
from security_analyzer.core.stage_registry import StageDefinition, StageResult, StageStatus


class AuthManager:
    """Coordinates isolated identity contexts across HTTP clients and Playwright browser contexts."""

    def __init__(
        self,
        *,
        scope_engine: ScopeEngine,
        project_root: Path,
        scan_id: str,
        default_target_url: str,
        coverage: CoverageTracker | None = None,
        auth_profiles_path: Path | None = None,
        resource_governor: ResourceGovernor | None = None,
    ) -> None:
        self.scope_engine = scope_engine
        self.default_target_url = default_target_url
        self.coverage = coverage
        self.store = StorageStateStore(project_root=project_root, scan_id=scan_id)
        self.session_manager = SessionManager(
            scope_engine,
            self.store,
            coverage=coverage,
            default_target_url=default_target_url,
            resource_governor=resource_governor,
        )
        self.profiles, self.verify_logout = load_auth_profiles(auth_profiles_path)
        self._contexts: dict[str, IdentityContext] = {}

    def initialize_all(self, *, stage_id: str = "auth_session_lifecycle") -> dict[str, Any]:
        is_https = self.default_target_url.lower().startswith("https://")
        lifecycle_records: list[dict[str, Any]] = []

        for ident_id, profile in self.profiles.items():
            try:
                ctx = self.session_manager.establish_context(profile, stage_id=stage_id)
            except Exception as exc:
                ctx = IdentityContext(
                    identity_id=ident_id,
                    resource_governor=self.session_manager.resource_governor,
                    role=profile.role,
                    auth_method=profile.auth_method,
                    authenticated=False,
                    session_valid=False,
                    notes=[f"Authentication setup failed: {type(exc).__name__}"],
                )
                self._contexts[ident_id] = ctx
                lifecycle_records.append(
                    {
                        "identity": ctx.redacted_summary(),
                        "validation": {
                            "identity_id": ident_id,
                            "checked": False,
                            "state": "configuration_error",
                            "session_valid": False,
                        },
                        "cookie_security_issues": [],
                        "logout_invalidation": {"tested": False, "reason": "identity_setup_failed"},
                    }
                )
                continue
            self._contexts[ident_id] = ctx

            validation = self.session_manager.validate_session(profile, ctx, stage_id=stage_id, auto_refresh=True)
            if validation.get("state") not in {"anonymous", "not_configured"}:
                ctx.status = str(validation.get("state", ctx.status))
            if profile.auth_method == AuthMethod.COOKIE_SESSION:
                # Cookie flags are synthesized from config, not observed from the server.
                cookie_audit = []
                ctx.notes.append("Cookie flag audit skipped: flags are not observable for configured cookies")
            else:
                cookie_audit = self.store.audit_cookie_security(ctx.cookies, is_https=is_https)

            logout_result: dict[str, Any] = {"tested": False, "reason": "disabled_by_policy"}
            if self.verify_logout and profile.auth_method != AuthMethod.ANONYMOUS and profile.logout_url:
                logout_result = self.session_manager.verify_logout_invalidation(profile, ctx, stage_id=stage_id)
                # Re-establish clean active session after logout test so downstream stages have a live token
                if logout_result.get("server_invalidated_session"):
                    if profile.auth_method == AuthMethod.API_LOGIN:
                        ctx = self.session_manager.establish_context(profile, stage_id=stage_id)
                    else:
                        # The configured token/cookie/state is now revoked and cannot be recreated.
                        ctx.session_valid = False
                        ctx.authenticated = False
                        ctx.status = "revoked_by_logout_test"
                        ctx.notes.append(
                            "Credential revoked by the logout test; supply a fresh one or disable verify_logout_invalidation"
                        )
                    self._contexts[ident_id] = ctx

            lifecycle_records.append(
                {
                    "identity": ctx.redacted_summary(),
                    "validation": validation,
                    "cookie_security_issues": cookie_audit,
                    "logout_invalidation": logout_result,
                }
            )

        return {
            "total_identities": len(self._contexts),
            "authenticated_identities": sum(1 for c in self._contexts.values() if c.authenticated),
            "records": lifecycle_records,
        }

    def get_context(self, identity_id: str = "anonymous") -> IdentityContext:
        if identity_id not in self._contexts:
            if identity_id in self.profiles:
                self._contexts[identity_id] = self.session_manager.establish_context(self.profiles[identity_id])
            else:
                raise ConfigurationError(f"Unknown identity_id: {identity_id!r}")
        return self._contexts[identity_id]

    def list_identities(self) -> list[str]:
        return list(self._contexts.keys()) or list(self.profiles.keys())


def run_auth_session_lifecycle(ctx: ExecutionContext, stage_def: StageDefinition) -> StageResult:
    """Establishes and validates isolated identity contexts and writes sanitized telemetry to ./output/<scan_id>/."""
    auth_path_str = str(ctx.config.get("auth_profiles_path", "")).strip()
    auth_path = Path(auth_path_str) if auth_path_str else None

    manager = AuthManager(
        scope_engine=ctx.scope_engine,
        project_root=ctx.workspace.project_root,
        scan_id=ctx.workspace.scan_id or "default",
        default_target_url=ctx.target,
        coverage=ctx.coverage,
        auth_profiles_path=auth_path,
        resource_governor=ctx.resource_governor,
    )
    ctx.auth_manager = manager

    audit_summary = manager.initialize_all(stage_id=stage_def.stage_id)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "scan_id": ctx.workspace.scan_id,
        "stage_id": stage_def.stage_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_identities": audit_summary["total_identities"],
        "authenticated_identities": audit_summary["authenticated_identities"],
        "records": audit_summary["records"],
    }
    ctx.workspace.write_json_atomic("analysis/auth_sessions.json", payload)

    failed_auth = [
        record
        for record in audit_summary["records"]
        if record["identity"]["auth_method"] != "anonymous"
        and not (
            bool(record["identity"].get("authenticated"))
            and bool(record["identity"].get("session_valid"))
        )
    ]
    status = StageStatus.PARTIAL if failed_auth else StageStatus.SUCCESS
    non_anonymous = [r for r in audit_summary["records"] if r["identity"]["auth_method"] != "anonymous"]
    unverified = [
        r["identity"]["identity_id"]
        for r in non_anonymous
        if r not in failed_auth and r["validation"].get("state") == "not_configured"
    ]
    if not non_anonymous:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id,
            "authenticated_identities",
            "No authenticated identities configured; authorization/IDOR and business-logic coverage will be limited",
        )
    for identity_id in unverified:
        ctx.coverage.record_skipped_check(
            stage_def.stage_id,
            f"session_validation:{identity_id}",
            "whoami_url not configured; session validity was not verified",
        )
    return StageResult(
        stage_id=stage_def.stage_id,
        status=status,
        summary=(
            f"Initialized {audit_summary['total_identities']} identity context(s) "
            f"({audit_summary['authenticated_identities']} authenticated, {len(failed_auth)} failed"
            + (", no authenticated identities configured" if not non_anonymous else "")
            + (f", {len(unverified)} unverified" if unverified else "")
            + ")"
        ),
        artifacts=["analysis/auth_sessions.json"],
        metrics={
            "targets_total": audit_summary["total_identities"],
            "targets_tested": audit_summary["total_identities"] - len(failed_auth),
            "targets_skipped": len(failed_auth),
        },
    )