"""DiscoveryFuzzingModule: the ScanModule implementation for the
discovery & fuzzing engine (slug "discovery_fuzzing").

Same structure as active_web_testing_module.py, with its own settings.
Gates 1 (is_enabled) and 3 (requires_active_confirmation) are enforced
before this runs. This module checks:

- Gate 2 (kill switch): `settings.discovery_fuzzing_enabled` must be
  True.
- Gate 4 (lab allowlist): the target's host:port must be in
  `settings.discovery_fuzzing_lab_allowlist`.
- Gate 5 (SSRF + IP pinning) is enforced on every request by the
  engine (through pinned_request.py) and by build_context.

Only "quick" mode is accepted for now. "standard" and "deep" are
configured in app/core/config.py but refused here with a clear error,
until Quick has been validated against a real target.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from app.core.config import get_settings
from app.engines.contracts import ModuleExecutionResult, ModuleExecutionStatus, ScanContext
from app.engines.discovery_fuzzing import engine as discovery_fuzzing_engine
from app.engines.recon import engine as recon_engine
from app.engines.recon.context import ReconBudget
from app.engines.recon.persistence import build_persisted_result
from app.engines.recon.security.scope_guard import ReconScopeError
from app.security.ssrf import SSRFValidationError

logger = logging.getLogger("app.tasks.discovery_fuzzing_module")

SLUG = "discovery_fuzzing"

# Mirrors app/engines/discovery_fuzzing/wordlist.py's own MODE_SETTING_ATTR
# keys -- kept as a separate, explicit constant here (rather than
# importing and trusting that dict's keys blindly) so the "only quick
# is runnable" restriction is visible and grep-able at this module's
# own call site, not implied by what happens to exist elsewhere.
_RUNNABLE_MODES = frozenset({"quick"})


def _target_host_port(target_base_url: str) -> str:
    """Identical normalization to
    app/tasks/active_web_testing_module.py::_target_host_port -- kept
    as its own copy (not a shared import) because the two modules'
    allowlists are deliberately independent and must never be coupled
    through shared code that could later grow a shared default."""
    parts = urlsplit(target_base_url)
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is None:
        return host
    return f"{host}:{port}"


class DiscoveryFuzzingModule:
    slug = SLUG

    def run(self, context: ScanContext) -> ModuleExecutionResult:
        settings = get_settings()
        options = context.configuration.options

        # --- Gate #2: deployment-level kill switch. ------------------
        if not settings.discovery_fuzzing_enabled:
            logger.warning("DiscoveryFuzzingModule: refused -- discovery_fuzzing_enabled is False")
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.FAILED,
                error=(
                    "discovery_fuzzing is disabled at the deployment level "
                    "(Settings.discovery_fuzzing_enabled=False) -- this is a separate switch "
                    "from the scan module's own enabled flag and must be explicitly turned on"
                ),
            )

        # --- Gate #4: strict, separate lab allowlist. -----------------
        lab_allowlist = {entry.lower() for entry in settings.discovery_fuzzing_lab_allowlist}
        target_host_port = _target_host_port(context.target_base_url)
        if target_host_port not in lab_allowlist:
            logger.warning(
                "DiscoveryFuzzingModule: refused -- %s not in discovery_fuzzing_lab_allowlist",
                target_host_port,
            )
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.FAILED,
                error=(
                    f"target {target_host_port!r} is not in discovery_fuzzing_lab_allowlist -- "
                    "path discovery is only ever permitted against explicitly authorized lab "
                    "targets, and this authorization is never inherited from any other allowlist"
                ),
            )

        mode = str(options.get("mode") or "quick")
        if mode not in _RUNNABLE_MODES:
            logger.warning("DiscoveryFuzzingModule: refused -- mode %r is not runnable yet", mode)
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.FAILED,
                error=(
                    f"discovery_fuzzing mode {mode!r} is prepared in configuration but not yet "
                    "runnable -- only 'quick' is accepted for now"
                ),
            )

        target_is_authorized = bool(options.get("target_is_authorized", False))
        lab_hosts = frozenset(options.get("lab_hosts") or ())
        allow_private_networks = bool(settings.ssrf_allow_private_networks)

        budget = ReconBudget.start_now(
            total_timeout_seconds=settings.discovery_fuzzing_total_timeout_seconds,
            request_timeout_seconds=settings.discovery_fuzzing_request_timeout_seconds,
            max_requests=settings.discovery_fuzzing_max_requests,
            max_response_bytes=settings.discovery_fuzzing_max_response_bytes,
            max_metadata_response_bytes=settings.discovery_fuzzing_max_response_bytes,
            max_redirects=settings.discovery_fuzzing_max_redirects,
        )

        try:
            ctx = recon_engine.build_context(
                scan_id=str(context.scan_id),
                target_base_url=context.target_base_url,
                target_is_authorized=target_is_authorized,
                budget=budget,
                allow_private_networks=allow_private_networks,
                lab_hosts=lab_hosts,
                is_cancelled=context.cancellation.check,
            )
        except (ReconScopeError, SSRFValidationError) as exc:
            logger.warning("DiscoveryFuzzingModule: target rejected before testing: %s", exc)
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.FAILED,
                error=f"target rejected before any path discovery: {exc.__class__.__name__}: {exc}",
            )

        if context.cancellation.check():
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled before discovery/fuzzing started",
            )

        collector_result, findings = discovery_fuzzing_engine.run_discovery(
            ctx, settings=settings, scan_id=str(context.scan_id), mode=mode
        )

        if context.cancellation.check():
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled during discovery/fuzzing",
            )

        results = {discovery_fuzzing_engine.SLUG: collector_result}
        persisted = build_persisted_result(
            results, max_bytes=settings.discovery_fuzzing_result_max_persisted_bytes
        )

        paths_tested = len(collector_result.observations)
        type_counts: dict[str, int] = {}
        for observation in collector_result.observations:
            obs_type = observation.value.get("observation_type", "unknown")
            type_counts[obs_type] = type_counts.get(obs_type, 0) + 1
        summary = (
            f"Discovery/fuzzing ({mode}) finished: {paths_tested} path(s) tested; "
            + ", ".join(f"{count} {obs_type}" for obs_type, count in sorted(type_counts.items()))
        )

        return ModuleExecutionResult(
            status=ModuleExecutionStatus.COMPLETED,
            findings=findings,
            summary=summary,
            result=persisted,
        )
