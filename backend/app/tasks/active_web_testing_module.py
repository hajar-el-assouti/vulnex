"""ActiveWebTestingModule: the ScanModule implementation for the active
web testing engine (slug "active_web_testing").

Runtime check for gates 2 and 4 of the five gates described on
Settings.active_web_testing_enabled (app/core/config.py). Gates 1
(is_enabled) and 3 (active_testing_confirmed) are already enforced
before this runs, by services/scan_modules.py and
services/scans.py::create_scan().

- Gate 2 (kill switch): `settings.active_web_testing_enabled` must be
  True. Otherwise the run FAILS with a clear reason, never a silent
  skip.
- Gate 4 (lab allowlist): the target's host:port must be in
  `settings.active_web_testing_lab_allowlist`, its own list, separate
  from the SSRF and port-scan allowlists.
- Gate 5 (SSRF + IP pinning) is enforced on every request by the
  engine (pinned_request.py) and by build_context's validation.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from app.core.config import get_settings
from app.engines.active_web_testing import engine as active_web_testing_engine
from app.engines.contracts import ModuleExecutionResult, ModuleExecutionStatus, ScanContext
from app.engines.recon.context import ReconBudget
from app.engines.recon.persistence import build_persisted_result
from app.engines.recon.security.scope_guard import ReconScopeError
from app.security.ssrf import SSRFValidationError

logger = logging.getLogger("app.tasks.active_web_testing_module")

SLUG = "active_web_testing"


def _target_host_port(target_base_url: str) -> str:
    """Normalizes a target's base URL to the "host:port" format used in
    `active_web_testing_lab_allowlist` (e.g. "192.168.56.102:3000").
    An explicit port is required in both; no default 80/443 is
    guessed."""
    parts = urlsplit(target_base_url)
    host = (parts.hostname or "").lower()
    port = parts.port
    if port is None:
        return host
    return f"{host}:{port}"


class ActiveWebTestingModule:
    slug = SLUG

    def run(self, context: ScanContext) -> ModuleExecutionResult:
        settings = get_settings()
        options = context.configuration.options

        # --- Gate #2: deployment-level kill switch, re-checked here at
        # run time, independent of the database row that already let
        # this module be selected. ---------------------------------
        if not settings.active_web_testing_enabled:
            logger.warning("ActiveWebTestingModule: refused -- active_web_testing_enabled is False")
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.FAILED,
                error=(
                    "active_web_testing is disabled at the deployment level "
                    "(Settings.active_web_testing_enabled=False) -- this is a separate switch "
                    "from the scan module's own enabled flag and must be explicitly turned on"
                ),
            )

        # --- Gate #4: strict, separate lab allowlist -- never
        # ssrf_lab_allowlist, never advanced_recon_network_lab_allowlist.
        lab_allowlist = {entry.lower() for entry in settings.active_web_testing_lab_allowlist}
        target_host_port = _target_host_port(context.target_base_url)
        if target_host_port not in lab_allowlist:
            logger.warning(
                "ActiveWebTestingModule: refused -- %s not in active_web_testing_lab_allowlist",
                target_host_port,
            )
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.FAILED,
                error=(
                    f"target {target_host_port!r} is not in active_web_testing_lab_allowlist -- "
                    "active testing is only ever permitted against explicitly authorized lab targets, "
                    "and this authorization is never inherited from any other allowlist"
                ),
            )

        target_is_authorized = bool(options.get("target_is_authorized", False))
        # Gate #4's own allowlist, passed through as this module's
        # `lab_hosts` -- used by build_context/pinned_request's SSRF
        # validation to permit this one private-lab address, exactly
        # like every other module's `ssrf_lab_allowlist`-sourced
        # `lab_hosts`, just sourced from the separate allowlist above.
        lab_hosts = frozenset(options.get("lab_hosts") or ())
        allow_private_networks = bool(settings.ssrf_allow_private_networks)

        budget = ReconBudget.start_now(
            total_timeout_seconds=settings.active_web_testing_total_timeout_seconds,
            request_timeout_seconds=settings.active_web_testing_request_timeout_seconds,
            max_requests=settings.active_web_testing_max_requests,
            max_response_bytes=settings.active_web_testing_max_response_bytes,
            max_metadata_response_bytes=settings.active_web_testing_max_response_bytes,
            max_redirects=settings.active_web_testing_max_redirects,
        )

        try:
            ctx = active_web_testing_engine.build_context(
                scan_id=str(context.scan_id),
                target_base_url=context.target_base_url,
                target_is_authorized=target_is_authorized,
                budget=budget,
                allow_private_networks=allow_private_networks,
                lab_hosts=lab_hosts,
                is_cancelled=context.cancellation.check,
            )
        except (ReconScopeError, SSRFValidationError) as exc:
            logger.warning("ActiveWebTestingModule: target rejected before testing: %s", exc)
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.FAILED,
                error=f"target rejected before any active testing: {exc.__class__.__name__}: {exc}",
            )

        if context.cancellation.check():
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled before active web testing started",
            )

        results, findings, entry_point_count = active_web_testing_engine.run_checks(
            ctx,
            settings=settings,
            max_response_bytes=settings.active_web_testing_max_response_bytes,
        )

        if context.cancellation.check():
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled during active web testing",
            )

        persisted = build_persisted_result(
            results, max_bytes=settings.active_web_testing_result_max_persisted_bytes
        )

        status_counts: dict[str, int] = {}
        for collector_result in results.values():
            status_counts[collector_result.status.value] = status_counts.get(collector_result.status.value, 0) + 1
        summary = (
            f"Active web testing finished: {entry_point_count} entry point(s) tested; "
            + ", ".join(f"{count} {status}" for status, count in sorted(status_counts.items()))
            + f"; {len(findings)} finding(s)"
        )

        return ModuleExecutionResult(
            status=ModuleExecutionStatus.COMPLETED,
            findings=[finding.to_dict() for finding in findings],
            summary=summary,
            result=persisted,
        )
