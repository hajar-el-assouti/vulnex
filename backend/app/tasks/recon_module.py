"""ReconModule: connects the recon engine (app/engines/recon) to the
scan orchestration.

Registered in scan_tasks.py::_RUNNABLE_MODULES under "recon". The
ScanModule run() signature is fixed and synchronous, so everything
else it needs (target authorization, private-network setting, lab
allowlist, Postgres-backed history provider) is prepared by the async
Celery task and passed through ScanConfiguration.options. This module
never queries Postgres and never checks authorization itself."""

from __future__ import annotations

import logging

from app.core.config import get_settings
from app.engines.contracts import ModuleExecutionResult, ModuleExecutionStatus, ScanContext
from app.engines.recon import engine as recon_engine
from app.engines.recon.context import ReconBudget
from app.engines.recon.fingerprint import NullHistoryProvider
from app.engines.recon.persistence import build_persisted_result
from app.engines.recon.security.scope_guard import ReconScopeError
from app.security.ssrf import SSRFValidationError

logger = logging.getLogger("app.tasks.recon_module")

SLUG = "recon"


class ReconModule:
    """Implements the ScanModule protocol (structurally -- see
    app/engines/contracts.py's @runtime_checkable ScanModule), the same
    way DiagnosticModule does."""

    slug = SLUG

    def run(self, context: ScanContext) -> ModuleExecutionResult:
        settings = get_settings()
        options = context.configuration.options

        target_is_authorized = bool(options.get("target_is_authorized", False))
        lab_hosts = frozenset(options.get("lab_hosts") or ())
        # Both halves of the lab-mode opt-in must be true for this
        # deployment AND the target must be in the allowlist above --
        # see app/security/ssrf.py's own "never a blanket trust-all"
        # docstring and Settings.ssrf_allow_private_networks.
        allow_private_networks = bool(settings.ssrf_allow_private_networks)
        history_provider = options.get("history_provider") or NullHistoryProvider()
        target_id = options.get("target_id")
        user_id = options.get("user_id")

        budget = ReconBudget.start_now(
            total_timeout_seconds=settings.recon_total_timeout_seconds,
            request_timeout_seconds=settings.recon_request_timeout_seconds,
            max_requests=settings.recon_max_requests,
            max_response_bytes=settings.recon_max_response_bytes,
            max_metadata_response_bytes=settings.recon_max_metadata_response_bytes,
            max_redirects=settings.recon_max_redirects,
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
            # Rejected before a single collector ran -- never a crash,
            # never a fabricated partial result for a target that was
            # never actually reachable/authorized in the first place.
            logger.warning("ReconModule: target rejected before collection: %s", exc)
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.FAILED,
                error=f"target rejected before any collection: {exc.__class__.__name__}: {exc}",
            )

        if context.cancellation.check():
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled before Recon collection started",
            )

        results = recon_engine.run_collectors(
            ctx,
            max_response_bytes=settings.recon_max_response_bytes,
            max_metadata_response_bytes=settings.recon_max_metadata_response_bytes,
            history_provider=history_provider,
            target_id=target_id,
            module_slug=SLUG,
            user_id=user_id,
            run_id=str(context.scan_module_run_id),
        )

        if context.cancellation.check():
            # The budget's own global deadline (recon_total_timeout_seconds)
            # already bounds how long collection could have run even if
            # this check is only made once, here, after collection
            # returns -- see ReconModule's module docstring and
            # app/models/scan.py's own "best-effort / eventually-
            # consistent" cancellation philosophy, which this module
            # does not change.
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled during Recon collection",
            )

        persisted = build_persisted_result(results, max_bytes=settings.recon_result_max_persisted_bytes)

        status_counts: dict[str, int] = {}
        for collector_result in results.values():
            status_counts[collector_result.status.value] = status_counts.get(collector_result.status.value, 0) + 1
        summary = "Recon collection finished: " + ", ".join(
            f"{count} {status}" for status, count in sorted(status_counts.items())
        )

        return ModuleExecutionResult(
            status=ModuleExecutionStatus.COMPLETED,
            findings=[],  # Recon produces observations, never findings -- see app/engines/recon/schemas.py
            summary=summary,
            result=persisted,
        )
