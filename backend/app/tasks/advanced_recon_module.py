"""AdvancedReconModule: the ScanModule implementation for advanced
reconnaissance (ports/services, WAF/CDN detection, visual snapshot).
Deep TLS is part of tls_collector.py.

Separate slug ("advanced_recon"). Like recon_module.py, it never
queries Postgres or checks authorization itself; scan_tasks.py does
both before calling it."""

from __future__ import annotations

import logging

from app.core.config import get_settings
from app.engines.contracts import ModuleExecutionResult, ModuleExecutionStatus, ScanContext
from app.engines.recon import advanced_engine
from app.engines.recon import engine as recon_engine
from app.engines.recon.context import ReconBudget
from app.engines.recon.fingerprint import NullHistoryProvider
from app.engines.recon.persistence import build_persisted_result
from app.engines.recon.security.scope_guard import ReconScopeError
from app.security.ssrf import SSRFValidationError

logger = logging.getLogger("app.tasks.advanced_recon_module")

SLUG = "advanced_recon"


class AdvancedReconModule:
    slug = SLUG

    def run(self, context: ScanContext) -> ModuleExecutionResult:
        settings = get_settings()
        options = context.configuration.options

        target_is_authorized = bool(options.get("target_is_authorized", False))
        # HTTP-facing SSRF lab allowlist -- used ONLY to validate the
        # target's own base_url (recon_engine.build_context does an
        # HTTP(S) SSRF check, same as the "recon" module), never to
        # authorize any port-scan connection. See network_lab_hosts
        # below for the latter's entirely separate allowlist.
        lab_hosts = frozenset(options.get("lab_hosts") or ())
        allow_private_networks = bool(settings.ssrf_allow_private_networks)

        # The port scan's own authorization inputs, never derived from
        # lab_hosts/allow_private_networks above: network and HTTP
        # authorizations stay separate.
        allowed_ports = list(
            options.get("allowed_ports") or settings.advanced_recon_default_allowed_ports
        )
        network_lab_hosts = frozenset(options.get("network_lab_hosts") or ())
        allow_private_network_scan = bool(settings.advanced_recon_allow_private_network_scan)

        # Postgres-backed fingerprint history, built by the async Celery
        # task before this module runs, like ReconModule. Falls back to
        # NullHistoryProvider when something is missing (e.g. in tests).
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
            logger.warning("AdvancedReconModule: target rejected before collection: %s", exc)
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.FAILED,
                error=f"target rejected before any collection: {exc.__class__.__name__}: {exc}",
            )

        if context.cancellation.check():
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled before advanced recon collection started",
            )

        results = advanced_engine.run_advanced_collectors(
            ctx,
            allowed_ports=allowed_ports,
            allow_private_network_scan=allow_private_network_scan,
            network_lab_hosts=network_lab_hosts,
            max_response_bytes=settings.recon_max_response_bytes,
            visual_snapshot_enabled=settings.advanced_recon_visual_snapshot_enabled,
            history_provider=history_provider,
            target_id=target_id,
            module_slug=SLUG,
            user_id=user_id,
            run_id=str(context.scan_module_run_id),
        )

        if context.cancellation.check():
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled during advanced recon collection",
            )

        persisted = build_persisted_result(results, max_bytes=settings.recon_result_max_persisted_bytes)

        status_counts: dict[str, int] = {}
        for collector_result in results.values():
            status_counts[collector_result.status.value] = status_counts.get(collector_result.status.value, 0) + 1
        summary = "Advanced recon collection finished: " + ", ".join(
            f"{count} {status}" for status, count in sorted(status_counts.items())
        )

        return ModuleExecutionResult(
            status=ModuleExecutionStatus.COMPLETED,
            findings=[],
            summary=summary,
            result=persisted,
        )
