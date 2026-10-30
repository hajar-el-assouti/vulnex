"""WebVulnAssessmentModule: the ScanModule implementation for the web
vulnerability assessment engine (slug "web_vuln_assessment").

Like the recon modules, it never queries Postgres or checks
authorization itself; scan_tasks.py does that before calling it.

Unlike them, it returns real findings in
`ModuleExecutionResult.findings` (via Finding.to_dict()), which
scan_tasks.py saves through app/services/findings.py."""

from __future__ import annotations

import logging

from app.core.config import get_settings
from app.engines.contracts import ModuleExecutionResult, ModuleExecutionStatus, ScanContext
from app.engines.recon.context import ReconBudget
from app.engines.recon.persistence import build_persisted_result
from app.engines.recon.security.scope_guard import ReconScopeError
from app.engines.web_vuln import engine as web_vuln_engine
from app.security.ssrf import SSRFValidationError

logger = logging.getLogger("app.tasks.web_vuln_module")

SLUG = "web_vuln_assessment"


class WebVulnAssessmentModule:
    slug = SLUG

    def run(self, context: ScanContext) -> ModuleExecutionResult:
        settings = get_settings()
        options = context.configuration.options

        target_is_authorized = bool(options.get("target_is_authorized", False))
        lab_hosts = frozenset(options.get("lab_hosts") or ())
        allow_private_networks = bool(settings.ssrf_allow_private_networks)

        budget = ReconBudget.start_now(
            total_timeout_seconds=settings.web_vuln_total_timeout_seconds,
            request_timeout_seconds=settings.web_vuln_request_timeout_seconds,
            max_requests=settings.web_vuln_max_requests,
            max_response_bytes=settings.web_vuln_max_response_bytes,
            max_metadata_response_bytes=settings.web_vuln_max_response_bytes,
            max_redirects=settings.web_vuln_max_redirects,
        )

        try:
            ctx = web_vuln_engine.build_context(
                scan_id=str(context.scan_id),
                target_base_url=context.target_base_url,
                target_is_authorized=target_is_authorized,
                budget=budget,
                allow_private_networks=allow_private_networks,
                lab_hosts=lab_hosts,
                is_cancelled=context.cancellation.check,
            )
        except (ReconScopeError, SSRFValidationError) as exc:
            logger.warning("WebVulnAssessmentModule: target rejected before collection: %s", exc)
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.FAILED,
                error=f"target rejected before any collection: {exc.__class__.__name__}: {exc}",
            )

        if context.cancellation.check():
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled before web vulnerability assessment started",
            )

        results, findings = web_vuln_engine.run_checks(
            ctx,
            settings=settings,
            max_response_bytes=settings.web_vuln_max_response_bytes,
        )

        if context.cancellation.check():
            return ModuleExecutionResult(
                status=ModuleExecutionStatus.CANCELLED,
                summary="Cancelled during web vulnerability assessment",
            )

        persisted = build_persisted_result(results, max_bytes=settings.web_vuln_result_max_persisted_bytes)

        status_counts: dict[str, int] = {}
        for collector_result in results.values():
            status_counts[collector_result.status.value] = status_counts.get(collector_result.status.value, 0) + 1
        summary = (
            f"Web vulnerability assessment finished: "
            + ", ".join(f"{count} {status}" for status, count in sorted(status_counts.items()))
            + f"; {len(findings)} finding(s)"
        )

        return ModuleExecutionResult(
            status=ModuleExecutionStatus.COMPLETED,
            findings=[finding.to_dict() for finding in findings],
            summary=summary,
            result=persisted,
        )
