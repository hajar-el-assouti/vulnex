"""Web vulnerability assessment engine.

Its own module, with its own Settings.web_vuln_* budget, independent
from recon and advanced_recon. It reuses existing pieces instead of
duplicating them:

- the recon context classes (ReconExecutionContext, ReconBudget,
  cancellation and budget errors);
- recon/engine.py::build_context() for the SSRF-validated target;
- the http, headers, cookies and tls collectors for its own page fetch
  and observations, so it works even if recon didn't run in the same
  scan.

Order: http -> headers/cookies -> tls -> cancellation check -> every
check in web_vuln/registry.py's CHECK_REGISTRY, in order. Cancellation
is checked between groups; a cancelled run returns what was collected
so far."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from app.core.config import Settings
from app.engines.recon import engine as recon_engine
from app.engines.recon.collectors import (
    api_discovery_collector,
    cookies_collector,
    headers_collector,
    http_collector,
    tls_collector,
)
from app.engines.recon.context import ReconBudget, ReconBudgetExceededError, ReconCancelledError, ReconExecutionContext
from app.engines.recon.schemas import CollectorResult
from app.engines.recon.security.request_policy import FetchedResponse
from app.engines.web_vuln.findings import Finding, dedupe_findings
from app.engines.web_vuln.registry import CHECK_REGISTRY, CheckInputs, CheckOutcome
from app.security.ssrf import SSRFValidationError

logger = logging.getLogger("app.engines.web_vuln.engine")

# Re-exported so app/tasks/web_vuln_module.py never has to import
# app/engines/recon/engine.py directly -- this module's own public
# surface is the one callers depend on.
build_context = recon_engine.build_context


def _run_check_safely(check, inputs: CheckInputs) -> CheckOutcome:
    """Mirrors app/engines/recon/collectors/base.py::run_collector_safely's
    exception handling (same three distinguished exception types, same
    "never let it escape" guarantee), but for a check's richer
    CheckOutcome (observations AND findings) rather than a bare
    CollectorResult. A check that raises produces zero findings --
    never a fabricated one built from a run that didn't actually
    complete."""
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc)
    try:
        return check.run(inputs)
    except ReconCancelledError:
        raise
    except ReconBudgetExceededError as exc:
        logger.info("Check %s stopped: budget exceeded (%s)", check.SLUG, exc)
        return CheckOutcome(
            collector_result=CollectorResult.error(
                collector=check.SLUG,
                source=check.SLUG,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"budget_exceeded: {exc}"],
            )
        )
    except SSRFValidationError as exc:
        logger.warning("Check %s refused by SSRF policy: %s", check.SLUG, exc)
        return CheckOutcome(
            collector_result=CollectorResult.error(
                collector=check.SLUG,
                source=check.SLUG,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"ssrf_rejected: {exc}"],
            )
        )
    except Exception as exc:  # noqa: BLE001 -- must never escape, see docstring
        logger.exception("Check %s raised unexpectedly", check.SLUG)
        return CheckOutcome(
            collector_result=CollectorResult.error(
                collector=check.SLUG,
                source=check.SLUG,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"unexpected_error: {exc.__class__.__name__}: {exc}"],
            )
        )


def run_checks(
    ctx: ReconExecutionContext,
    *,
    settings: Settings,
    max_response_bytes: int,
) -> tuple[dict[str, CollectorResult], list[Finding]]:
    """Runs this engine's own primary fetch + headers/cookies/TLS
    collection, then every registered check, checking cooperative
    cancellation between groups. Returns (observations_by_slug,
    deduplicated_findings) -- `findings` is always deduplicated here
    (app/engines/web_vuln/findings.py::dedupe_findings) before it
    leaves this function, so no caller has to repeat that logic."""
    results: dict[str, CollectorResult] = {}
    all_findings: list[Finding] = []

    try:
        fetched: FetchedResponse | None = None
        fetch_error: str | None = None
        try:
            fetched = http_collector.fetch_primary(ctx, max_response_bytes=max_response_bytes)
        except ReconCancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 -- recorded below, never escapes
            fetch_error = f"{exc.__class__.__name__}: {exc}"

        results[http_collector.SLUG] = http_collector.collect(ctx, fetched, fetch_error)

        if ctx.is_cancelled():
            return results, all_findings

        results[headers_collector.SLUG] = headers_collector.collect(ctx, fetched, fetch_error)
        results[cookies_collector.SLUG] = cookies_collector.collect(ctx, fetched, fetch_error)
        # Same passive api_discovery collector recon uses, so
        # checks/api_security.py can work from already-collected endpoints.
        results[api_discovery_collector.SLUG] = api_discovery_collector.collect(ctx, fetched, fetch_error)

        if ctx.is_cancelled():
            return results, all_findings

        results[tls_collector.SLUG] = tls_collector.collect(ctx)
    except ReconCancelledError:
        return results, all_findings

    if ctx.is_cancelled():
        return results, all_findings

    inputs = CheckInputs(
        ctx=ctx,
        fetched=fetched,
        fetch_error=fetch_error,
        collector_results=results,
        settings=settings,
    )

    try:
        for check in CHECK_REGISTRY:
            outcome = _run_check_safely(check, inputs)
            results[check.SLUG] = outcome.collector_result
            all_findings.extend(outcome.findings)
            if ctx.is_cancelled():
                break
    except ReconCancelledError:
        pass

    return results, dedupe_findings(all_findings)
