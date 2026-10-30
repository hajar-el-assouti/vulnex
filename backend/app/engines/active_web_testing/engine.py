"""Active web testing engine.

Its own module, budget and network policy (see
security/pinned_request.py), but it reuses existing pieces:

- the recon context classes (ReconExecutionContext, ReconBudget,
  cancellation and budget errors);
- recon/engine.py::build_context(), so the target goes through the
  same authorization and SSRF checks as every engine. Each test
  request is then also pinned to the validated IP;
- the http and api_discovery collectors for the baseline fetch and
  passive endpoint discovery, so it doesn't depend on another module
  running in the same scan;
- web_vuln/findings.py's Finding and dedupe_findings.

Order: http (normal request_policy, read-only baseline) ->
api_discovery -> entry-point discovery (pinned, for the OpenAPI
probe) -> cancellation check -> every check in CHECK_REGISTRY, in
order, sharing one EndpointRequestTracker."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from app.core.config import Settings
from app.engines.active_web_testing.entrypoints import discover_entry_points
from app.engines.active_web_testing.registry import CHECK_REGISTRY, CheckInputs, CheckOutcome, EndpointRequestTracker
from app.engines.recon import engine as recon_engine
from app.engines.recon.collectors import api_discovery_collector, http_collector
from app.engines.recon.context import ReconBudgetExceededError, ReconCancelledError, ReconExecutionContext
from app.engines.recon.schemas import CollectorResult
from app.engines.recon.security.request_policy import FetchedResponse
from app.engines.web_vuln.findings import Finding, dedupe_findings
from app.security.ssrf import SSRFValidationError

logger = logging.getLogger("app.engines.active_web_testing.engine")

# Re-exported so app/tasks/active_web_testing_module.py never has to
# import app/engines/recon/engine.py directly.
build_context = recon_engine.build_context


def _run_check_safely(check, inputs: CheckInputs) -> CheckOutcome:
    """Mirrors app/engines/web_vuln/engine.py::_run_check_safely's own
    exception-safety guarantee exactly, for this engine's own
    CheckOutcome shape."""
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
                collector=check.SLUG, source=check.SLUG, collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"budget_exceeded: {exc}"],
            )
        )
    except SSRFValidationError as exc:
        logger.warning("Check %s refused by SSRF policy: %s", check.SLUG, exc)
        return CheckOutcome(
            collector_result=CollectorResult.error(
                collector=check.SLUG, source=check.SLUG, collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"ssrf_rejected: {exc}"],
            )
        )
    except Exception as exc:  # noqa: BLE001 -- must never escape
        logger.exception("Check %s raised unexpectedly", check.SLUG)
        return CheckOutcome(
            collector_result=CollectorResult.error(
                collector=check.SLUG, source=check.SLUG, collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"unexpected_error: {exc.__class__.__name__}: {exc}"],
            )
        )


def run_checks(
    ctx: ReconExecutionContext,
    *,
    settings: Settings,
    max_response_bytes: int,
) -> tuple[dict[str, CollectorResult], list[Finding], int]:
    """Runs this engine's own primary fetch + passive endpoint
    discovery, then entry-point discovery, then every registered
    active check, checking cooperative cancellation between groups.
    Returns (observations_by_slug, deduplicated_findings,
    entry_points_discovered_count)."""
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
            return results, all_findings, 0

        results[api_discovery_collector.SLUG] = api_discovery_collector.collect(ctx, fetched, fetch_error)
    except ReconCancelledError:
        return results, all_findings, 0

    if ctx.is_cancelled():
        return results, all_findings, 0

    entry_points = discover_entry_points(
        ctx=ctx,
        fetched=fetched,
        collector_results=results,
        openapi_probe_paths=settings.web_vuln_openapi_probe_paths,
        max_response_bytes=max_response_bytes,
    )

    if ctx.is_cancelled():
        return results, all_findings, len(entry_points)

    tracker = EndpointRequestTracker(settings.active_web_testing_max_requests_per_endpoint)
    inputs = CheckInputs(ctx=ctx, fetched=fetched, entry_points=entry_points, settings=settings, request_tracker=tracker)

    try:
        for check in CHECK_REGISTRY:
            outcome = _run_check_safely(check, inputs)
            results[check.SLUG] = outcome.collector_result
            all_findings.extend(outcome.findings)
            if ctx.is_cancelled():
                break
    except ReconCancelledError:
        pass

    return results, dedupe_findings(all_findings), len(entry_points)
