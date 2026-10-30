"""Shared wrapper every recon collector runs through.

A collector may raise (SSRF rejection, budget exhausted, network
error, bug). This turns any of those into a
CollectorResult(status=ERROR, ...) so one failing collector doesn't
abort the whole scan."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Callable

from app.engines.recon.context import ReconBudgetExceededError, ReconCancelledError
from app.engines.recon.schemas import CollectorResult
from app.security.ssrf import SSRFValidationError

logger = logging.getLogger("app.engines.recon.collectors")


def run_collector_safely(
    *,
    collector_slug: str,
    source: str,
    fn: Callable[[], CollectorResult],
) -> CollectorResult:
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc)
    try:
        return fn()
    except ReconCancelledError:
        # Deliberately NOT turned into a CollectorStatus.ERROR result --
        # re-raised so app/engines/recon/engine.py::run_collectors() can
        # stop dispatching further collectors entirely. Converting this
        # to an ERROR result here would make a cancelled scan look like
        # a scan where this one collector happened to fail, and would
        # let the orchestrator keep running every remaining collector
        # after cancellation was already observed (see
        # ReconCancelledError's own docstring).
        raise
    except ReconBudgetExceededError as exc:
        logger.info("Collector %s stopped: budget exceeded (%s)", collector_slug, exc)
        return CollectorResult.error(
            collector=collector_slug,
            source=source,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            errors=[f"budget_exceeded: {exc}"],
        )
    except SSRFValidationError as exc:
        logger.warning("Collector %s refused by SSRF policy: %s", collector_slug, exc)
        return CollectorResult.error(
            collector=collector_slug,
            source=source,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            errors=[f"ssrf_rejected: {exc}"],
        )
    except Exception as exc:  # noqa: BLE001 -- must never escape, see docstring
        logger.exception("Collector %s raised unexpectedly", collector_slug)
        return CollectorResult.error(
            collector=collector_slug,
            source=source,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            errors=[f"unexpected_error: {exc.__class__.__name__}: {exc}"],
        )
