"""HTTP reconnaissance collector.

Fetches the target's primary page through
app/engines/recon/security/request_policy.py (the only sanctioned path
to a scan target) and reports URL/redirect/timing/size/hash facts.

Also the single shared fetch that headers_collector, cookies_collector
and technology_collector all build on -- app/engines/recon/engine.py
calls `fetch_primary()` once per scan and passes its FetchedResponse to
all three, so the target is never fetched four separate times for four
collectors."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone

from app.engines.recon.collectors.base import run_collector_safely
from app.engines.recon.context import ReconExecutionContext
from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)
from app.engines.recon.security.request_policy import FetchedResponse, fetch_target_url

SLUG = "http"


def fetch_primary(ctx: ReconExecutionContext, *, max_response_bytes: int) -> FetchedResponse:
    """Not wrapped in run_collector_safely -- this is the shared raw
    fetch other collectors need even to report their own
    not_applicable/error state (e.g. headers_collector must know *why*
    the fetch failed to say so, rather than silently reporting zero
    headers as if the target simply sent none). Exceptions propagate to
    the caller (engine.py), which decides how every dependent collector
    reports the failure."""
    return fetch_target_url(
        ctx, ctx.target_base_url, max_response_bytes=max_response_bytes, where="http_collector.primary"
    )


def collect(
    ctx: ReconExecutionContext,
    fetched: FetchedResponse | None,
    fetch_error: str | None,
) -> CollectorResult:
    def _run() -> CollectorResult:
        started = time.monotonic()
        collected_at = datetime.now(timezone.utc)
        if fetched is None:
            return CollectorResult(
                collector=SLUG,
                status=CollectorStatus.ERROR,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[fetch_error or "primary fetch failed"],
                source="direct_http",
            )

        body_hash = hashlib.sha256(fetched.body_bytes).hexdigest()
        observations = [
            Observation("initial_url", fetched.url_chain[0], ObservationNature.OBSERVED),
            Observation("final_url", fetched.final_url, ObservationNature.OBSERVED),
            Observation("status_code", fetched.status_code, ObservationNature.OBSERVED),
            Observation("redirect_count", len(fetched.url_chain) - 1, ObservationNature.OBSERVED),
            Observation("redirect_chain", fetched.url_chain, ObservationNature.OBSERVED),
            Observation(
                "content_type", fetched.headers.get("content-type"), ObservationNature.OBSERVED
            ),
            Observation(
                "content_length_header",
                fetched.headers.get("content-length"),
                ObservationNature.OBSERVED,
            ),
            Observation("body_size_bytes", len(fetched.body_bytes), ObservationNature.OBSERVED),
            Observation("body_truncated", fetched.body_truncated, ObservationNature.OBSERVED),
            Observation("elapsed_ms", fetched.elapsed_ms, ObservationNature.OBSERVED),
            Observation(
                "body_sha256",
                body_hash,
                ObservationNature.OBSERVED,
                note=(
                    "hash computed over the TRUNCATED body, not the full page -- not"
                    " representative of the complete resource"
                    if fetched.body_truncated
                    else None
                ),
            ),
        ]
        # A truncated body makes body_size_bytes/body_sha256 (and any
        # downstream collector that scans this body, e.g.
        # technology_collector) a read of a partial resource -- PARTIAL,
        # not OK, so this is visible without having to inspect every
        # individual observation's note.
        status = CollectorStatus.PARTIAL if fetched.body_truncated else CollectorStatus.OK
        return CollectorResult(
            collector=SLUG,
            status=status,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={
                "status_code": fetched.status_code,
                "final_url": fetched.final_url,
                "body_truncated": fetched.body_truncated,
            },
            source="direct_http",
            confidence=ConfidenceLevel.HIGH,
        )

    return run_collector_safely(collector_slug=SLUG, source="direct_http", fn=_run)
