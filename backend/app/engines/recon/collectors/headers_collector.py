"""Security-relevant HTTP response headers.

Reports presence, raw value and a short, factual interpretation for
each header. A missing header is never reported as a critical
vulnerability, and HSTS is not counted as protection on a response
that wasn't served over HTTPS."""

from __future__ import annotations

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
from app.engines.recon.security.request_policy import FetchedResponse

SLUG = "headers"

_HEADERS_OF_INTEREST = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
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
                status=CollectorStatus.NOT_APPLICABLE,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                errors=[f"no primary response to inspect: {fetch_error or 'unknown'}"],
                source="direct_http",
            )

        is_https = fetched.final_url.lower().startswith("https://")
        observations: list[Observation] = []
        for header_name in _HEADERS_OF_INTEREST:
            value = fetched.headers.get(header_name)
            if header_name == "strict-transport-security" and not is_https:
                observations.append(
                    Observation(
                        f"header.{header_name}",
                        value,
                        ObservationNature.NOT_APPLICABLE,
                        note=(
                            "HSTS is only meaningful on a response actually served over "
                            "HTTPS; this response was not."
                        ),
                    )
                )
                continue
            observations.append(
                Observation(
                    f"header.{header_name}",
                    value,
                    ObservationNature.OBSERVED,
                    note=None if value is not None else "absent",
                )
            )

        observations.append(
            Observation("server_header", fetched.headers.get("server"), ObservationNature.OBSERVED)
        )

        return CollectorResult(
            collector=SLUG,
            status=CollectorStatus.OK,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"is_https": is_https},
            source="direct_http",
            confidence=ConfidenceLevel.HIGH,
        )

    return run_collector_safely(collector_slug=SLUG, source="direct_http", fn=_run)
