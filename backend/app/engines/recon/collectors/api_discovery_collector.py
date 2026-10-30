"""API endpoint discovery: candidate endpoints written in the initial
HTML. No crawling, no extra request, no guessing.

Only finds endpoints that literally appear in the HTML (inline
<script>, href/action/data-* attributes, fetch()/axios()/XMLHttpRequest
calls). It never downloads external .js bundles and never brute-forces
paths. Matches are INFERRED from text, never OBSERVED.

Works on the `fetched.body_bytes` already retrieved by http_collector.
Every candidate goes through redact_secrets() before being stored."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from app.engines.recon.collectors._secrets import redact_secrets
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

SLUG = "api_discovery"

_MAX_CANDIDATES_REPORTED = 50
_MAX_BODY_SCAN_CHARS = 500_000

# Each pattern's one capturing group is the candidate endpoint string.
# Deliberately narrow and literal -- no attempt to parse JavaScript,
# just to find quoted strings in call-site or markup shapes that
# plainly reference an API-looking path. False negatives (a reference
# this doesn't recognize) are expected and fine; a false positive here
# is just an extra candidate string, never acted upon.
_PATTERNS: tuple[re.Pattern, ...] = (
    # fetch("/api/..."), fetch('https://x/api/...')
    re.compile(r"""\bfetch\(\s*["']([^"']{1,500})["']"""),
    # axios.get("..."), axios.post("...", axios.request({url: "..."
    re.compile(r"""\baxios\.\w+\(\s*["']([^"']{1,500})["']"""),
    # new XMLHttpRequest / xhr.open("GET", "...")
    re.compile(r"""\.open\(\s*["']\w+["']\s*,\s*["']([^"']{1,500})["']"""),
    # any quoted string containing an /api/ path segment, in markup or
    # inline script alike (href="/api/...", action="/api/...",
    # data-endpoint="/api/...", a bare string literal in inline JS).
    re.compile(r"""["'](/[-\w./]*\bapi\b[-\w./]*)["']""", re.IGNORECASE),
)


def _looks_like_endpoint(candidate: str) -> bool:
    return candidate.startswith(("/", "http://", "https://")) and len(candidate) > 1


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
                source="direct_http+html",
            )

        body_text = fetched.body_bytes.decode("utf-8", errors="replace")[:_MAX_BODY_SCAN_CHARS]

        candidates: set[str] = set()
        for pattern in _PATTERNS:
            for match in pattern.finditer(body_text):
                candidate = match.group(1)
                if _looks_like_endpoint(candidate):
                    candidates.add(redact_secrets(candidate))

        sorted_candidates = sorted(candidates)
        observations: list[Observation] = []

        if not sorted_candidates:
            observations.append(
                Observation(
                    "api_discovery.candidate_endpoints",
                    [],
                    ObservationNature.UNKNOWN,
                    note=(
                        "no API-looking string literal matched in the initial HTML --"
                        " this is not proof the target has no API; it may be loaded"
                        " entirely from external script bundles this collector never"
                        " fetches"
                    ),
                )
            )
        else:
            observations.append(
                Observation(
                    "api_discovery.candidate_endpoints",
                    sorted_candidates[:_MAX_CANDIDATES_REPORTED],
                    ObservationNature.INFERRED,
                    note=(
                        "static text matches only -- never confirmed by an actual request;"
                        f" {len(sorted_candidates)} distinct candidate(s) found"
                        + (f", first {_MAX_CANDIDATES_REPORTED} reported" if len(sorted_candidates) > _MAX_CANDIDATES_REPORTED else "")
                    ),
                )
            )

        if fetched.body_truncated:
            observations.append(
                Observation(
                    "api_discovery.body_scan_truncated",
                    True,
                    ObservationNature.OBSERVED,
                    note="the body was truncated before this collector scanned it -- a reference below the truncation point would not be found",
                )
            )

        status = CollectorStatus.PARTIAL if fetched.body_truncated else CollectorStatus.OK
        return CollectorResult(
            collector=SLUG,
            status=status,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"candidate_count": len(sorted_candidates), "body_truncated": fetched.body_truncated},
            source="direct_http+html",
            confidence=ConfidenceLevel.LOW if fetched.body_truncated else ConfidenceLevel.MEDIUM,
        )

    return run_collector_safely(collector_slug=SLUG, source="direct_http+html", fn=_run)
