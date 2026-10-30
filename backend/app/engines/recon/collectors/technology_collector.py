"""Technology fingerprinting from observable HTTP signals only.

Uses the headers and the already-fetched, size-capped HTML body (no
new request). The body is only searched as text with regular
expressions; it is never parsed as a DOM, rendered or executed.

Each detection has its evidence and confidence. A version is reported
only if it literally appears in the signal, never guessed. No known
signature means UNKNOWN, not "this technology isn't used"."""

from __future__ import annotations

import re
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

SLUG = "technology"

# The body is already size-capped upstream (Settings.recon_max_response_
# bytes); this is a second, independent cap on how much of it this
# collector's own regexes scan, so a borderline-sized body can't make
# fingerprinting itself slow.
_MAX_BODY_SCAN_CHARS = 200_000

_HEADER_PRODUCT_RE = re.compile(r"^([A-Za-z][A-Za-z0-9._-]*)(?:/([\w.]+))?")

_BODY_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    # (regex, technology name, note)
    (r"__NEXT_DATA__", "Next.js", "found __NEXT_DATA__ script marker"),
    (r"data-reactroot|react-dom", "React", "found React-specific DOM marker"),
    (r'ng-version="([\w.]*)"', "Angular", "found ng-version attribute"),
    (r"wp-content/|wp-includes/", "WordPress", "found wp-content/wp-includes path reference"),
    (
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        "generator-meta-tag",
        "found <meta name=generator> tag",
    ),
)


def _decode_body(fetched: FetchedResponse) -> str:
    # Always decoded as best-effort UTF-8 with replacement -- never
    # trusts (or needs to parse) a target-supplied charset declaration
    # to decide how to decode untrusted bytes.
    return fetched.body_bytes.decode("utf-8", errors="replace")[:_MAX_BODY_SCAN_CHARS]


def _detect_from_headers(headers) -> list[Observation]:
    observations: list[Observation] = []

    for header_name, note in (("server", "parsed from Server header"), ("x-powered-by", "parsed from X-Powered-By header")):
        raw = headers.get(header_name)
        if not raw:
            continue
        observations.append(
            Observation(f"technology.raw_{header_name.replace('-', '_')}", raw, ObservationNature.OBSERVED)
        )
        match = _HEADER_PRODUCT_RE.match(raw)
        if match:
            name, version = match.group(1), match.group(2)
            observations.append(
                Observation(
                    f"technology.{name.lower()}",
                    {"name": name, "version": version},
                    ObservationNature.OBSERVED if version else ObservationNature.INFERRED,
                    note=note,
                )
            )

    if headers.get("cf-ray") or headers.get("cf-cache-status"):
        observations.append(
            Observation(
                "technology.cloudflare",
                {"name": "Cloudflare", "version": None},
                ObservationNature.INFERRED,
                note="cf-ray/cf-cache-status header present",
            )
        )
    return observations


def _detect_from_body(body_text: str) -> list[Observation]:
    observations: list[Observation] = []
    for pattern, name, note in _BODY_SIGNATURES:
        match = re.search(pattern, body_text, re.IGNORECASE)
        if not match:
            continue
        version = match.group(1) if match.groups() and match.group(1) else None
        observations.append(
            Observation(
                f"technology.{name.lower().replace(' ', '_').replace('-', '_')}",
                {"name": name, "version": version},
                ObservationNature.INFERRED,
                note=note,
            )
        )
    return observations


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

        observations = _detect_from_headers(fetched.headers)
        body_text = _decode_body(fetched)
        observations += _detect_from_body(body_text)

        if not observations:
            observations.append(
                Observation(
                    "technologies_detected",
                    [],
                    ObservationNature.UNKNOWN,
                    note="no known signature matched; absence of a signature is not proof of absence",
                )
            )

        # Header-based detections are unaffected by body truncation (the
        # headers are always complete), but every body-based signature
        # match above only ever saw the truncated prefix of the page --
        # a signature further down would simply never be seen, which is
        # a false negative, not a false positive. Surface that
        # explicitly rather than let a truncated-body technology report
        # look as complete as a full-body one.
        observations.append(
            Observation(
                "technology.body_scan_truncated",
                fetched.body_truncated,
                ObservationNature.OBSERVED,
                note=(
                    "the body was truncated before this collector scanned it for"
                    " signatures; a technology with no matching signature below the"
                    " truncation point would not be detected -- this result is"
                    " potentially incomplete, not a confirmed absence"
                    if fetched.body_truncated
                    else None
                ),
            )
        )

        status = CollectorStatus.PARTIAL if fetched.body_truncated else CollectorStatus.OK
        return CollectorResult(
            collector=SLUG,
            status=status,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"body_scanned_chars": len(body_text), "body_truncated": fetched.body_truncated},
            source="direct_http+html",
            confidence=ConfidenceLevel.LOW if fetched.body_truncated else ConfidenceLevel.MEDIUM,
        )

    return run_collector_safely(collector_slug=SLUG, source="direct_http+html", fn=_run)
