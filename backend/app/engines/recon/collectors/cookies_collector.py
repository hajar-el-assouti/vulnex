"""Set-Cookie inspection.

Records name, Secure, HttpOnly, SameSite, Path, Domain and
Max-Age/Expires for each cookie. Cookie values are never stored or
logged, only their length, to show the value was masked."""

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

SLUG = "cookies"


def _parse_set_cookie_line(line: str) -> dict[str, object] | None:
    """A small, deliberately explicit parser (not stdlib
    http.cookies.SimpleCookie, whose reserved-attribute boolean
    semantics are easy to get subtly wrong) -- splits on ';', treats
    the first segment as name=value and every other segment as either
    a bare flag (Secure, HttpOnly) or a key=value attribute."""
    parts = [p.strip() for p in line.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return None

    name, _, value = parts[0].partition("=")
    attrs: dict[str, object] = {
        "name": name.strip(),
        "value_length": len(value),
        "secure": False,
        "httponly": False,
        "samesite": None,
        "path": None,
        "domain": None,
        "max_age": None,
        "expires": None,
    }
    for part in parts[1:]:
        if "=" in part:
            key, _, val = part.partition("=")
            key_norm, val = key.strip().lower(), val.strip()
        else:
            key_norm, val = part.strip().lower(), True

        if key_norm == "secure":
            attrs["secure"] = True
        elif key_norm == "httponly":
            attrs["httponly"] = True
        elif key_norm in ("samesite", "path", "domain"):
            attrs[key_norm] = val
        elif key_norm == "max-age":
            attrs["max_age"] = val
        elif key_norm == "expires":
            attrs["expires"] = val
    return attrs


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

        raw_lines = fetched.headers.get_list("set-cookie")
        observations: list[Observation] = []
        for line in raw_lines:
            parsed = _parse_set_cookie_line(line)
            if parsed is None:
                continue
            value_length = parsed.pop("value_length")
            observations.append(
                Observation(
                    f"cookie.{parsed['name']}",
                    parsed,
                    ObservationNature.OBSERVED,
                    note=f"value masked ({value_length} chars), never stored",
                )
            )

        if not raw_lines:
            observations.append(
                Observation(
                    "set_cookie_present",
                    False,
                    ObservationNature.OBSERVED,
                    note="no Set-Cookie header returned",
                )
            )

        return CollectorResult(
            collector=SLUG,
            status=CollectorStatus.OK,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"cookie_count": len(raw_lines)},
            source="direct_http",
            confidence=ConfidenceLevel.HIGH,
        )

    return run_collector_safely(collector_slug=SLUG, source="direct_http", fn=_run)
