"""Discovery & fuzzing engine.

Tests a deterministic, capped selection of a SecLists-based wordlist
(wordlist.py) against one authorized target. Uses the same transport
as active_web_testing (security/pinned_request.py): SSRF validation
and IP pinning on every request, GET only.

Redirects are never followed (`follow_redirects=False`): the 3xx
status and Location header are the observation, so no request is ever
sent to an unverified destination.

Produces observations only, never findings: `run_discovery()` always
returns an empty findings list. A found path is not a vulnerability by
itself; a human decides whether it is interesting.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from app.core.config import Settings
from app.engines.active_web_testing.security import pinned_request
from app.engines.discovery_fuzzing import baseline, wordlist as wordlist_module
from app.engines.recon.context import ReconBudgetExceededError, ReconCancelledError, ReconExecutionContext
from app.engines.recon.schemas import CollectorResult, CollectorStatus, ConfidenceLevel, Observation, ObservationNature
from app.security.ssrf import SSRFValidationError

logger = logging.getLogger("app.engines.discovery_fuzzing.engine")

SLUG = "discovery_fuzzing"

# Observation "type" values -- plain strings (not a shared enum with
# any other engine) because these categories are specific to path
# discovery and have no equivalent elsewhere in this codebase.
TYPE_ACCESSIBLE = "accessible"
TYPE_LIKELY_SOFT_404 = "likely_soft_404"
TYPE_REDIRECT = "redirect"
TYPE_AUTH_REQUIRED = "auth_required"
TYPE_FORBIDDEN = "forbidden"
TYPE_NOT_FOUND = "not_found"
TYPE_RATE_LIMITED = "rate_limited"
TYPE_SERVER_ERROR = "server_error"
TYPE_OTHER = "other"
TYPE_ERROR = "error"


def _classify(status_code: int, *, is_soft_404: bool) -> str:
    if 200 <= status_code < 300:
        return TYPE_LIKELY_SOFT_404 if is_soft_404 else TYPE_ACCESSIBLE
    if status_code in (301, 302, 303, 307, 308):
        return TYPE_REDIRECT
    if status_code == 401:
        return TYPE_AUTH_REQUIRED
    if status_code == 403:
        return TYPE_FORBIDDEN
    if status_code == 404:
        return TYPE_NOT_FOUND
    if status_code == 429:
        return TYPE_RATE_LIMITED
    if 500 <= status_code < 600:
        return TYPE_SERVER_ERROR
    return TYPE_OTHER


def _fetch_one(
    ctx: ReconExecutionContext, url: str, *, max_response_bytes: int, where: str
) -> tuple[int | None, int | None, str | None, str | None]:
    """Returns (status_code, body_length, location_header, error) for
    one probe/path -- never raises for an ordinary target-side failure
    (timeout, connection error, non-fatal SSRF rejection of a redirect
    target we never even chase); DOES let ReconCancelledError and
    ReconBudgetExceededError propagate, since those stop the whole run,
    not just this one path."""
    try:
        response = pinned_request.fetch_pinned_url(
            ctx,
            url,
            max_response_bytes=max_response_bytes,
            where=where,
            method="GET",
            follow_redirects=False,
        )
    except (ReconCancelledError, ReconBudgetExceededError):
        raise
    except SSRFValidationError as exc:
        return None, None, None, f"ssrf_rejected: {exc}"
    except Exception as exc:  # noqa: BLE001 -- a target's own failure must never abort the scan
        return None, None, None, f"{exc.__class__.__name__}: {exc}"
    location = response.headers.get("location")
    return response.status_code, len(response.body_bytes), location, None


def run_discovery(
    ctx: ReconExecutionContext,
    *,
    settings: Settings,
    scan_id: str,
    mode: str = "quick",
) -> tuple[CollectorResult, list[dict]]:
    """Runs the soft-404 baseline probes, then the deterministically
    selected wordlist entries for `mode`, and returns (CollectorResult,
    findings) -- findings is always `[]` (see module docstring).
    Checks cancellation and the shared request/time budget between
    EVERY single request (baseline probe or real path), via
    `ctx.budget`/`ctx.is_cancelled()` exactly like every other engine
    in this codebase -- never only between groups of requests."""
    started = time.monotonic()
    collected_at = datetime.now(timezone.utc)
    observations: list[Observation] = []
    errors: list[str] = []
    max_paths = getattr(settings, wordlist_module.MODE_SETTING_ATTR[mode])

    probe_paths = baseline.build_probe_paths(
        scan_id, count=settings.discovery_fuzzing_soft_404_probe_count
    )
    probe_outcomes: list[baseline.ProbeOutcome] = []
    stopped_early_reason: str | None = None

    try:
        for probe_path in probe_paths:
            ctx.raise_if_cancelled(where="discovery_fuzzing baseline probe")
            url = wordlist_module.build_request_url(ctx.target_base_url, probe_path)
            status_code, body_length, _location, error = _fetch_one(
                ctx, url, max_response_bytes=settings.discovery_fuzzing_max_response_bytes,
                where="discovery_fuzzing baseline probe",
            )
            probe_outcomes.append(baseline.ProbeOutcome(path=probe_path, status_code=status_code, body_length=body_length))
            if error:
                errors.append(f"baseline probe {probe_path!r}: {error}")

        signature = baseline.compute_signature(
            probe_outcomes, body_length_tolerance=settings.discovery_fuzzing_soft_404_body_length_tolerance
        )

        entries = wordlist_module.load_wordlist()
        selected = wordlist_module.select_paths(entries, max_paths=max_paths)

        paths_tested = 0
        for entry in selected:
            ctx.raise_if_cancelled(where=f"discovery_fuzzing path {entry!r}")
            url = wordlist_module.build_request_url(ctx.target_base_url, entry)
            status_code, body_length, location, error = _fetch_one(
                ctx, url, max_response_bytes=settings.discovery_fuzzing_max_response_bytes,
                where=f"discovery_fuzzing path {entry!r}",
            )
            paths_tested += 1
            tested_at = datetime.now(timezone.utc).isoformat()

            if error is not None:
                observations.append(
                    Observation(
                        key=entry,
                        value={
                            "status_code": None,
                            "observation_type": TYPE_ERROR,
                            "is_redirect": False,
                            "location": None,
                            "tested_at": tested_at,
                            "error": error,
                        },
                        nature=ObservationNature.ERROR,
                    )
                )
                # Folded into the collector-level `errors` too (not just
                # the per-path observation) so CollectorStatus correctly
                # reflects PARTIAL whenever at least one path could not
                # actually be tested -- never silently reported as a
                # clean OK run alongside a hidden per-observation error.
                errors.append(f"path {entry!r}: {error}")
                continue

            is_soft_404 = (
                status_code is not None
                and 200 <= status_code < 300
                and baseline.matches_soft_404(
                    signature,
                    status_code=status_code,
                    body_length=body_length or 0,
                    body_length_tolerance=settings.discovery_fuzzing_soft_404_body_length_tolerance,
                )
            )
            observation_type = _classify(status_code, is_soft_404=is_soft_404)
            observations.append(
                Observation(
                    key=entry,
                    value={
                        "status_code": status_code,
                        "observation_type": observation_type,
                        "is_redirect": observation_type == TYPE_REDIRECT,
                        "location": location,
                        "tested_at": tested_at,
                    },
                    nature=ObservationNature.OBSERVED,
                )
            )

            if observation_type == TYPE_RATE_LIMITED:
                # On a 429, stop sending requests right away instead of retrying
                # later. Simpler, predictable, and respects the target.
                stopped_early_reason = (
                    f"stopped after {paths_tested}/{len(selected)} path(s): "
                    f"target returned 429 (rate limited) for {entry!r}"
                )
                break
    except ReconCancelledError:
        return (
            CollectorResult(
                collector=SLUG,
                status=CollectorStatus.PARTIAL,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=observations,
                evidence=_evidence(mode, max_paths, scan_id, ctx.target_base_url, len(observations), None),
                errors=errors + ["cancelled before completion"],
                source="discovery_fuzzing",
                confidence=ConfidenceLevel.LOW,
            ),
            [],
        )
    except ReconBudgetExceededError as exc:
        return (
            CollectorResult(
                collector=SLUG,
                status=CollectorStatus.PARTIAL,
                collected_at=collected_at,
                duration_ms=int((time.monotonic() - started) * 1000),
                observations=observations,
                evidence=_evidence(mode, max_paths, scan_id, ctx.target_base_url, len(observations), None),
                errors=errors + [f"budget_exceeded: {exc}"],
                source="discovery_fuzzing",
                confidence=ConfidenceLevel.LOW,
            ),
            [],
        )

    status = CollectorStatus.OK if not errors else CollectorStatus.PARTIAL
    result = CollectorResult(
        collector=SLUG,
        status=status,
        collected_at=collected_at,
        duration_ms=int((time.monotonic() - started) * 1000),
        observations=observations,
        evidence=_evidence(
            mode, max_paths, scan_id, ctx.target_base_url, len(observations), stopped_early_reason
        ),
        errors=errors,
        source="discovery_fuzzing",
        confidence=ConfidenceLevel.LOW,
    )
    return result, []


def _evidence(
    mode: str, max_paths: int, scan_id: str, target_base_url: str, paths_tested: int, stopped_early_reason: str | None
) -> dict:
    return {
        "mode": mode,
        "max_paths": max_paths,
        "scan_id": scan_id,
        "target_base_url": target_base_url,
        "paths_tested": paths_tested,
        "stopped_early_reason": stopped_early_reason,
    }
