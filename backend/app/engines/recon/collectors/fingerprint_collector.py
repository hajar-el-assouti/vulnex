"""Fingerprint/history collector: wraps the compute/compare logic of
recon/fingerprint.py in a CollectorResult.

It makes no network call: it uses the other collectors' results for
the same run and, when a history provider and the run identity
(target_id/module_slug/user_id/run_id) are given, compares with the
previous run. Without them, recon/engine.py leaves this collector out
instead of reporting a meaningless "no_history"."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from app.engines.recon.collectors.base import run_collector_safely
from app.engines.recon.fingerprint import (
    FingerprintComparisonStatus,
    FingerprintHistoryProvider,
    compare_fingerprints,
    compute_fingerprint,
    fingerprint_hash,
)
from app.engines.recon.schemas import (
    CollectorResult,
    CollectorStatus,
    ConfidenceLevel,
    Observation,
    ObservationNature,
)

SLUG = "fingerprint"

_STATUS_TO_NATURE = {
    FingerprintComparisonStatus.NO_HISTORY: ObservationNature.OBSERVED,
    FingerprintComparisonStatus.UNCHANGED: ObservationNature.OBSERVED,
    FingerprintComparisonStatus.CHANGED: ObservationNature.OBSERVED,
    FingerprintComparisonStatus.PARTIAL_DATA: ObservationNature.UNKNOWN,
}


def collect(
    results: dict[str, "CollectorResult"],
    *,
    target_id: str,
    module_slug: str,
    user_id: str,
    run_id: str,
    history_provider: FingerprintHistoryProvider,
) -> CollectorResult:
    def _run() -> CollectorResult:
        started = time.monotonic()
        collected_at = datetime.now(timezone.utc)

        current_fingerprint = compute_fingerprint(results)
        current_hash = fingerprint_hash(current_fingerprint)

        previous = history_provider.get_previous_relevant_run(
            target_id=target_id,
            module_slug=module_slug,
            user_id=user_id,
            before_run_id=run_id,
        )
        comparison = compare_fingerprints(current_fingerprint, previous)

        observations = [
            Observation("fingerprint.hash", current_hash, ObservationNature.OBSERVED),
            Observation(
                "fingerprint.comparison_status",
                comparison.status,
                _STATUS_TO_NATURE[comparison.status],
                note=comparison.note or None,
            ),
        ]
        if comparison.changed_keys:
            observations.append(
                Observation("fingerprint.changed_keys", list(comparison.changed_keys), ObservationNature.OBSERVED)
            )
        if previous is not None:
            observations.append(
                Observation("fingerprint.compared_against_run_id", previous.run_id, ObservationNature.OBSERVED)
            )

        status = (
            CollectorStatus.PARTIAL
            if comparison.status == FingerprintComparisonStatus.PARTIAL_DATA
            else CollectorStatus.OK
        )
        return CollectorResult(
            collector=SLUG,
            status=status,
            collected_at=collected_at,
            duration_ms=int((time.monotonic() - started) * 1000),
            observations=observations,
            evidence={"target_id": target_id, "module_slug": module_slug, "run_id": run_id},
            source="fingerprint",
            confidence=ConfidenceLevel.HIGH,
        )

    return run_collector_safely(collector_slug=SLUG, source="fingerprint", fn=_run)
