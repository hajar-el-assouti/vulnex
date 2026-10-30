"""Fingerprint computation and history comparison.

Pure logic, no Postgres, Celery or network. The history provider (the
`FingerprintHistoryProvider` protocol below) is implemented in
app/services/recon_history.py.

A run is only compared with a relevant previous run:
- same target_id and same module_slug;
- same user_id: a provider must never return another user's run;
- finished strictly before the current run;
- if either run is incomplete, the result is an explicit
  partial_data verdict (FingerprintComparison.PARTIAL_DATA), never a
  confident changed/unchanged.

compute_fingerprint() only uses Observation.value (already sanitized),
never evidence or errors, and skips ERROR/NOT_APPLICABLE observations,
since comparing "we don't know" between runs would only compare
noise."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from app.engines.recon.schemas import CollectorResult, CollectorStatus, ObservationNature

# Observation natures that represent an actual, comparable fact about
# the target at the time of the run. ERROR (collection failed) and
# NOT_APPLICABLE (the check didn't apply) are deliberately excluded --
# including them would make "the DNS resolver timed out this run but
# not last run" look like a target change, which it is not.
_COMPARABLE_NATURES = frozenset({ObservationNature.OBSERVED, ObservationNature.INFERRED})


def compute_fingerprint(results: dict[str, CollectorResult]) -> dict:
    """A stable, JSON-serializable snapshot of this run's comparable
    facts, grouped by collector slug. Two runs with identical target
    behavior produce byte-identical fingerprints (dict key order is
    irrelevant -- compare_fingerprints() and the hash below both sort
    keys), so an actual change always shows up as a real diff, never as
    incidental reordering noise."""
    observations_by_collector: dict[str, dict] = {}
    incomplete_collectors: list[str] = []

    for slug, result in sorted(results.items()):
        if result.status in (CollectorStatus.PARTIAL, CollectorStatus.ERROR):
            incomplete_collectors.append(slug)
        comparable = {
            obs.key: obs.value for obs in result.observations if obs.nature in _COMPARABLE_NATURES
        }
        if comparable:
            observations_by_collector[slug] = comparable

    return {
        "observations": observations_by_collector,
        "incomplete_collectors": sorted(incomplete_collectors),
    }


def fingerprint_hash(fingerprint: dict) -> str:
    """A short, stable digest of compute_fingerprint()'s output --
    convenient for a quick equality check or for display, but
    compare_fingerprints() below diffs the structured dict directly
    (not just this hash) so it can report WHICH keys actually changed."""
    canonical = json.dumps(fingerprint, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class HistoryEntry:
    """One prior run, as a history provider returns it. `is_partial`
    must be True whenever that prior run itself had any incomplete
    collector (mirrors compute_fingerprint()'s own
    incomplete_collectors tracking) -- a provider that always reports
    is_partial=False defeats the whole point of this field."""

    run_id: str
    fingerprint: dict
    is_partial: bool
    completed_at: datetime


@runtime_checkable
class FingerprintHistoryProvider(Protocol):
    def get_previous_relevant_run(
        self,
        *,
        target_id: str,
        module_slug: str,
        user_id: str,
        before_run_id: str,
    ) -> HistoryEntry | None:
        """Returns the latest completed run with the same target_id,
        module_slug and user_id, strictly before before_run_id, or None.
        The implementation must apply all three filters in its query."""
        ...


class NullHistoryProvider:
    """Default provider when none is given: always reports no history."""

    def get_previous_relevant_run(
        self,
        *,
        target_id: str,
        module_slug: str,
        user_id: str,
        before_run_id: str,
    ) -> HistoryEntry | None:
        return None


class FingerprintComparisonStatus:
    NO_HISTORY = "no_history"
    UNCHANGED = "unchanged"
    CHANGED = "changed"
    PARTIAL_DATA = "partial_data"


@dataclass(frozen=True)
class FingerprintComparison:
    status: str
    changed_keys: tuple[str, ...] = ()
    note: str = ""


def _flatten(fingerprint: dict) -> dict[str, object]:
    flat: dict[str, object] = {}
    for slug, observations in fingerprint.get("observations", {}).items():
        for key, value in observations.items():
            flat[f"{slug}.{key}"] = value
    return flat


def compare_fingerprints(current: dict, previous: HistoryEntry | None) -> FingerprintComparison:
    """Three-way (plus a fourth structural) outcome, exactly as
    required: no_history (nothing to compare against), unchanged,
    changed (with the specific keys that differ), or partial_data
    (either side was itself incomplete, so no confident verdict is
    offered)."""
    if previous is None:
        return FingerprintComparison(
            status=FingerprintComparisonStatus.NO_HISTORY,
            note="no prior completed run of this module for this target/user to compare against",
        )

    current_incomplete = bool(current.get("incomplete_collectors"))
    if previous.is_partial or current_incomplete:
        sides = []
        if previous.is_partial:
            sides.append("previous run")
        if current_incomplete:
            sides.append("current run")
        return FingerprintComparison(
            status=FingerprintComparisonStatus.PARTIAL_DATA,
            note=f"comparison not attempted: {' and '.join(sides)} had incomplete collector data",
        )

    current_flat = _flatten(current)
    previous_flat = _flatten(previous.fingerprint)
    all_keys = set(current_flat) | set(previous_flat)
    changed = sorted(key for key in all_keys if current_flat.get(key) != previous_flat.get(key))

    if not changed:
        return FingerprintComparison(status=FingerprintComparisonStatus.UNCHANGED)

    return FingerprintComparison(
        status=FingerprintComparisonStatus.CHANGED,
        changed_keys=tuple(changed),
        note=f"{len(changed)} field(s) differ from the previous run",
    )
