"""Postgres-backed history lookup for the recon fingerprint collector.

The `FingerprintHistoryProvider` protocol is synchronous, because the
recon module runs synchronously inside `ScanModule.run()`. But the
app's only database driver is async SQLAlchemy.

So the Celery task awaits `fetch_previous_recon_run()` once, before the
module runs, and wraps the result in `FrozenFingerprintHistoryProvider`,
a small sync object that just returns what was already fetched. This
keeps app/engines/recon free of database code while still comparing
against real data."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.recon.fingerprint import HistoryEntry
from app.models.scan import Scan
from app.models.scan_module import ScanModule
from app.models.scan_module_run import ScanModuleRun, ScanModuleRunStatus


async def fetch_previous_recon_run(
    db: AsyncSession,
    *,
    target_id: uuid.UUID,
    user_id: uuid.UUID,
    before_run_id: uuid.UUID,
    module_slug: str = "recon",
) -> HistoryEntry | None:
    """The single, deterministic query Checkpoint-A adjustment #4
    (restated in fingerprint.py's own module docstring) requires: same
    target, same module, same owning user -- `Scan.initiated_by_id`,
    the user who actually ran that scan, is the "appartenant à" (user
    ownership) filter, never trusted from anywhere else -- excludes the
    run being compared (`before_run_id`), and only ever returns a
    COMPLETED run that actually has a persisted result. A run that was
    CANCELLED, FAILED, SKIPPED, or that is still PENDING/RUNNING is
    never a valid comparison point, confirmed-complete or otherwise --
    `status == COMPLETED` alone decides candidacy; a completed run
    whose OWN collectors were partial is still a candidate (that is
    exactly what `HistoryEntry.is_partial` below is for: the comparison
    layer in fingerprint.py reports `partial_data`, it does not refuse
    to compare).

    Deterministic tie-break (there should normally be at most one
    candidate per target/module/user, since the orchestration layer
    only allows one active scan per target at a time -- see
    services/scans.py::ACTIVE_SCAN_STATUSES -- but the ordering is
    still pinned down explicitly rather than left to incidental query
    -plan order): most recently finished first, then most recently
    created, then by id, so re-running this query against the same data
    always returns the same row."""
    stmt = (
        select(ScanModuleRun)
        .join(Scan, Scan.id == ScanModuleRun.scan_id)
        .join(ScanModule, ScanModule.id == ScanModuleRun.scan_module_id)
        .where(
            ScanModule.slug == module_slug,
            Scan.target_id == target_id,
            Scan.initiated_by_id == user_id,
            ScanModuleRun.id != before_run_id,
            ScanModuleRun.status == ScanModuleRunStatus.COMPLETED,
            ScanModuleRun.result.is_not(None),
        )
        .order_by(
            ScanModuleRun.finished_at.desc(),
            ScanModuleRun.created_at.desc(),
            ScanModuleRun.id.desc(),
        )
        .limit(1)
    )
    result = await db.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        return None

    snapshot = (row.result or {}).get("fingerprint_snapshot")
    if snapshot is None:
        # A persisted result exists but carries no fingerprint snapshot
        # (a run whose module implementation didn't produce one, or
        # that predates this field) -- never fabricate one; this is
        # "no usable history", not an empty-but-valid fingerprint.
        return None

    return HistoryEntry(
        run_id=str(row.id),
        fingerprint=snapshot,
        is_partial=bool(snapshot.get("incomplete_collectors")),
        completed_at=row.finished_at or row.updated_at,
    )


class FrozenFingerprintHistoryProvider:
    """Satisfies `FingerprintHistoryProvider` (app/engines/recon/
    fingerprint.py) synchronously by handing back a single
    `HistoryEntry | None` that was already fetched from Postgres via
    `fetch_previous_recon_run()` above, BEFORE the synchronous Recon
    module was invoked -- see this module's own docstring for why the
    fetch and the handoff are split this way.

    Asserts its captured identity matches what the engine actually asks
    for on every call -- a defensive check that this one-shot object,
    built for exactly one run, is never accidentally reused across a
    different target/user/run than the one it was fetched for."""

    def __init__(
        self,
        entry: HistoryEntry | None,
        *,
        target_id: uuid.UUID,
        user_id: uuid.UUID,
        before_run_id: uuid.UUID,
    ) -> None:
        self._entry = entry
        self._target_id = str(target_id)
        self._user_id = str(user_id)
        self._before_run_id = str(before_run_id)

    def get_previous_relevant_run(
        self,
        *,
        target_id: str,
        module_slug: str,
        user_id: str,
        before_run_id: str,
    ) -> HistoryEntry | None:
        assert self._target_id == target_id, "FrozenFingerprintHistoryProvider used for the wrong target"
        assert self._user_id == user_id, "FrozenFingerprintHistoryProvider used for the wrong user"
        assert self._before_run_id == before_run_id, "FrozenFingerprintHistoryProvider used for the wrong run"
        return self._entry
