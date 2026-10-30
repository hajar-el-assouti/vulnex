"""The only place that talks to Celery from the FastAPI process.

Kept deliberately separate from services/scans.py (which is pure
DB/no-Celery) so that module can be unit-tested without a broker, and so
this module's functions can be monkeypatched/mocked in endpoint tests
without touching the DB-only state machine logic.

Reliable-dispatch note (the "outbox" described in app/models/scan.py):
a scan is already committed as PENDING before this module is ever
called. `dispatch_scan()` is best-effort -- if it fails, the scan simply
stays PENDING (dispatch_attempts incremented) and
app/tasks/maintenance.py::reconcile_pending_scans picks it up later.
Nothing here is allowed to raise out to the caller in a way that would
make the already-committed scan disappear or look like it was never
created.
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import get_celery_app
from app.services import scans as scans_service

logger = logging.getLogger("app.services.scan_dispatch")

CELERY_SCAN_TASK_NAME = "app.tasks.scan_tasks.run_scan_task"


async def dispatch_scan(db: AsyncSession, scan_id: uuid.UUID) -> bool:
    """Attempts to hand a PENDING scan to Celery. Returns True iff this
    attempt succeeded (the scan is now QUEUED with a celery_task_id).
    Never raises -- a broker outage here is an expected, handled
    condition, not an exceptional one."""
    await scans_service.record_dispatch_attempt(db, scan_id)
    await db.commit()

    try:
        celery_app = get_celery_app()
        # send_task() is a synchronous call to the Celery/Redis client
        # library (there is no official async client) -- run it off the
        # event loop so one broker round-trip never blocks every other
        # in-flight request on this worker.
        async_result = await asyncio.to_thread(
            celery_app.send_task, CELERY_SCAN_TASK_NAME, args=[str(scan_id)]
        )
    except Exception as exc:
        logger.warning("dispatch_scan: could not enqueue scan %s: %s", scan_id, exc)
        return False

    changed = await scans_service.mark_dispatched(db, scan_id, async_result.id)
    await db.commit()
    if not changed:
        # The scan stopped being PENDING between our transaction above
        # and now (e.g. it was cancelled concurrently). The task was
        # already sent and cannot be un-sent; it will see CANCELLED when
        # it runs and its own QUEUED->RUNNING transition will simply
        # fail closed (transition_scan_status returns False), so no
        # terminal state is at risk -- see app/tasks/scan_tasks.py.
        logger.info(
            "dispatch_scan: scan %s was no longer PENDING when marking dispatched; "
            "task %s already sent and will no-op against the current state",
            scan_id,
            async_result.id,
        )
    return True


def best_effort_revoke(celery_task_id: str | None) -> None:
    """Prevents a QUEUED-but-not-yet-started task from starting after
    its scan was already finalized to CANCELLED. Explicitly NOT relied
    on as the mechanism that makes cancellation correct -- the state
    machine (QUEUED -> CANCELLED happens in the DB first, independently
    of whether this call succeeds) is what's authoritative. This is a
    courtesy to avoid wasted work, not a safety boundary; never called
    with terminate=True against a RUNNING task (see services/scans.py
    and app/tasks/scan_tasks.py for the cooperative-cancellation path a
    RUNNING scan actually takes)."""
    if not celery_task_id:
        return
    try:
        get_celery_app().control.revoke(celery_task_id, terminate=False)
    except Exception as exc:  # pragma: no cover - best-effort by design
        logger.warning("best_effort_revoke: could not revoke task %s: %s", celery_task_id, exc)
