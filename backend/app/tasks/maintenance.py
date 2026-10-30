"""Periodic reconciliation tasks (Celery beat -- see app/celery_app.py).

These exist so two specific failure modes never leave a scan stuck
forever:

1. A scan was committed PENDING but the dispatch to Celery itself failed
   (Redis was briefly down, the API process crashed between the commit
   and the send_task() call). `reconcile_pending_scans` retries it, up
   to Settings.scan_dispatch_max_attempts, then gives up and marks it
   FAILED with an explanatory event -- never silently stuck PENDING.

2. A scan was moved to CANCELLING (cooperative cancellation requested)
   but the worker running it crashed, or was itself killed, before it
   ever checked the flag and finalized to CANCELLED.
   `reconcile_stuck_cancellations` force-finalizes it after a grace
   period. This is the documented, explicit limit of "cancellation is
   cooperative, not instantaneous" -- a scan can legitimately sit in
   CANCELLING for up to Settings.scan_cancellation_grace_seconds even in
   the worst case.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.celery_app import get_celery_app
from app.core.config import get_settings
from app.db.session import worker_scoped_session
from app.models.scan import Scan, ScanStatus
from app.models.scan_event import ScanEventType
from app.services import scan_dispatch, scans as scans_service

logger = logging.getLogger("app.tasks.maintenance")

celery_app = get_celery_app()


async def reconcile_pending_scans_logic(db) -> int:
    """Testable core logic, taking an already-open session -- see
    app/tasks/scan_tasks.py::run_scan_logic for why this split exists
    (the SQLite-backed unit-test fixture vs. the real-Postgres worker
    session)."""
    settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.scan_dispatch_stuck_after_seconds)
    retried = 0

    result = await db.execute(
        select(Scan).where(
            Scan.status == ScanStatus.PENDING,
            Scan.dispatched_at.is_(None),
            Scan.created_at <= cutoff,
        )
    )
    stuck_scans = list(result.scalars().all())

    for scan in stuck_scans:
        if scan.dispatch_attempts >= settings.scan_dispatch_max_attempts:
            await scans_service.transition_scan_status(
                db,
                scan.id,
                to_status=ScanStatus.FAILED,
                from_statuses=[ScanStatus.PENDING],
                extra_values={"finished_at": datetime.now(timezone.utc)},
            )
            await scans_service.record_event(
                db,
                scan.id,
                ScanEventType.ERROR,
                message=(
                    f"Giving up after {scan.dispatch_attempts} failed dispatch "
                    "attempts; the broker may be unreachable"
                ),
            )
            await db.commit()
            continue

        succeeded = await scan_dispatch.dispatch_scan(db, scan.id)
        retried += 1
        logger.info(
            "reconcile_pending_scans: retried dispatch for scan %s -> %s",
            scan.id,
            "succeeded" if succeeded else "still failing",
        )

    return retried


async def reconcile_stuck_cancellations_logic(db) -> int:
    settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=settings.scan_cancellation_grace_seconds)
    finalized = 0

    result = await db.execute(
        select(Scan).where(
            Scan.status == ScanStatus.CANCELLING,
            Scan.updated_at <= cutoff,
        )
    )
    stuck_scans = list(result.scalars().all())

    for scan in stuck_scans:
        changed = await scans_service.transition_scan_status(
            db,
            scan.id,
            to_status=ScanStatus.CANCELLED,
            from_statuses=[ScanStatus.CANCELLING],
            extra_values={"finished_at": datetime.now(timezone.utc)},
        )
        if changed:
            await scans_service.record_event(
                db,
                scan.id,
                ScanEventType.CANCELLED,
                message=(
                    "Force-finalized by reconciliation after "
                    f"{settings.scan_cancellation_grace_seconds}s in CANCELLING "
                    "with no worker update -- likely a crashed worker"
                ),
            )
            await db.commit()
            finalized += 1

    return finalized


async def _reconcile_pending_scans_async() -> int:
    async with worker_scoped_session() as db:
        return await reconcile_pending_scans_logic(db)


async def _reconcile_stuck_cancellations_async() -> int:
    async with worker_scoped_session() as db:
        return await reconcile_stuck_cancellations_logic(db)


@celery_app.task(name="app.tasks.maintenance.reconcile_pending_scans")
def reconcile_pending_scans() -> int:
    return asyncio.run(_reconcile_pending_scans_async())


@celery_app.task(name="app.tasks.maintenance.reconcile_stuck_cancellations")
def reconcile_stuck_cancellations() -> int:
    return asyncio.run(_reconcile_stuck_cancellations_async())
