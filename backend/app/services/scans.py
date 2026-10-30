"""Scan lifecycle: creation, status transitions, cancellation, events.

The key function is `transition_scan_status()`: every status change,
from the API or from a worker, goes through it. It is a conditional
`UPDATE ... WHERE status NOT IN (terminal) [AND status IN (from)]`,
never a plain assignment, so a late worker can't overwrite a terminal
state and two concurrent callers can't both "win".
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.scan import TERMINAL_SCAN_STATUSES, Scan, ScanStatus
from app.models.scan_event import ScanEvent, ScanEventType
from app.models.scan_module_run import ScanModuleRun, ScanModuleRunStatus
from app.models.target import Target
from app.schemas.scans import ScanCreateRequest
from app.services import scan_modules as scan_modules_service
from app.services.targets import TargetNotAuthorizedError, ensure_target_is_authorized

# A scan is "active" (one allowed at a time per target -- see
# create_scan) in every non-terminal status, including PENDING (created
# but not yet dispatched) and CANCELLING (cancellation in flight).
ACTIVE_SCAN_STATUSES = tuple(s for s in ScanStatus if s not in TERMINAL_SCAN_STATUSES)



class ScanNotFoundError(Exception):
    """Same reasoning as TargetNotFoundError: covers both "doesn't
    exist" and "exists but you don't own the target it belongs to",
    collapsed into one 404 so ids can't be enumerated."""


class ScanAlreadyInProgressError(Exception):
    def __init__(self, target_id: uuid.UUID) -> None:
        self.target_id = target_id
        super().__init__(f"Target {target_id} already has an active scan")


class ScanNotCancellableError(Exception):
    def __init__(self, scan_id: uuid.UUID, status: ScanStatus) -> None:
        self.scan_id = scan_id
        self.status = status
        super().__init__(f"Scan {scan_id} cannot be cancelled from status {status.value!r}")


class ActiveTestingNotConfirmedError(Exception):
    """Raised when `modules` includes a module with
    `requires_active_confirmation=True` but the request doesn't set
    `active_testing_confirmed`.

    Driven by the module's own flag, so a future active module is
    covered as soon as its migration marks it, with no new if-branch
    here. The column defaults to True (fail closed). Confirmation is
    required when the scan is created; a module being enabled is not
    enough. Mapped to a 400 by the API."""

    def __init__(self, slugs: list[str]) -> None:
        self.slugs = slugs
        super().__init__(
            "the following module(s) require active_testing_confirmed=true on the scan "
            f"creation request: {', '.join(sorted(slugs))}"
        )


async def record_event(
    db: AsyncSession,
    scan_id: uuid.UUID,
    event_type: ScanEventType,
    *,
    message: str | None = None,
    payload: dict | None = None,
) -> ScanEvent:
    event = ScanEvent(scan_id=scan_id, event_type=event_type, message=message, payload=payload or {})
    db.add(event)
    await db.flush()
    return event


async def create_scan(
    db: AsyncSession,
    *,
    owner_id: uuid.UUID,
    initiated_by_id: uuid.UUID,
    data: ScanCreateRequest,
) -> Scan:
    """Validates target ownership + authorization, resolves the module
    list, refuses a duplicate active scan on the same target, and
    commits the scan as PENDING with dispatched_at=NULL (see
    app/models/scan.py's outbox-style dispatch comment -- Celery is
    deliberately NOT touched here; the caller dispatches after this
    transaction commits, via services/scan_dispatch.py)."""
    target_result = await db.execute(
        select(Target).where(Target.id == data.target_id, Target.owner_id == owner_id)
    )
    target = target_result.scalar_one_or_none()
    if target is None:
        raise ScanNotFoundError(f"target {data.target_id} not found for this owner")

    # Raises TargetNotAuthorizedError, mapped to 403 by the caller.
    # Checked on every scan creation, never trusted from the UI.
    ensure_target_is_authorized(target)

    active_result = await db.execute(
        select(Scan.id).where(
            Scan.target_id == target.id, Scan.status.in_(ACTIVE_SCAN_STATUSES)
        )
    )
    if active_result.first() is not None:
        raise ScanAlreadyInProgressError(target.id)

    modules = (
        await scan_modules_service.get_enabled_modules_by_slugs(db, data.modules)
        if data.modules
        else await scan_modules_service.list_enabled_modules(db)
    )
    if not modules:
        raise scan_modules_service.UnknownOrDisabledModuleError("<no enabled modules>")

    # Any resolved module that requires confirmation blocks scan
    # creation unless the request confirms it. Checked on every scan
    # creation, never trusted from the UI. Checked against the resolved
    # module list, not the raw request, so it also covers the "no modules
    # specified -> every enabled module" case.
    modules_requiring_confirmation = sorted(
        module.slug for module in modules if module.requires_active_confirmation
    )
    if modules_requiring_confirmation and not data.active_testing_confirmed:
        raise ActiveTestingNotConfirmedError(modules_requiring_confirmation)

    scan = Scan(
        target_id=target.id,
        initiated_by_id=initiated_by_id,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.flush()

    for module in modules:
        db.add(
            ScanModuleRun(
                scan_id=scan.id,
                scan_module_id=module.id,
                status=ScanModuleRunStatus.PENDING,
            )
        )

    await record_event(
        db,
        scan.id,
        ScanEventType.CREATED,
        message="Scan created",
        payload={"modules": [m.slug for m in modules]},
    )
    await db.flush()
    return scan


async def transition_scan_status(
    db: AsyncSession,
    scan_id: uuid.UUID,
    *,
    to_status: ScanStatus,
    from_statuses: Iterable[ScanStatus] | None = None,
    extra_values: dict | None = None,
) -> bool:
    """The race-safe choke point described in the module docstring.
    Returns True iff a row was actually updated -- callers must check
    this and treat False as "someone else already moved this scan
    elsewhere", not as an error to retry blindly."""
    values: dict = {"status": to_status}
    if extra_values:
        values.update(extra_values)

    stmt = update(Scan).where(Scan.id == scan_id, Scan.status.notin_(TERMINAL_SCAN_STATUSES))
    if from_statuses is not None:
        stmt = stmt.where(Scan.status.in_(list(from_statuses)))
    stmt = stmt.values(**values)

    result = await db.execute(stmt)
    await db.flush()
    return result.rowcount == 1


async def record_dispatch_attempt(db: AsyncSession, scan_id: uuid.UUID) -> None:
    await db.execute(
        update(Scan).where(Scan.id == scan_id).values(dispatch_attempts=Scan.dispatch_attempts + 1)
    )
    await db.flush()


async def mark_dispatched(db: AsyncSession, scan_id: uuid.UUID, celery_task_id: str) -> bool:
    return await transition_scan_status(
        db,
        scan_id,
        to_status=ScanStatus.QUEUED,
        from_statuses=[ScanStatus.PENDING],
        extra_values={
            "celery_task_id": celery_task_id,
            "dispatched_at": datetime.now(timezone.utc),
        },
    )


async def rerun_scan(
    db: AsyncSession,
    *,
    owner_id: uuid.UUID,
    initiated_by_id: uuid.UUID,
    scan_id: uuid.UUID,
    active_testing_confirmed: bool,
) -> Scan:
    """Reruns a scan with the same modules, after checking authorization
    again.

    Reads the original scan's modules (from its module_runs) and passes
    them to create_scan() as a new ScanCreateRequest, so every check
    runs again: target ownership, authorization, duplicate active scan,
    active testing confirmation. The original `active_testing_confirmed`
    is never reused: the caller must send it again."""
    original_result = await db.execute(
        select(Scan)
        .join(Target, Target.id == Scan.target_id)
        .where(Scan.id == scan_id, Target.owner_id == owner_id)
        .options(selectinload(Scan.module_runs).selectinload(ScanModuleRun.module))
    )
    original = original_result.scalar_one_or_none()
    if original is None:
        raise ScanNotFoundError(scan_id)

    module_slugs = [run.module.slug for run in original.module_runs if run.module is not None]
    if not module_slugs:
        raise scan_modules_service.UnknownOrDisabledModuleError("<original scan has no module runs>")

    return await create_scan(
        db,
        owner_id=owner_id,
        initiated_by_id=initiated_by_id,
        data=ScanCreateRequest(
            target_id=original.target_id,
            modules=module_slugs,
            active_testing_confirmed=active_testing_confirmed,
        ),
    )


async def get_scan_for_owner(db: AsyncSession, owner_id: uuid.UUID, scan_id: uuid.UUID) -> Scan:
    result = await db.execute(
        select(Scan)
        .join(Target, Target.id == Scan.target_id)
        .where(Scan.id == scan_id, Target.owner_id == owner_id)
        # Load .module with module_runs, and Scan.findings, so the response
        # schemas never trigger a lazy load outside the session.
        .options(
            selectinload(Scan.module_runs).selectinload(ScanModuleRun.module),
            selectinload(Scan.findings),
        )
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise ScanNotFoundError(scan_id)
    return scan


async def list_scans_for_owner(
    db: AsyncSession, owner_id: uuid.UUID, *, target_id: uuid.UUID | None = None
) -> list[Scan]:
    stmt = (
        select(Scan)
        .join(Target, Target.id == Scan.target_id)
        .where(Target.owner_id == owner_id)
        .options(
            selectinload(Scan.module_runs).selectinload(ScanModuleRun.module),
            selectinload(Scan.findings),
        )
        .order_by(Scan.created_at.desc())
    )
    if target_id is not None:
        stmt = stmt.where(Scan.target_id == target_id)
    result = await db.execute(stmt)
    return list(result.scalars().unique().all())


async def list_scan_events(db: AsyncSession, scan_id: uuid.UUID) -> list[ScanEvent]:
    result = await db.execute(
        select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at)
    )
    return list(result.scalars().all())


async def request_cancel_scan(db: AsyncSession, scan: Scan) -> Scan:
    """Idempotent: cancelling a scan that is already CANCELLING or
    CANCELLED returns it unchanged. A COMPLETED or FAILED scan can't
    be cancelled and raises."""
    if scan.status in (ScanStatus.CANCELLING, ScanStatus.CANCELLED):
        return scan

    if scan.status in (ScanStatus.PENDING, ScanStatus.QUEUED):
        # Never picked up (or not yet dispatched) -- finalize directly,
        # nothing cooperative to wait for. A best-effort task.revoke()
        # against any celery_task_id is the caller's job (needs the
        # Celery app; kept out of this DB-only service -- see
        # services/scan_dispatch.py::cancel_dispatch).
        now = datetime.now(timezone.utc)
        changed = await transition_scan_status(
            db,
            scan.id,
            to_status=ScanStatus.CANCELLED,
            from_statuses=[ScanStatus.PENDING, ScanStatus.QUEUED],
            extra_values={"cancel_requested_at": now, "finished_at": now},
        )
        if changed:
            await record_event(db, scan.id, ScanEventType.CANCELLED, message="Cancelled before start")
            await db.refresh(scan)
        return scan

    if scan.status == ScanStatus.RUNNING:
        now = datetime.now(timezone.utc)
        changed = await transition_scan_status(
            db,
            scan.id,
            to_status=ScanStatus.CANCELLING,
            from_statuses=[ScanStatus.RUNNING],
            extra_values={"cancel_requested_at": now},
        )
        if changed:
            await record_event(
                db, scan.id, ScanEventType.LOG, message="Cancellation requested; waiting for worker"
            )
            await db.refresh(scan)
        return scan

    raise ScanNotCancellableError(scan.id, scan.status)
