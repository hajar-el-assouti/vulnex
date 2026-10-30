"""POST/GET /scans, GET /scans/{id}, GET /scans/{id}/status,
GET /scans/{id}/events, POST /scans/{id}/cancel.

Every mutating endpoint here is session-gated (get_current_user),
CSRF-protected (require_csrf), and ownership-checked server-side via
services/scans.py (never trusting a client-supplied owner/user id).
Creation is idempotent against accidental double-submission: a second
POST while a scan is already active on the same target is a 409, not a
second scan (see services/scans.py::create_scan).
"""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_csrf
from app.models.user import User
from app.schemas.scans import (
    ScanCreateRequest,
    ScanEventListResponse,
    ScanEventPublic,
    ScanListResponse,
    ScanPublic,
    ScanRerunRequest,
    ScanStatusResponse,
)
from app.services import scan_dispatch, scan_modules as scan_modules_service, scans as scans_service
from app.services.targets import TargetNotAuthorizedError

router = APIRouter()
logger = logging.getLogger("app.scans")


@router.post(
    "/scans",
    response_model=ScanPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def create_scan(
    data: ScanCreateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanPublic:
    try:
        scan = await scans_service.create_scan(
            db, owner_id=user.id, initiated_by_id=user.id, data=data
        )
    except scans_service.ScanNotFoundError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    except TargetNotAuthorizedError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This target is not authorized for scanning",
        )
    except scans_service.ScanAlreadyInProgressError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This target already has an active scan",
        )
    except scan_modules_service.UnknownOrDisabledModuleError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown or disabled scan module: {exc.slug}",
        )
    except scans_service.ActiveTestingNotConfirmedError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "active_web_testing sends active test requests to the target and requires "
                "active_testing_confirmed=true to run"
            ),
        )

    # The scan is already committed as PENDING at this point (create_scan
    # flushes but services never commit -- the endpoint owns the commit,
    # same convention as app/services/auth.py). Only AFTER this commit
    # succeeds do we attempt to hand it to Celery -- see
    # app/models/scan.py's outbox-style dispatch comment. A dispatch
    # failure here is not an API error: the scan still exists and will be
    # retried by app/tasks/maintenance.py::reconcile_pending_scans.
    await db.commit()
    dispatched = await scan_dispatch.dispatch_scan(db, scan.id)
    if not dispatched:
        logger.warning("create_scan: scan %s committed but initial dispatch failed; "
                        "the periodic reconciler will retry it", scan.id)
    # Re-fetch with module_runs eagerly loaded (the plain `scan` object
    # above never had that relationship populated, since create_scan
    # adds ScanModuleRun rows directly rather than through
    # scan.module_runs.append(...)) -- get_scan_for_owner's
    # selectinload gives ScanPublic a fully-loaded object to serialize.
    scan = await scans_service.get_scan_for_owner(db, user.id, scan.id)
    return ScanPublic.model_validate(scan)


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    target_id: uuid.UUID | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanListResponse:
    items = await scans_service.list_scans_for_owner(db, user.id, target_id=target_id)
    return ScanListResponse(items=[ScanPublic.model_validate(s) for s in items])


async def _get_owned_scan(db: AsyncSession, user: User, scan_id: uuid.UUID):
    try:
        return await scans_service.get_scan_for_owner(db, user.id, scan_id)
    except scans_service.ScanNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")


@router.get("/scans/{scan_id}", response_model=ScanPublic)
async def get_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanPublic:
    scan = await _get_owned_scan(db, user, scan_id)
    return ScanPublic.model_validate(scan)


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanStatusResponse:
    """Deliberately a small, separate payload from GET /scans/{id} --
    this is the endpoint the frontend polls on a timer (see the
    frontend's useScanStatus hook), and it should stay cheap to call
    often without re-fetching module-run details every tick."""
    scan = await _get_owned_scan(db, user, scan_id)
    return ScanStatusResponse(
        id=scan.id,
        status=scan.status.value,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        cancel_requested_at=scan.cancel_requested_at,
    )


@router.get("/scans/{scan_id}/events", response_model=ScanEventListResponse)
async def get_scan_events(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanEventListResponse:
    await _get_owned_scan(db, user, scan_id)  # 404s / ownership-checks first
    events = await scans_service.list_scan_events(db, scan_id)
    return ScanEventListResponse(items=[ScanEventPublic.model_validate(e) for e in events])


@router.post(
    "/scans/{scan_id}/cancel",
    response_model=ScanPublic,
    dependencies=[Depends(require_csrf)],
)
async def cancel_scan(
    scan_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanPublic:
    scan = await _get_owned_scan(db, user, scan_id)

    try:
        scan = await scans_service.request_cancel_scan(db, scan)
    except scans_service.ScanNotCancellableError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This scan has already finished and cannot be cancelled",
        )
    await db.commit()

    # Best-effort only -- the DB transition above is what's authoritative
    # (see services/scans.py::request_cancel_scan and
    # services/scan_dispatch.py::best_effort_revoke's own docstring).
    if scan.celery_task_id:
        scan_dispatch.best_effort_revoke(scan.celery_task_id)

    # Re-fetch with module_runs eagerly loaded for the response -- same
    # reasoning as create_scan above: request_cancel_scan's internal
    # db.refresh() can leave the previously selectinload()'d
    # module_runs collection expired.
    scan = await scans_service.get_scan_for_owner(db, user.id, scan.id)
    return ScanPublic.model_validate(scan)


@router.post(
    "/scans/{scan_id}/rerun",
    response_model=ScanPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def rerun_scan(
    scan_id: uuid.UUID,
    data: ScanRerunRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanPublic:
    """Creates a new scan with the same target and modules as `scan_id`.

    Goes through create_scan(), so every check and error mapping is the
    same."""
    try:
        new_scan = await scans_service.rerun_scan(
            db,
            owner_id=user.id,
            initiated_by_id=user.id,
            scan_id=scan_id,
            active_testing_confirmed=data.active_testing_confirmed,
        )
    except scans_service.ScanNotFoundError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    except TargetNotAuthorizedError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This target is not authorized for scanning",
        )
    except scans_service.ScanAlreadyInProgressError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This target already has an active scan",
        )
    except scan_modules_service.UnknownOrDisabledModuleError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown or disabled scan module: {exc.slug}",
        )
    except scans_service.ActiveTestingNotConfirmedError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "active_web_testing sends active test requests to the target and requires "
                "active_testing_confirmed=true to run"
            ),
        )

    await db.commit()
    dispatched = await scan_dispatch.dispatch_scan(db, new_scan.id)
    if not dispatched:
        logger.warning(
            "rerun_scan: scan %s committed but initial dispatch failed; "
            "the periodic reconciler will retry it",
            new_scan.id,
        )
    new_scan = await scans_service.get_scan_for_owner(db, user.id, new_scan.id)
    return ScanPublic.model_validate(new_scan)
