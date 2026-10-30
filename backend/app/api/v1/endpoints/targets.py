"""POST/GET /targets, GET /targets/{id}, POST /targets/{id}/authorize.

Authorization recording is a separate, explicit, CSRF-protected action
from target creation -- a target is never created already-authorized
from client input (see app/schemas/targets.py). `is_authorized=true`
alone still proves nothing when a scan is actually created; see
app/services/targets.py::ensure_target_is_authorized, called from
services/scans.py::create_scan, not duplicated here.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_csrf
from app.models.user import User
from app.schemas.targets import (
    TargetAuthorizeRequest,
    TargetCreateRequest,
    TargetListResponse,
    TargetPublic,
)
from app.services import targets as targets_service

router = APIRouter()


@router.post(
    "/targets",
    response_model=TargetPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def create_target(
    data: TargetCreateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TargetPublic:
    try:
        target = await targets_service.create_target(db, user.id, data)
    except targets_service.TargetAlreadyExistsError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="You already have a target with this base URL",
        )
    await db.commit()
    return TargetPublic.model_validate(target)


@router.get("/targets", response_model=TargetListResponse)
async def list_targets(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> TargetListResponse:
    items = await targets_service.list_targets_for_owner(db, user.id)
    return TargetListResponse(items=[TargetPublic.model_validate(t) for t in items])


@router.get("/targets/{target_id}", response_model=TargetPublic)
async def get_target(
    target_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TargetPublic:
    try:
        target = await targets_service.get_target_for_owner(db, user.id, target_id)
    except targets_service.TargetNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return TargetPublic.model_validate(target)


@router.post(
    "/targets/{target_id}/authorize",
    response_model=TargetPublic,
    dependencies=[Depends(require_csrf)],
)
async def authorize_target(
    target_id: uuid.UUID,
    data: TargetAuthorizeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TargetPublic:
    """Records a claim of authorization -- see this module's docstring
    and app/models/target.py. There is no endpoint to flip
    is_authorized=true any other way."""
    try:
        target = await targets_service.get_target_for_owner(db, user.id, target_id)
    except targets_service.TargetNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    target = await targets_service.authorize_target(
        db, target, authorization_reference=data.authorization_reference, authorized_by_id=user.id
    )
    await db.commit()
    # authorize_target assigns ORM attributes directly and flushes; the
    # server-computed `updated_at` (onupdate=func.now()) isn't known
    # Python-side after that -- refresh to fetch it back rather than
    # leaving it expired for Pydantic's (synchronous) serialization to
    # trip over.
    await db.refresh(target)
    return TargetPublic.model_validate(target)
