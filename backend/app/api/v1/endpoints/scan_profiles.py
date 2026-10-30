"""GET/POST /scan-profiles, DELETE /scan-profiles/{id}"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_csrf
from app.models.user import User
from app.schemas.scan_profiles import (
    ScanProfileCreateRequest,
    ScanProfileListResponse,
    ScanProfilePublic,
)
from app.services import scan_profiles as scan_profiles_service

router = APIRouter()


@router.get("/scan-profiles", response_model=ScanProfileListResponse)
async def list_scan_profiles(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanProfileListResponse:
    profiles = await scan_profiles_service.list_profiles_for_owner(db, user.id)
    return ScanProfileListResponse(items=[ScanProfilePublic.model_validate(p) for p in profiles])


@router.post(
    "/scan-profiles",
    response_model=ScanProfilePublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def create_scan_profile(
    data: ScanProfileCreateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanProfilePublic:
    try:
        profile = await scan_profiles_service.create_profile(
            db,
            user.id,
            name=data.name,
            description=data.description,
            module_slugs=data.module_slugs,
            active_testing_confirmed_default=data.active_testing_confirmed_default,
        )
    except scan_profiles_service.UnknownModuleSlugError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scan module slug: {exc.slug!r}",
        )
    return ScanProfilePublic.model_validate(profile)


@router.delete(
    "/scan-profiles/{profile_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
async def delete_scan_profile(
    profile_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    try:
        await scan_profiles_service.delete_profile(db, user.id, profile_id)
    except scan_profiles_service.ScanProfileNotFoundError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan profile not found")
