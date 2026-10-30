"""GET /findings, GET /findings/{id}, PATCH /findings/{id}/status

Global findings page: filters, search, pagination, sorting, detail
view and status updates. Results are always scoped to the current
user by app/services/findings.py.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_csrf
from app.models.user import User
from app.schemas.findings import (
    FindingListResponse,
    FindingPublic,
    FindingStatusUpdateRequest,
)
from app.services import findings as findings_service

router = APIRouter()


@router.get("/findings", response_model=FindingListResponse)
async def list_findings(
    target_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    category: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = None,
    sort_by: str = "created_at",
    sort_desc: bool = True,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=findings_service.MAX_PAGE_SIZE),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingListResponse:
    items, total = await findings_service.list_findings_for_owner(
        db,
        owner_id=user.id,
        target_id=target_id,
        scan_id=scan_id,
        severity=severity,
        confidence=confidence,
        category=category,
        status_filter=status_filter,
        search=search,
        sort_by=sort_by,
        sort_desc=sort_desc,
        page=page,
        page_size=page_size,
    )
    return FindingListResponse(
        items=[FindingPublic(**findings_service.to_public_dict(f)) for f in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/findings/{finding_id}", response_model=FindingPublic)
async def get_finding(
    finding_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingPublic:
    try:
        finding = await findings_service.get_finding_for_owner(db, user.id, finding_id)
    except findings_service.FindingNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return FindingPublic(**findings_service.to_public_dict(finding))


@router.patch(
    "/findings/{finding_id}/status",
    response_model=FindingPublic,
    dependencies=[Depends(require_csrf)],
)
async def update_finding_status(
    finding_id: uuid.UUID,
    data: FindingStatusUpdateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> FindingPublic:
    try:
        finding = await findings_service.update_finding_status(
            db, user.id, finding_id, data.status
        )
    except findings_service.FindingNotFoundError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return FindingPublic(**findings_service.to_public_dict(finding))
