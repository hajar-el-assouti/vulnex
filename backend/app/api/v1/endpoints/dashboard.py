"""GET /dashboard/stats

Read-only and session-protected, so no CSRF check (only mutating
endpoints use require_csrf). All numbers come from owner-scoped
queries in app/services/dashboard.py.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.dashboard import DashboardStats
from app.services import dashboard as dashboard_service

router = APIRouter()


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DashboardStats:
    return await dashboard_service.get_dashboard_stats(db, owner_id=user.id)
