"""GET /scan-modules -- read-only, no create/update/delete here.

Only is_enabled=true modules are ever returned (see
services/scan_modules.py); today that's exactly one row, the
non-offensive diagnostic module (app/tasks/diagnostic.py). A disabled
or future, not-yet-implemented engine must never appear in this list --
that would present it to the frontend as something a user can select
and run, which it isn't.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.scan_modules import ScanModuleListResponse, ScanModulePublic
from app.services import scan_modules as scan_modules_service

router = APIRouter()


@router.get("/scan-modules", response_model=ScanModuleListResponse)
async def list_scan_modules(
    user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
) -> ScanModuleListResponse:
    modules = await scan_modules_service.list_enabled_modules(db)
    return ScanModuleListResponse(items=[ScanModulePublic.model_validate(m) for m in modules])
