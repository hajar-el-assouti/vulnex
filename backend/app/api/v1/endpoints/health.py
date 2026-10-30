from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.core.config import get_settings
from app.schemas.health import LivenessResponse, ReadinessResponse

router = APIRouter()
settings = get_settings()


@router.get("/health/live", response_model=LivenessResponse)
async def liveness() -> LivenessResponse:
    """Is the process up? No dependency checks -- this must stay cheap and
    never block on the database, or a DB outage would also take down the
    liveness probe and cause an orchestrator to kill/restart healthy pods
    for the wrong reason."""
    return LivenessResponse(
        status="ok",
        service=settings.project_name,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/health/ready", response_model=ReadinessResponse)
async def readiness(response: Response, db: AsyncSession = Depends(get_db)) -> ReadinessResponse:
    """Is the process up AND able to serve real requests? Does a real
    `SELECT 1` against the configured database. Returns HTTP 503 (not 200)
    when the database is unreachable, so load balancers / orchestrators
    correctly stop routing traffic here instead of reading a 200 body and
    assuming everything is fine."""
    try:
        await db.execute(text("SELECT 1"))
        database_status = "ok"
    except Exception:
        database_status = "unreachable"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status="ok" if database_status == "ok" else "unavailable",
        database=database_status,
        timestamp=datetime.now(timezone.utc),
    )
