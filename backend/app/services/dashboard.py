"""Dashboard stats.

Every query is scoped to one owner (through Target.owner_id, same join
as services/scans.py::get_scan_for_owner) and uses a SQL aggregate.
A user with no targets gets zeros everywhere.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from redis.exceptions import RedisError
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis_client import get_redis_client
from app.models.scan import Scan, ScanStatus
from app.models.scan_finding import ScanFinding
from app.models.scan_module import ScanModule
from app.models.scan_module_run import ScanModuleRun
from app.models.target import Target
from app.schemas.dashboard import (
    DashboardStats,
    FindingsTrendPoint,
    ModuleUsageCount,
    PlatformStatus,
    RecentFindingSummary,
    RecentScanSummary,
    SeverityCount,
)

# How many days of history the trend chart covers -- a fixed, documented
# window, not "everything ever scanned", so the chart stays legible and
# the query stays cheap regardless of account age.
_TREND_WINDOW_DAYS = 30
_RECENT_LIMIT = 5


async def _redis_reachable() -> bool:
    try:
        client = get_redis_client()
        return bool(await client.ping())
    except (RedisError, RuntimeError, OSError):
        # RuntimeError: REDIS_URL not configured at all in this
        # deployment -- still a real, non-fabricated "no" answer.
        return False


async def get_dashboard_stats(db: AsyncSession, owner_id: uuid.UUID) -> DashboardStats:
    # --- targets ---------------------------------------------------
    targets_row = (
        await db.execute(
            select(
                func.count(Target.id),
                func.coalesce(func.sum(case((Target.is_authorized.is_(True), 1), else_=0)), 0),
            ).where(Target.owner_id == owner_id)
        )
    ).one()
    total_targets, authorized_targets = int(targets_row[0]), int(targets_row[1])

    # --- scans by status --------------------------------------------
    scans_by_status_rows = (
        await db.execute(
            select(Scan.status, func.count(Scan.id))
            .join(Target, Target.id == Scan.target_id)
            .where(Target.owner_id == owner_id)
            .group_by(Scan.status)
        )
    ).all()
    status_counts: dict[ScanStatus, int] = {status: 0 for status in ScanStatus}
    for status, count in scans_by_status_rows:
        status_counts[status] = int(count)
    scans_total = sum(status_counts.values())
    scans_running = status_counts[ScanStatus.RUNNING] + status_counts[ScanStatus.QUEUED]
    scans_completed = status_counts[ScanStatus.COMPLETED]
    scans_failed = status_counts[ScanStatus.FAILED]

    # --- findings total + by severity --------------------------------
    findings_total_row = (
        await db.execute(
            select(func.count(ScanFinding.id))
            .join(Scan, Scan.id == ScanFinding.scan_id)
            .join(Target, Target.id == Scan.target_id)
            .where(Target.owner_id == owner_id)
        )
    ).scalar_one()
    findings_total = int(findings_total_row)

    severity_rows = (
        await db.execute(
            select(ScanFinding.severity, func.count(ScanFinding.id))
            .join(Scan, Scan.id == ScanFinding.scan_id)
            .join(Target, Target.id == Scan.target_id)
            .where(Target.owner_id == owner_id)
            .group_by(ScanFinding.severity)
        )
    ).all()
    findings_by_severity = [
        SeverityCount(severity=severity.value, count=int(count)) for severity, count in severity_rows
    ]

    # --- findings trend (last _TREND_WINDOW_DAYS days, by day) -------
    since = datetime.now(timezone.utc) - timedelta(days=_TREND_WINDOW_DAYS)
    day_bucket = func.date(ScanFinding.created_at)
    trend_rows = (
        await db.execute(
            select(day_bucket, func.count(ScanFinding.id))
            .join(Scan, Scan.id == ScanFinding.scan_id)
            .join(Target, Target.id == Scan.target_id)
            .where(Target.owner_id == owner_id, ScanFinding.created_at >= since)
            .group_by(day_bucket)
            .order_by(day_bucket)
        )
    ).all()
    findings_trend = [
        FindingsTrendPoint(date=str(day), count=int(count)) for day, count in trend_rows
    ]

    # --- recent scans --------------------------------------------------
    recent_scans_rows = (
        await db.execute(
            select(Scan.id, Scan.target_id, Target.name, Scan.status, Scan.created_at, Scan.finished_at)
            .join(Target, Target.id == Scan.target_id)
            .where(Target.owner_id == owner_id)
            .order_by(Scan.created_at.desc())
            .limit(_RECENT_LIMIT)
        )
    ).all()
    recent_scans = [
        RecentScanSummary(
            id=row[0],
            target_id=row[1],
            target_name=row[2],
            status=row[3].value,
            created_at=row[4],
            finished_at=row[5],
        )
        for row in recent_scans_rows
    ]

    # --- recent findings -----------------------------------------------
    recent_findings_rows = (
        await db.execute(
            select(
                ScanFinding.id,
                ScanFinding.scan_id,
                Target.name,
                ScanFinding.title,
                ScanFinding.severity,
                ScanFinding.confidence,
                ScanFinding.created_at,
            )
            .join(Scan, Scan.id == ScanFinding.scan_id)
            .join(Target, Target.id == Scan.target_id)
            .where(Target.owner_id == owner_id)
            .order_by(ScanFinding.created_at.desc())
            .limit(_RECENT_LIMIT)
        )
    ).all()
    recent_findings = [
        RecentFindingSummary(
            id=row[0],
            scan_id=row[1],
            target_name=row[2],
            title=row[3],
            severity=row[4].value,
            confidence=row[5].value,
            created_at=row[6],
        )
        for row in recent_findings_rows
    ]

    # --- module usage ----------------------------------------------------
    module_usage_rows = (
        await db.execute(
            select(ScanModule.slug, ScanModule.name, func.count(ScanModuleRun.id))
            .join(ScanModule, ScanModule.id == ScanModuleRun.scan_module_id)
            .join(Scan, Scan.id == ScanModuleRun.scan_id)
            .join(Target, Target.id == Scan.target_id)
            .where(Target.owner_id == owner_id)
            .group_by(ScanModule.slug, ScanModule.name)
            .order_by(func.count(ScanModuleRun.id).desc())
        )
    ).all()
    module_usage = [
        ModuleUsageCount(module_slug=slug, module_name=name, run_count=int(count))
        for slug, name, count in module_usage_rows
    ]

    platform_status = PlatformStatus(redis_reachable=await _redis_reachable())

    return DashboardStats(
        total_targets=total_targets,
        authorized_targets=authorized_targets,
        scans_completed=scans_completed,
        scans_running=scans_running,
        scans_failed=scans_failed,
        scans_total=scans_total,
        findings_total=findings_total,
        findings_by_severity=findings_by_severity,
        findings_trend=findings_trend,
        recent_scans=recent_scans,
        recent_findings=recent_findings,
        module_usage=module_usage,
        platform_status=platform_status,
    )
