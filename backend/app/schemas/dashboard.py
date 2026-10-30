"""Dashboard stats response schemas.

Every number comes from an owner-scoped SQL aggregate in
app/services/dashboard.py. A real zero is returned as 0, never left
out or replaced by a placeholder; the frontend decides how to show it."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class SeverityCount(BaseModel):
    severity: str
    count: int


class ModuleUsageCount(BaseModel):
    module_slug: str
    module_name: str
    run_count: int


class FindingsTrendPoint(BaseModel):
    """One day's worth of findings created, for the trend chart."""

    date: str  # ISO date (YYYY-MM-DD), not a datetime -- this is a day bucket
    count: int


class RecentScanSummary(BaseModel):
    id: UUID
    target_id: UUID
    target_name: str
    status: str
    created_at: datetime
    finished_at: datetime | None


class RecentFindingSummary(BaseModel):
    id: UUID
    scan_id: UUID
    target_name: str
    title: str
    severity: str
    confidence: str
    created_at: datetime


class PlatformStatus(BaseModel):
    """Platform status from real checks. database is always True here,
    since this request already ran a query; redis_reachable is a real
    PING."""

    database_reachable: bool = True
    redis_reachable: bool


class DashboardStats(BaseModel):
    total_targets: int
    authorized_targets: int
    scans_completed: int
    scans_running: int
    scans_failed: int
    scans_total: int
    findings_total: int
    findings_by_severity: list[SeverityCount] = Field(default_factory=list)
    findings_trend: list[FindingsTrendPoint] = Field(default_factory=list)
    recent_scans: list[RecentScanSummary] = Field(default_factory=list)
    recent_findings: list[RecentFindingSummary] = Field(default_factory=list)
    module_usage: list[ModuleUsageCount] = Field(default_factory=list)
    platform_status: PlatformStatus
