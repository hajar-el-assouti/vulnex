"""Report generation and secure download.

Generation is synchronous (in the request, not a Celery task): all
inputs are already stored, there is no network call, and rendering is
fast in-memory work. The Report row still goes through
PENDING -> GENERATING -> READY/FAILED, so moving to a background task
later wouldn't change the API or the schema.

Ownership is checked through Target.owner_id -> Scan -> Report.
Report files are never served statically: get_report_file_for_owner()
re-checks ownership on every download.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.models.report import Report, ReportFormat, ReportStatus
from app.models.scan import Scan, TERMINAL_SCAN_STATUSES
from app.models.scan_module_run import ScanModuleRun
from app.models.target import Target
from app.services.report_builder import (
    ReportContext,
    ReportFindingView,
    ReportModuleRunView,
    render_html,
    render_pdf,
)


class ReportScanNotFoundError(Exception):
    """Same "404 for both missing and unauthorized" reasoning as
    ScanNotFoundError in services/scans.py."""


class ReportNotFoundError(Exception):
    pass


class ScanNotTerminalError(Exception):
    """A report is a summary of what a scan found -- generating one
    from a scan that is still PENDING/QUEUED/RUNNING/CANCELLING would
    either be empty or describe a half-finished run as if it were
    final. Wait for the scan to reach a terminal state first."""

    def __init__(self, scan_id: uuid.UUID, status: str) -> None:
        self.scan_id = scan_id
        self.status = status
        super().__init__(f"Scan {scan_id} is not terminal yet (status={status})")


def _storage_dir() -> Path:
    path = Path(get_settings().report_storage_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


async def _get_owned_scan_for_report(
    db: AsyncSession, owner_id: uuid.UUID, scan_id: uuid.UUID
) -> Scan:
    result = await db.execute(
        select(Scan)
        .join(Target, Target.id == Scan.target_id)
        .where(Scan.id == scan_id, Target.owner_id == owner_id)
        .options(
            selectinload(Scan.target),
            selectinload(Scan.findings),
            selectinload(Scan.module_runs).selectinload(ScanModuleRun.module),
        )
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise ReportScanNotFoundError(scan_id)
    return scan


def _build_context(report_id: uuid.UUID, scan: Scan, generated_by_email: str) -> ReportContext:
    active_testing_performed = any(
        run.module is not None and run.module.slug == "active_web_testing" for run in scan.module_runs
    )
    return ReportContext(
        report_id=str(report_id),
        generated_at=datetime.now(timezone.utc),
        generated_by_email=generated_by_email,
        scan_id=str(scan.id),
        scan_status=scan.status.value,
        scan_started_at=scan.started_at,
        scan_finished_at=scan.finished_at,
        target_name=scan.target.name,
        target_base_url=scan.target.base_url,
        target_authorization_reference=scan.target.authorization_reference,
        target_authorized_at=scan.target.authorized_at,
        modules=[
            ReportModuleRunView(
                slug=run.module.slug if run.module else "unknown",
                name=run.module.name if run.module else "unknown",
                description=run.module.description if run.module else None,
                status=run.status.value,
            )
            for run in scan.module_runs
        ],
        findings=[
            ReportFindingView(
                title=f.title,
                severity=f.severity.value,
                confidence=f.confidence.value,
                category=(f.evidence or {}).get("_check", "other") if isinstance(f.evidence, dict) else "other",
                description=f.description,
                affected_url=f.affected_url,
                cwe_id=f.cwe_id,
                evidence=f.evidence or {},
                remediation=f.remediation,
            )
            for f in scan.findings
        ],
        active_testing_performed=active_testing_performed,
    )


async def generate_report(
    db: AsyncSession,
    *,
    owner_id: uuid.UUID,
    generated_by_id: uuid.UUID,
    generated_by_email: str,
    scan_id: uuid.UUID,
    report_format: str,
) -> Report:
    scan = await _get_owned_scan_for_report(db, owner_id, scan_id)
    if scan.status not in TERMINAL_SCAN_STATUSES:
        raise ScanNotTerminalError(scan_id, scan.status.value)

    fmt = ReportFormat(report_format)
    report = Report(
        scan_id=scan.id,
        generated_by_id=generated_by_id,
        format=fmt,
        status=ReportStatus.GENERATING,
    )
    db.add(report)
    await db.flush()

    try:
        ctx = _build_context(report.id, scan, generated_by_email)
        if fmt == ReportFormat.PDF:
            content: bytes = render_pdf(ctx)
            extension = "pdf"
        else:
            content = render_html(ctx).encode("utf-8")
            extension = "html"

        relative_path = f"{report.id}.{extension}"
        (_storage_dir() / relative_path).write_bytes(content)

        report.status = ReportStatus.READY
        report.storage_path = relative_path
        report.completed_at = datetime.now(timezone.utc)
    except Exception:
        report.status = ReportStatus.FAILED
        await db.commit()
        raise

    await db.commit()
    await db.refresh(report)
    return report


async def list_reports_for_owner(
    db: AsyncSession, owner_id: uuid.UUID, *, scan_id: uuid.UUID | None = None
) -> list[Report]:
    stmt = (
        select(Report)
        .join(Scan, Scan.id == Report.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .where(Target.owner_id == owner_id)
        .order_by(Report.created_at.desc())
    )
    if scan_id is not None:
        stmt = stmt.where(Report.scan_id == scan_id)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_report_for_owner(db: AsyncSession, owner_id: uuid.UUID, report_id: uuid.UUID) -> Report:
    result = await db.execute(
        select(Report)
        .join(Scan, Scan.id == Report.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .where(Report.id == report_id, Target.owner_id == owner_id)
    )
    report = result.scalar_one_or_none()
    if report is None:
        raise ReportNotFoundError(report_id)
    return report


async def get_report_file_for_owner(
    db: AsyncSession, owner_id: uuid.UUID, report_id: uuid.UUID
) -> tuple[Report, bytes]:
    """Returns the Report row AND its file bytes, re-checking
    ownership first -- the one path allowed to read a report file back
    off disk. Raises ReportNotFoundError if the report doesn't exist,
    isn't owned by this user, or isn't READY yet (a GENERATING/FAILED/
    PENDING report has no file to serve, and this is deliberately the
    same 404 rather than a different status code that would leak which
    case applies to an id the caller doesn't own)."""
    report = await get_report_for_owner(db, owner_id, report_id)
    if report.status != ReportStatus.READY or not report.storage_path:
        raise ReportNotFoundError(report_id)

    file_path = _storage_dir() / report.storage_path
    if not file_path.is_file():
        raise ReportNotFoundError(report_id)
    return report, file_path.read_bytes()
