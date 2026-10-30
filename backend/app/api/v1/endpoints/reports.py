"""POST /reports, GET /reports, GET /reports/{id},
GET /reports/{id}/download

Generation is synchronous and CSRF-protected. Downloads are streamed
through an authenticated endpoint that re-checks ownership on every
call, never served as static files.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_csrf
from app.models.user import User
from app.schemas.reports import ReportCreateRequest, ReportListResponse, ReportPublic
from app.services import reports as reports_service

router = APIRouter()

_CONTENT_TYPES = {"pdf": "application/pdf", "html": "text/html; charset=utf-8"}


@router.post(
    "/reports",
    response_model=ReportPublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def create_report(
    data: ReportCreateRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportPublic:
    try:
        report = await reports_service.generate_report(
            db,
            owner_id=user.id,
            generated_by_id=user.id,
            generated_by_email=user.email,
            scan_id=data.scan_id,
            report_format=data.format,
        )
    except reports_service.ReportScanNotFoundError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    except reports_service.ScanNotTerminalError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is still {exc.status} -- a report can only be generated once a scan "
            "has finished (completed, failed, or cancelled)",
        )
    except Exception:
        # generate_report() has already marked the Report row FAILED
        # and committed that before re-raising (see its own
        # try/except) -- this is a real, unexpected rendering error,
        # never silently swallowed, and the Report row survives as a
        # visible FAILED record rather than vanishing.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Report generation failed",
        )
    return ReportPublic.model_validate(report)


@router.get("/reports", response_model=ReportListResponse)
async def list_reports(
    scan_id: uuid.UUID | None = None,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportListResponse:
    items = await reports_service.list_reports_for_owner(db, user.id, scan_id=scan_id)
    return ReportListResponse(items=[ReportPublic.model_validate(r) for r in items])


@router.get("/reports/{report_id}", response_model=ReportPublic)
async def get_report(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ReportPublic:
    try:
        report = await reports_service.get_report_for_owner(db, user.id, report_id)
    except reports_service.ReportNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return ReportPublic.model_validate(report)


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    try:
        report, content = await reports_service.get_report_file_for_owner(db, user.id, report_id)
    except reports_service.ReportNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    extension = report.format.value
    content_type = _CONTENT_TYPES.get(extension, "application/octet-stream")
    return Response(
        content=content,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="report-{report.scan_id}.{extension}"',
            # The API's own SecurityHeadersMiddleware already sets a
            # strict default-src 'none' CSP for every JSON response;
            # repeated here explicitly because this endpoint returns a
            # browser-renderable HTML body for the html format, which
            # must never execute script even if a finding's own
            # (already-escaped, see report_builder.py) text somehow
            # still reached the page.
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
        },
    )
