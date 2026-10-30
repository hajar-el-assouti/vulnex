"""Findings: saving them from a module's results, and the global
list/detail/status views.

## Saving and deduplication (persist_module_findings)

The only place a dict shaped like Finding.to_dict() becomes a
ScanFinding row. Deduplication uses each dict's `_dedup_key`, within
the same scan only: the same finding in another scan is stored again
(each scan is its own run), but calling this twice for the same scan
creates the row once. A malformed entry (unknown severity, empty
title) is skipped without stopping the rest of the batch.

## Global list, detail and status

Every query is scoped to one owner through Target.owner_id -> Scan ->
ScanFinding, so another user's finding can't be returned.

"category" is not a column: every check already stores its slug in
`evidence['_check']`, so filtering reads that.
`ScanFinding.evidence[...].as_string()` works on both Postgres
(`->>`) and SQLite (`json_extract`).

The global list doesn't deduplicate again: that was done when saving,
and doing it across modules could hide two different real findings.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.scan import Scan
from app.models.scan_finding import Confidence, FindingStatus, ScanFinding, Severity
from app.models.scan_module import ScanModule
from app.models.target import Target

ALLOWED_SORT_FIELDS = frozenset({"created_at", "severity", "confidence"})
MAX_PAGE_SIZE = 100


async def persist_module_findings(
    db: AsyncSession,
    *,
    scan_id: uuid.UUID,
    scan_module_id: uuid.UUID | None,
    finding_dicts: list[dict],
) -> list[ScanFinding]:
    """Persists `finding_dicts` (each shaped like Finding.to_dict()) as
    real ScanFinding rows, skipping any dict already represented by a
    same-`_dedup_key` row on THIS scan (and any duplicate within this
    same call), and skipping -- never raising on -- a dict with an
    unrecognized severity/confidence or a blank title. Does not commit
    (the caller, app/tasks/scan_tasks.py, controls the transaction
    boundary); does flush, so a dedup check immediately after this
    call within the same scan sees what was just added."""
    if not finding_dicts:
        return []

    existing_rows = (
        await db.execute(select(ScanFinding.evidence).where(ScanFinding.scan_id == scan_id))
    ).all()
    existing_keys = {
        row[0].get("_dedup_key")
        for row in existing_rows
        if isinstance(row[0], dict) and row[0].get("_dedup_key") is not None
    }

    created: list[ScanFinding] = []
    seen_this_call: set[str] = set()
    for raw in finding_dicts:
        title = (raw.get("title") or "").strip()
        if not title:
            continue
        try:
            severity = Severity(raw["severity"])
            confidence = Confidence(raw.get("confidence", Confidence.LOW.value))
        except (KeyError, ValueError):
            continue

        dedup_key = raw.get("_dedup_key")
        if dedup_key is not None:
            if dedup_key in existing_keys or dedup_key in seen_this_call:
                continue
            seen_this_call.add(dedup_key)

        evidence = dict(raw.get("evidence") or {})
        if raw.get("_check") is not None:
            evidence["_check"] = raw["_check"]
        if dedup_key is not None:
            evidence["_dedup_key"] = dedup_key
        if raw.get("_detected_at") is not None:
            evidence["_detected_at"] = raw["_detected_at"]

        finding = ScanFinding(
            scan_id=scan_id,
            scan_module_id=scan_module_id,
            title=title,
            description=raw.get("description"),
            severity=severity,
            confidence=confidence,
            affected_url=raw.get("affected_url"),
            cwe_id=raw.get("cwe_id"),
            evidence=evidence,
            remediation=raw.get("remediation"),
        )
        db.add(finding)
        created.append(finding)

    if created:
        await db.flush()
    return created


class FindingNotFoundError(Exception):
    """Covers both "doesn't exist" and "exists but belongs to another
    user's scan" -- collapsed into one 404, same reasoning as
    ScanNotFoundError in services/scans.py."""


def _category_of(finding: ScanFinding) -> str:
    check = finding.evidence.get("_check") if isinstance(finding.evidence, dict) else None
    return check if isinstance(check, str) and check else "other"


def _base_owner_query():
    return (
        select(ScanFinding)
        .join(Scan, Scan.id == ScanFinding.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .outerjoin(ScanModule, ScanModule.id == ScanFinding.scan_module_id)
        .options(selectinload(ScanFinding.module), selectinload(ScanFinding.scan).selectinload(Scan.target))
    )


async def list_findings_for_owner(
    db: AsyncSession,
    owner_id: uuid.UUID,
    *,
    target_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    severity: str | None = None,
    confidence: str | None = None,
    category: str | None = None,
    status_filter: str | None = None,
    search: str | None = None,
    sort_by: str = "created_at",
    sort_desc: bool = True,
    page: int = 1,
    page_size: int = 25,
) -> tuple[Sequence[ScanFinding], int]:
    page = max(page, 1)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    sort_by = sort_by if sort_by in ALLOWED_SORT_FIELDS else "created_at"

    stmt = _base_owner_query().where(Target.owner_id == owner_id)
    count_stmt = (
        select(func.count(ScanFinding.id))
        .join(Scan, Scan.id == ScanFinding.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .where(Target.owner_id == owner_id)
    )

    if target_id is not None:
        stmt = stmt.where(Scan.target_id == target_id)
        count_stmt = count_stmt.where(Scan.target_id == target_id)
    if scan_id is not None:
        stmt = stmt.where(ScanFinding.scan_id == scan_id)
        count_stmt = count_stmt.where(ScanFinding.scan_id == scan_id)
    if severity is not None:
        stmt = stmt.where(ScanFinding.severity == severity)
        count_stmt = count_stmt.where(ScanFinding.severity == severity)
    if confidence is not None:
        stmt = stmt.where(ScanFinding.confidence == confidence)
        count_stmt = count_stmt.where(ScanFinding.confidence == confidence)
    if status_filter is not None:
        stmt = stmt.where(ScanFinding.status == status_filter)
        count_stmt = count_stmt.where(ScanFinding.status == status_filter)
    if category is not None:
        category_expr = ScanFinding.evidence["_check"].as_string()
        stmt = stmt.where(category_expr == category)
        count_stmt = count_stmt.where(category_expr == category)
    if search:
        pattern = f"%{search.lower()}%"
        search_clause = func.lower(ScanFinding.title).like(pattern) | func.lower(
            func.coalesce(ScanFinding.description, "")
        ).like(pattern)
        stmt = stmt.where(search_clause)
        count_stmt = count_stmt.where(search_clause)

    sort_column = getattr(ScanFinding, sort_by)
    stmt = stmt.order_by(sort_column.desc() if sort_desc else sort_column.asc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)

    total = (await db.execute(count_stmt)).scalar_one()
    result = await db.execute(stmt)
    items = list(result.scalars().unique().all())
    return items, int(total)


async def get_finding_for_owner(
    db: AsyncSession, owner_id: uuid.UUID, finding_id: uuid.UUID
) -> ScanFinding:
    stmt = _base_owner_query().where(Target.owner_id == owner_id, ScanFinding.id == finding_id)
    result = await db.execute(stmt)
    finding = result.scalars().unique().one_or_none()
    if finding is None:
        raise FindingNotFoundError(finding_id)
    return finding


def to_public_dict(finding: ScanFinding) -> dict:
    """Builds the plain dict app/schemas/findings.py::FindingPublic is
    constructed from. A function, not a FindingPublic.model_validate
    straight off the ORM object, because target_id/target_name/
    category aren't columns on ScanFinding itself -- they come from
    the eagerly-loaded scan/target/module relationships
    (_base_owner_query() above already loads them, so this never
    triggers a lazy-load outside the session)."""
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "target_id": finding.scan.target_id,
        "target_name": finding.scan.target.name,
        "module_slug": finding.module.slug if finding.module is not None else None,
        "category": _category_of(finding),
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "status": finding.status.value,
        "affected_url": finding.affected_url,
        "cwe_id": finding.cwe_id,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "created_at": finding.created_at,
    }


async def update_finding_status(
    db: AsyncSession, owner_id: uuid.UUID, finding_id: uuid.UUID, new_status: str
) -> ScanFinding:
    finding = await get_finding_for_owner(db, owner_id, finding_id)
    finding.status = FindingStatus(new_status)
    await db.commit()
    # Deliberately no db.refresh() here: this finding's scan/target/
    # module relationships were already eagerly loaded by
    # get_finding_for_owner() (via _base_owner_query()'s selectinload
    # options) and are needed by to_public_dict() right after this
    # returns -- a refresh() would expire them and force a lazy-load,
    # which fails outside the greenlet SQLAlchemy's async mode uses
    # for implicit I/O. Only `status` changed, and it's already set on
    # the in-memory object above, so there's nothing stale to reload.
    return finding
