"""Request/response schemas for /api/v1/findings.

Global findings view across scans. app/schemas/scans.py::ScanFindingPublic
covers findings inside a single scan; this adds the target and scan
context, filters, pagination and the status update.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

FindingStatusLiteral = Literal["open", "in_review", "resolved", "false_positive"]


class FindingPublic(BaseModel):
    """One finding, with just enough scan/target context to make sense
    outside its own scan's page. `category` is read from
    evidence["_check"] when present (every engine's own checks already
    set this -- see app/engines/*/checks/*.py) and falls back to
    "other" rather than crashing or omitting the field when an older
    or hand-inserted row lacks it."""

    id: uuid.UUID
    scan_id: uuid.UUID
    target_id: uuid.UUID
    target_name: str
    module_slug: str | None
    category: str
    title: str
    description: str | None
    severity: str
    confidence: str
    status: str
    affected_url: str | None
    cwe_id: str | None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None
    created_at: datetime


class FindingListResponse(BaseModel):
    items: list[FindingPublic]
    total: int
    page: int
    page_size: int


class FindingStatusUpdateRequest(BaseModel):
    status: FindingStatusLiteral
