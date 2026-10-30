"""Request/response schemas for /api/v1/reports."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ReportCreateRequest(BaseModel):
    scan_id: uuid.UUID
    format: Literal["pdf", "html"] = "pdf"


class ReportPublic(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    generated_by_id: uuid.UUID
    format: str
    status: str
    completed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportListResponse(BaseModel):
    items: list[ReportPublic]
