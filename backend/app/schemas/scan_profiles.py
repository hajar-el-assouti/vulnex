"""Request/response schemas for /api/v1/scan-profiles.
See app/models/scan_profile.py: a profile is a shortcut for picking
modules, never an authorization shortcut."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ScanProfilePublic(BaseModel):
    id: uuid.UUID
    owner_id: uuid.UUID | None
    name: str
    description: str | None
    module_slugs: list[str]
    active_testing_confirmed_default: bool
    is_builtin: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanProfileListResponse(BaseModel):
    items: list[ScanProfilePublic]


class ScanProfileCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1024)
    module_slugs: list[str] = Field(min_length=1, max_length=20)
    active_testing_confirmed_default: bool = False
