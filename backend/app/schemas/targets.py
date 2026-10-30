"""Request/response schemas for /api/v1/targets.

Creating or editing a target never lets the client set
is_authorized/authorization_reference/authorized_at/authorized_by_id
directly. Authorizing a target is a separate, explicit action
(TargetAuthorizeRequest), never a side effect of creating it.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class TargetCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    base_url: str = Field(min_length=1, max_length=2048)
    description: str | None = Field(default=None, max_length=4000)

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        from urllib.parse import urlsplit

        parts = urlsplit(value.strip())
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("base_url must be an absolute http(s) URL")
        return value.strip()

    @field_validator("name")
    @classmethod
    def _strip_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("name must not be blank")
        return cleaned


class TargetAuthorizeRequest(BaseModel):
    """Explicit, separate action: recording a claim of authorization.
    See app/models/target.py docstring -- this is a pointer to proof
    (a ticket id, a signed scope doc reference), never proof itself."""

    authorization_reference: str = Field(min_length=1, max_length=512)


class TargetPublic(BaseModel):
    id: uuid.UUID
    owner_id: uuid.UUID
    name: str
    base_url: str
    description: str | None
    is_authorized: bool
    authorization_reference: str | None
    authorized_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class TargetListResponse(BaseModel):
    items: list[TargetPublic]
