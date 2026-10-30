"""Read-only schema for /api/v1/scan-modules.

GET only: modules are registered by migrations, never through the API.
Only modules with is_enabled=true are returned (see
services/scan_modules.py), so a disabled module is never offered to
the user.
"""

import uuid

from pydantic import BaseModel


class ScanModulePublic(BaseModel):
    id: uuid.UUID
    slug: str
    name: str
    description: str | None
    version: str

    model_config = {"from_attributes": True}


class ScanModuleListResponse(BaseModel):
    items: list[ScanModulePublic]
