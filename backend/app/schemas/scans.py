"""Request/response schemas for /api/v1/scans.

Scan creation is deliberately idempotent against accidental double
submission: the service layer refuses to create a second scan for the
same target while one is already PENDING/QUEUED/RUNNING/CANCELLING (see
services/scans.py::create_scan -- a 409, not a silent second scan).
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import AliasPath, BaseModel, Field, field_validator


class ScanCreateRequest(BaseModel):
    target_id: uuid.UUID
    # Module slugs to run. None/omitted = every currently-enabled module
    # in the registry at creation time (today, in practice, just the
    # diagnostic module -- see services/scan_modules.py). Unknown or
    # disabled slugs are rejected by the service, never silently dropped.
    modules: list[str] | None = Field(default=None, max_length=20)
    # The owner must explicitly confirm active testing before it runs
    # (gate 3 of the active testing design, see app/core/config.py).
    # Selecting an active module without setting this to True is rejected
    # by services/scans.py::create_scan() with a 4xx error. Ignored when
    # no active module is requested.
    active_testing_confirmed: bool = False

    @field_validator("modules")
    @classmethod
    def _dedupe_modules(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        deduped = list(dict.fromkeys(slug.strip() for slug in value if slug.strip()))
        if not deduped:
            raise ValueError("modules, if provided, must not be empty")
        return deduped


class ScanModuleRunPublic(BaseModel):
    id: uuid.UUID
    scan_module_id: uuid.UUID
    # The module's slug, from the ScanModuleRun.module relationship
    # (loaded with selectinload in get_scan_for_owner). The frontend uses
    # it to group and label results; scan_module_id alone is just an FK.
    module_slug: str = Field(validation_alias=AliasPath("module", "slug"))
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    # The module's structured, already-sanitized output (see
    # app/engines/recon/persistence.py::build_persisted_result). None if
    # the module doesn't produce one or hasn't finished. Only returned
    # through get_scan_for_owner(), which filters by owner.
    result: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class ScanFindingPublic(BaseModel):
    """A stored ScanFinding row, read-only. Findings are only created by
    app/services/findings.py from a module's results, never through
    the API. Only returned through get_scan_for_owner(), which filters
    by owner."""

    id: uuid.UUID
    scan_module_id: uuid.UUID | None
    title: str
    description: str | None
    severity: str
    confidence: str
    affected_url: str | None
    cwe_id: str | None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None
    created_at: datetime
    # Optional triage status. Existing findings default to "open" at
    # the database level (see the migration).
    status: str = "open"

    model_config = {"from_attributes": True}


class ScanPublic(BaseModel):
    id: uuid.UUID
    target_id: uuid.UUID
    initiated_by_id: uuid.UUID
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    cancel_requested_at: datetime | None
    created_at: datetime
    updated_at: datetime
    module_runs: list[ScanModuleRunPublic] = Field(default_factory=list)
    # Empty for scans that didn't run a findings-producing module
    # (web_vuln_assessment, active_web_testing).
    findings: list[ScanFindingPublic] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    items: list[ScanPublic]


class ScanRerunRequest(BaseModel):
    """active_testing_confirmed must be sent again on every rerun
    (default False, like ScanCreateRequest). It is never copied from
    the original scan; see services/scans.py::rerun_scan()."""

    active_testing_confirmed: bool = False


class ScanStatusResponse(BaseModel):
    id: uuid.UUID
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    cancel_requested_at: datetime | None


class ScanEventPublic(BaseModel):
    id: uuid.UUID
    event_type: str
    message: str | None
    payload: dict
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanEventListResponse(BaseModel):
    items: list[ScanEventPublic]
