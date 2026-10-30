"""Types a scan engine plugs into.

The orchestration (API, scan state machine in Postgres, Celery
dispatch, cancellation) only talks to engines through these types.
An engine implements `ScanModule` and is registered as a row in
`scan_modules`, no schema change needed.

Authorization checks, cancellation checks and event logging live in
the Celery task that calls the engine (app/tasks/scan_tasks.py), so a
new engine can't bypass them by accident.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class ModuleExecutionStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ScanConfiguration:
    """Per-module configuration for one scan. `options` is module-specific
    and intentionally untyped here (each engine defines/validates its own
    shape) -- the orchestration layer only ever passes it through."""

    module_slug: str
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScanContext:
    """Everything an engine needs to run one module against one target,
    and nothing it needs to look up itself. Built by the Celery task from
    already-validated, already-authorized database rows -- an engine
    receiving a ScanContext never has to (and must not) re-derive
    authorization on its own; that is done once, centrally, before this
    object is constructed (see services/targets.py::ensure_target_is_authorized
    and the SSRF checks in app/security/ssrf.py)."""

    scan_id: uuid.UUID
    scan_module_run_id: uuid.UUID
    target_id: uuid.UUID
    target_base_url: str
    configuration: ScanConfiguration
    cancellation: "CancellationContext"


@dataclass(frozen=True)
class ScanProgress:
    """A single progress tick an engine may report mid-run. Carried
    through to a `progress` ScanEvent by the calling task -- an engine
    never writes to the database directly."""

    percent: int  # 0-100
    message: str = ""


@dataclass(frozen=True)
class ModuleExecutionResult:
    """What an engine hands back when it finishes (success, failure, or
    having stopped early because cancellation was requested). `findings`
    is a list of plain dicts shaped like ScanFinding's own fields
    (title/severity/confidence/affected_url/cwe_id/evidence/remediation);
    kept as dicts here (not a full model type) so this contract module
    never has to import SQLAlchemy models, but validated by the calling
    task before being persisted."""

    status: ModuleExecutionStatus
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: str | None = None
    error: str | None = None
    # A module's structured, already-sanitized output (observations,
    # not findings). None by default, for modules that produce no
    # structured output (e.g. app/tasks/diagnostic.py). Only the calling
    # task (app/tasks/scan_tasks.py) writes it to ScanModuleRun.result;
    # engines never touch the database.
    result: dict[str, Any] | None = None


@dataclass(frozen=True)
class ScanEvent:
    """What an engine (or the task wrapping it) emits for the live
    activity feed. Mirrors app/models/scan_event.py's columns one-to-one
    on purpose, but stays a plain dataclass so this module has no DB
    dependency; the calling task converts this into an actual
    ScanEvent row."""

    event_type: str
    message: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class CancellationContext:
    """Passed into an engine so it can cooperatively check, at whatever
    checkpoints make sense for its own work (between requests, between
    pages, every N seconds -- the engine's choice), whether cancellation
    has been requested. `is_cancelled()` is a plain callable, not tied to
    Celery, so it can be backed by a real DB poll in production and by a
    fixed/fake value in tests."""

    is_cancelled: "CancellationCheck"

    def check(self) -> bool:
        return self.is_cancelled()


@runtime_checkable
class CancellationCheck(Protocol):
    def __call__(self) -> bool: ...


@runtime_checkable
class ScanModule(Protocol):
    """The interface a scan engine must implement."""

    slug: str

    def run(self, context: ScanContext) -> ModuleExecutionResult: ...
