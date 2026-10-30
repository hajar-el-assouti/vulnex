"""Join table: which modules ran (or will run) as part of a given scan.

Not one of the 7 tables named in the spec -- added because a `scan` can
involve several engines (recon + fuzzing + sqli + xss in one run), and each
one needs its own status/timing/config without overloading the `scans` row
itself. Flagged explicitly rather than silently expanding the schema.
"""

import enum
import uuid
from datetime import datetime

from typing import Any

from sqlalchemy import DateTime, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import GUID, JSONVariant
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ScanModuleRunStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScanModuleRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_module_runs"
    __table_args__ = (
        UniqueConstraint("scan_id", "scan_module_id", name="uq_scan_module_runs_scan_module"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_module_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("scan_modules.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[ScanModuleRunStatus] = mapped_column(
        Enum(ScanModuleRunStatus, name="scan_module_run_status", native_enum=True),
        default=ScanModuleRunStatus.PENDING,
        nullable=False,
    )
    config: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    celery_task_id: Mapped[str | None] = mapped_column(String(255))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The module's structured output. NULL if the run never completed
    # or the module has nothing to store (e.g. diagnostic). Every value
    # goes through sanitization and size limiting first (see
    # app/engines/recon/persistence.py::build_persisted_result).
    # Findings are stored separately in scan_findings.
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONVariant, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="module_runs")
    module: Mapped["ScanModule"] = relationship(back_populates="runs")

    def __repr__(self) -> str:  # pragma: no cover
        return f"ScanModuleRun(scan_id={self.scan_id!r}, module_id={self.scan_module_id!r})"
