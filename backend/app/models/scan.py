import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ScanStatus(str, enum.Enum):
    """State machine:

        PENDING -> QUEUED -> RUNNING -> COMPLETED
                                      -> FAILED
        PENDING -> QUEUED -> CANCELLING -> CANCELLED
                   RUNNING -> CANCELLING -> CANCELLED
        QUEUED  -> CANCELLED   (not yet picked up by a worker)

    COMPLETED, FAILED and CANCELLED are terminal. Every transition goes
    through services/scans.py::transition_scan_status(), a conditional
    UPDATE ... WHERE status NOT IN (terminal), never a plain assignment."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_SCAN_STATUSES = frozenset(
    {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
)


class Scan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scans"

    target_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    initiated_by_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus, name="scan_status", native_enum=True),
        default=ScanStatus.PENDING,
        nullable=False,
        index=True,
    )
    # Set once the scan is sent to Celery. Nullable: a scan exists
    # (PENDING) before a worker picks it up.
    celery_task_id: Mapped[str | None] = mapped_column(String(255), unique=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # --- Reliable dispatch (outbox-style) ------------------------------
    # A scan row is the durable source of truth; Redis/Celery is not. On
    # creation a scan is committed as PENDING with dispatched_at=NULL
    # *before* anything touches Celery. dispatched_at is only set once
    # task.delay() has actually succeeded. If it stays NULL for too long
    # (Redis was unreachable, the process crashed between commit and
    # dispatch, ...) the scan is NOT silently stuck: a periodic
    # reconciliation task (app/tasks/maintenance.py) finds PENDING rows
    # with dispatched_at IS NULL older than a threshold and retries,
    # bounded by dispatch_attempts, until it gives up and marks FAILED
    # with a ScanEvent explaining why. See README "Fiabilité du dispatch".
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dispatch_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # --- Cooperative cancellation ---------------------------------------
    # Set by POST /scans/{id}/cancel. Never used to forcibly kill a
    # worker process (no blind task.revoke(terminate=True)): a RUNNING
    # scan's worker is expected to check this timestamp at module-run
    # boundaries and finalize itself to CANCELLED. A reconciliation task
    # force-finalizes a scan stuck in CANCELLING past a grace period
    # (worker crash), which is why cancellation is documented as
    # best-effort / eventually-consistent, not instantaneous.
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    target: Mapped["Target"] = relationship(back_populates="scans")
    initiated_by_user: Mapped["User"] = relationship(back_populates="scans")
    module_runs: Mapped[list["ScanModuleRun"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["ScanFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    events: Mapped[list["ScanEvent"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[list["Report"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"Scan(id={self.id!r}, status={self.status!r})"
