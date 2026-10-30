"""Append-only audit / progress log for a scan.

Deliberately uses CreatedAtMixin (no updated_at) -- events are never edited,
only appended. This is what the future Celery workers will write progress
updates to (module_started, progress, log, error, ...) for a live-ish
dashboard view, without touching the `scans` row itself on every tick.
"""

import enum
import uuid

from sqlalchemy import Enum, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import GUID, JSONVariant
from app.models.mixins import CreatedAtMixin, UUIDPrimaryKeyMixin


class ScanEventType(str, enum.Enum):
    CREATED = "created"
    QUEUED = "queued"
    STARTED = "started"
    MODULE_STARTED = "module_started"
    MODULE_COMPLETED = "module_completed"
    PROGRESS = "progress"
    LOG = "log"
    ERROR = "error"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class ScanEvent(Base, UUIDPrimaryKeyMixin, CreatedAtMixin):
    __tablename__ = "scan_events"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[ScanEventType] = mapped_column(
        Enum(ScanEventType, name="scan_event_type", native_enum=True),
        nullable=False,
        index=True,
    )
    message: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="events")

    def __repr__(self) -> str:  # pragma: no cover
        return f"ScanEvent(scan_id={self.scan_id!r}, type={self.event_type!r})"
