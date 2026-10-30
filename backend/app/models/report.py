import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ReportFormat(str, enum.Enum):
    PDF = "pdf"
    # HTML was added to the existing enum (ALTER TYPE ... ADD VALUE,
    # see the migration), like ScanStatus.CANCELLING.
    HTML = "html"


class ReportStatus(str, enum.Enum):
    PENDING = "pending"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"


class Report(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "reports"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    generated_by_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    format: Mapped[ReportFormat] = mapped_column(
        Enum(ReportFormat, name="report_format", native_enum=True),
        default=ReportFormat.PDF,
        nullable=False,
    )
    status: Mapped[ReportStatus] = mapped_column(
        Enum(ReportStatus, name="report_status", native_enum=True),
        default=ReportStatus.PENDING,
        nullable=False,
    )
    storage_path: Mapped[str | None] = mapped_column(String(1024))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan: Mapped["Scan"] = relationship(back_populates="reports")
    generated_by_user: Mapped["User"] = relationship(back_populates="reports")

    def __repr__(self) -> str:  # pragma: no cover
        return f"Report(id={self.id!r}, status={self.status!r})"
