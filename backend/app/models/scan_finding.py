import enum
import uuid

from sqlalchemy import Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import GUID, JSONVariant
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class FindingStatus(str, enum.Enum):
    """Optional triage status, set by a user via PATCH /findings/{id}.

    It tracks what was done about a finding. The severity and
    confidence set by the engine never change. Every new finding starts
    as OPEN, and nothing changes the status automatically."""

    OPEN = "open"
    IN_REVIEW = "in_review"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ScanFinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Nullable: if a module is later removed from the registry, its past
    # findings must survive (SET NULL), not vanish or block the delete.
    scan_module_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("scan_modules.id", ondelete="SET NULL"), index=True
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="finding_severity", native_enum=True), nullable=False, index=True
    )
    confidence: Mapped[Confidence] = mapped_column(
        Enum(Confidence, name="finding_confidence", native_enum=True),
        default=Confidence.LOW,
        nullable=False,
    )
    affected_url: Mapped[str | None] = mapped_column(String(2048))
    cwe_id: Mapped[str | None] = mapped_column(String(20))
    evidence: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)
    remediation: Mapped[str | None] = mapped_column(Text)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status", native_enum=True),
        default=FindingStatus.OPEN,
        # SQLAlchemy's Enum(SomePyEnum, ...) persists each member's NAME
        # ('OPEN'), not its .value ('open') -- no values_callable
        # override here, same convention already established by
        # ScanStatus (see alembic/versions/7d54134c62fe's own comment).
        server_default=FindingStatus.OPEN.name,
        nullable=False,
        index=True,
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    module: Mapped["ScanModule"] = relationship(back_populates="findings")

    def __repr__(self) -> str:  # pragma: no cover
        return f"ScanFinding(id={self.id!r}, severity={self.severity!r})"
