"""Scan targets.

A Target represents an asset the platform might be allowed to scan.

IMPORTANT -- what `is_authorized` is and is NOT:
`is_authorized` is an internal enforcement gate, nothing more. Flipping it
to True does not itself constitute legal authorization to scan anything --
it is a claim that authorization exists, recorded here so the application
can refuse to act when it's False. The actual proof (a signed engagement
letter, a scope document, a ticket approved by the target's owner) lives
outside this table; `authorization_reference` only *points* at it.

To stop the boolean from being flipped carelessly, a DB-level CHECK
constraint (see __table_args__) requires that authorizing a target also
records a reference and a timestamp, and `authorized_by_id` records which
platform user made that claim -- so "who said this was authorized" is
always answerable from the row itself, not just "someone, at some point".
None of this proves the underlying authorization is real or still valid;
that verification is a human/process responsibility outside this schema.

See app/services/targets.py for the guard that enforces `is_authorized`
at the service layer before any scan/engine can run.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class Target(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("owner_id", "base_url", name="uq_targets_owner_base_url"),
        CheckConstraint(
            "NOT is_authorized OR "
            "(authorization_reference IS NOT NULL AND authorized_at IS NOT NULL)",
            # The naming convention (app/db/base.py) already prefixes this
            # with "ck_targets_" -- don't repeat the table name here or
            # you get "ck_targets_ck_targets_...".
            name="authorization_requires_reference",
        ),
    )

    owner_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    is_authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_reference: Mapped[str | None] = mapped_column(
        String(512),
        doc="Pointer to the authorization proof (ticket id, doc ref, contract id) "
        "-- not the proof itself. Required by a CHECK constraint whenever "
        "is_authorized is True.",
    )
    authorized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    authorized_by_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID,
        ForeignKey("users.id", ondelete="SET NULL"),
        doc="Which platform user recorded this authorization claim. "
        "Accountability, not proof.",
    )

    owner: Mapped["User"] = relationship(back_populates="targets", foreign_keys=[owner_id])
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"Target(id={self.id!r}, base_url={self.base_url!r})"
