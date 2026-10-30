"""Reusable column mixins for ORM models."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.types import GUID


class UUIDPrimaryKeyMixin:
    """UUID primary key, generated application-side."""

    id: Mapped[uuid.UUID] = mapped_column(
        GUID, primary_key=True, default=uuid.uuid4
    )


class CreatedAtMixin:
    """For append-only / event-log style tables: creation time only."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class TimestampMixin(CreatedAtMixin):
    """For mutable records: creation + last-update time."""

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
