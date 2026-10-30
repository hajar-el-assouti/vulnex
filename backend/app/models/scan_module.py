"""Registry of scan engines (recon, fuzzing, sqli, xss, ...).

This table is what lets new engines be plugged in without restructuring the
backend: adding a module is an INSERT here (slug, name, default_config) plus
dropping the engine's code in its own package later -- no schema change, no
new FastAPI routes, no new Celery wiring required just to register it.
"""

import uuid

from sqlalchemy import Boolean, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import JSONVariant
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ScanModule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_modules"

    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str] = mapped_column(String(50), nullable=False, default="0.1.0")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Whether selecting this module requires active-testing
    # confirmation on the scan. Replaces a hardcoded
    # "is this 'active_web_testing'?" check in create_scan().
    # Defaults to True, the opposite of `is_enabled`, so a module seeded
    # without setting it requires confirmation (fail closed) instead of
    # running unconfirmed. Passive modules set it to False explicitly in
    # their migration.
    requires_active_confirmation: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    default_config: Mapped[dict] = mapped_column(JSONVariant, default=dict, nullable=False)

    runs: Mapped[list["ScanModuleRun"]] = relationship(back_populates="module")
    findings: Mapped[list["ScanFinding"]] = relationship(back_populates="module")

    def __repr__(self) -> str:  # pragma: no cover
        return f"ScanModule(slug={self.slug!r})"
