"""Saved scan profiles.

A profile is a named, reusable list of module slugs (plus the
active-testing confirmation default that goes with it). It only saves
time in the new-scan form. It gives no authorization: a scan created
from a profile still goes through every check in
services/scans.py::create_scan() (target ownership, target
authorization, module validation, active testing confirmation).

Three built-in profiles (owner_id IS NULL, is_builtin=True) are seeded
by migration and visible to everyone. Users can save their own
(owner_id set, is_builtin=False), visible only to them. Built-in
profiles can't be edited or deleted through the API."""

import uuid

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import GUID, JSONVariant
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ScanProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_profiles"

    # NULL = a built-in profile, visible to every user, not owned by
    # anyone. Never NULL for a user-created profile.
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(1024))
    # Module slugs, e.g. ["recon", "web_vuln_assessment"] -- validated
    # against the live scan_modules registry only at scan-creation
    # time (services/scans.py already does this), never re-validated
    # just for a profile to exist, so a profile referencing a slug that
    # is later disabled/removed still simply fails that later check,
    # rather than being silently rewritten or deleted here.
    module_slugs: Mapped[list[str]] = mapped_column(JSONVariant, default=list, nullable=False)
    # Whether creating a scan from this profile should default
    # active_testing_confirmed=True -- still just a form default; the
    # same confirmation checkbox/field is always presented and always
    # re-enforced server-side.
    active_testing_confirmed_default: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"ScanProfile(id={self.id!r}, name={self.name!r}, is_builtin={self.is_builtin!r})"
