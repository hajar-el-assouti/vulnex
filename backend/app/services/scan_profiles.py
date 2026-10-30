"""Saved scan profiles. See app/models/scan_profile.py.

A profile may reference a disabled module (the built-in "Authorized
Active Assessment" profile includes active_web_testing, disabled by
default). So here we only check the slug exists; whether it is enabled
is checked when the scan is created
(services/scan_modules.py::get_enabled_modules_by_slugs)."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_module import ScanModule
from app.models.scan_profile import ScanProfile


class UnknownModuleSlugError(Exception):
    def __init__(self, slug: str) -> None:
        self.slug = slug
        super().__init__(f"Scan module {slug!r} does not exist")


class ScanProfileNotFoundError(Exception):
    """Covers "doesn't exist", "belongs to another user", AND "is a
    built-in profile" for delete/update -- a built-in profile is never
    mutable via the API (see delete_profile), so attempting to touch
    one 404s exactly like touching someone else's profile would."""


async def list_profiles_for_owner(db: AsyncSession, owner_id: uuid.UUID) -> list[ScanProfile]:
    """Built-ins (owner_id IS NULL) plus this user's own -- never
    another user's."""
    result = await db.execute(
        select(ScanProfile)
        .where((ScanProfile.owner_id == owner_id) | (ScanProfile.is_builtin.is_(True)))
        .order_by(ScanProfile.is_builtin.desc(), ScanProfile.name)
    )
    return list(result.scalars().all())


async def _validate_slugs_exist(db: AsyncSession, slugs: list[str]) -> None:
    result = await db.execute(select(ScanModule.slug).where(ScanModule.slug.in_(slugs)))
    found = {row[0] for row in result.all()}
    for slug in slugs:
        if slug not in found:
            raise UnknownModuleSlugError(slug)


async def create_profile(
    db: AsyncSession,
    owner_id: uuid.UUID,
    *,
    name: str,
    description: str | None,
    module_slugs: list[str],
    active_testing_confirmed_default: bool,
) -> ScanProfile:
    await _validate_slugs_exist(db, module_slugs)
    profile = ScanProfile(
        owner_id=owner_id,
        name=name,
        description=description,
        module_slugs=module_slugs,
        active_testing_confirmed_default=active_testing_confirmed_default,
        is_builtin=False,
    )
    db.add(profile)
    await db.commit()
    await db.refresh(profile)
    return profile


async def delete_profile(db: AsyncSession, owner_id: uuid.UUID, profile_id: uuid.UUID) -> None:
    result = await db.execute(
        select(ScanProfile).where(ScanProfile.id == profile_id, ScanProfile.owner_id == owner_id)
    )
    profile = result.scalar_one_or_none()
    # is_builtin is never True when owner_id matches a real user (seed
    # data always sets owner_id=NULL for builtins), so this where()
    # already excludes built-ins -- the explicit check below is a
    # second, structural guarantee against that invariant ever being
    # violated by a future bug, not just a comment-level assumption.
    if profile is None or profile.is_builtin:
        raise ScanProfileNotFoundError(profile_id)
    await db.delete(profile)
    await db.commit()
