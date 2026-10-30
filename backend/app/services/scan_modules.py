"""Reads of the scan-module registry.

Only `is_enabled=true` rows are ever returned to a client or accepted as
a valid module slug for a new scan -- a module that exists as a row but
isn't enabled (e.g. seeded ahead of time, not yet implemented) must never
be presented as operational. See app/models/scan_module.py.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_module import ScanModule


class UnknownOrDisabledModuleError(Exception):
    def __init__(self, slug: str) -> None:
        self.slug = slug
        super().__init__(f"Scan module {slug!r} does not exist or is not enabled")


async def list_enabled_modules(db: AsyncSession) -> list[ScanModule]:
    result = await db.execute(
        select(ScanModule).where(ScanModule.is_enabled.is_(True)).order_by(ScanModule.slug)
    )
    return list(result.scalars().all())


async def get_enabled_modules_by_slugs(db: AsyncSession, slugs: list[str]) -> list[ScanModule]:
    """Returns the enabled ScanModule rows matching `slugs`, in no
    particular order. Raises UnknownOrDisabledModuleError naming the
    first slug that doesn't resolve to an enabled module -- a typo or a
    disabled/future engine must block scan creation, never be silently
    dropped from the run."""
    result = await db.execute(
        select(ScanModule).where(ScanModule.is_enabled.is_(True), ScanModule.slug.in_(slugs))
    )
    found = {module.slug: module for module in result.scalars().all()}
    for slug in slugs:
        if slug not in found:
            raise UnknownOrDisabledModuleError(slug)
    return [found[slug] for slug in slugs]
