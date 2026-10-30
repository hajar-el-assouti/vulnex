"""Authorization guard for targets.

Every scan must be tied to an authorized target. This is the single
check called before a scan is created and before any engine runs, so
a new endpoint can't skip it by forgetting to re-implement it.

`Target.is_authorized` is an internal flag, not proof. The guard checks
the flag and that it has a reference and a timestamp (the same rule as
the DB CHECK constraint, re-checked for objects not saved yet). It
can't verify that the real-world authorization is genuine or still
valid; that is a human responsibility.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.target import Target
from app.schemas.targets import TargetCreateRequest


class TargetNotFoundError(Exception):
    """Raised when a target doesn't exist, or exists but is not owned by
    the requesting user. Deliberately the same error/status for both
    cases (404, never 403) so a user can't use this endpoint to probe
    which target ids exist for other owners."""


class TargetAlreadyExistsError(Exception):
    pass


async def create_target(db: AsyncSession, owner_id: uuid.UUID, data: TargetCreateRequest) -> Target:
    existing = await db.execute(
        select(Target).where(Target.owner_id == owner_id, Target.base_url == data.base_url)
    )
    if existing.scalar_one_or_none() is not None:
        raise TargetAlreadyExistsError(data.base_url)

    target = Target(
        owner_id=owner_id,
        name=data.name,
        base_url=data.base_url,
        description=data.description,
    )
    db.add(target)
    await db.flush()
    return target


async def get_target_for_owner(db: AsyncSession, owner_id: uuid.UUID, target_id: uuid.UUID) -> Target:
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.owner_id == owner_id)
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise TargetNotFoundError(target_id)
    return target


async def list_targets_for_owner(db: AsyncSession, owner_id: uuid.UUID) -> list[Target]:
    result = await db.execute(
        select(Target).where(Target.owner_id == owner_id).order_by(Target.created_at.desc())
    )
    return list(result.scalars().all())


async def authorize_target(
    db: AsyncSession,
    target: Target,
    *,
    authorization_reference: str,
    authorized_by_id: uuid.UUID,
) -> Target:
    """Records the authorization *claim* -- see app/models/target.py for
    why this is a claim, not proof. Separate, explicit action; never a
    side effect of target creation."""
    target.is_authorized = True
    target.authorization_reference = authorization_reference
    target.authorized_at = datetime.now(timezone.utc)
    target.authorized_by_id = authorized_by_id
    await db.flush()
    return target


class TargetNotAuthorizedError(Exception):
    """Raised when an operation requires an authorized target and the
    target provided has not been marked as authorized."""

    def __init__(self, target_id: object, reason: str) -> None:
        self.target_id = target_id
        self.reason = reason
        super().__init__(f"Target {target_id} is not authorized for scanning: {reason}")


def ensure_target_is_authorized(target: Target) -> None:
    """Raise TargetNotAuthorizedError unless the target is authorized and
    that authorization has a reference and a timestamp.

    Pure and synchronous: the caller fetches the Target first. Kept
    simple so it is easy to test and can be called from both FastAPI
    handlers and Celery tasks.
    """
    if not target.is_authorized:
        raise TargetNotAuthorizedError(target.id, "is_authorized is False")
    if not target.authorization_reference or not target.authorized_at:
        # Should be unreachable for a persisted row (DB CHECK constraint
        # enforces this) -- defends against an in-memory object built
        # without going through the DB.
        raise TargetNotAuthorizedError(
            target.id, "is_authorized is True but missing reference/timestamp"
        )
