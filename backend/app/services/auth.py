"""Registration, authentication and session lifecycle.

Functions here call `db.flush()` (so ids and timestamps are available)
but never `db.commit()`. The endpoint commits once, after all changes
for the request, so a later failure doesn't leave a partial commit.

Session policy:
- A new session is created on every successful login. Several
  sessions per user are allowed (one per device).
- Absolute lifetime: `settings.session_ttl_hours` (12h by default)
  from creation.
- Idle timeout: `settings.session_idle_timeout_minutes` (30 min by
  default) since `last_seen_at`, updated on every authenticated
  request.
- Logout revokes (`revoked_at`) only the session in the request's
  cookie. The row is kept as an audit trail.
- Every login gets a new opaque token and row; an existing token is
  never extended. No refresh token (stateful sessions, not JWT).
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import (
    generate_session_token,
    hash_password,
    hash_session_token,
    password_needs_rehash,
    verify_dummy_password,
    verify_password,
)
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.auth import RegisterRequest


class EmailAlreadyRegisteredError(Exception):
    pass


class InvalidCredentialsError(Exception):
    """Deliberately used for every login failure reason (no such email,
    wrong password, inactive account) -- see module docstring / security
    summary for why collapsing these into one response matters."""


async def register_user(db: AsyncSession, data: RegisterRequest) -> User:
    existing = await db.execute(select(User).where(User.email == data.email))
    if existing.scalar_one_or_none() is not None:
        raise EmailAlreadyRegisteredError(data.email)

    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        full_name=data.full_name,
    )
    db.add(user)
    await db.flush()
    return user


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User:
    """Raises InvalidCredentialsError for every failure case, with no
    observable difference (response shape, and as close to constant-time
    as a single process can offer) between "no such user", "wrong
    password", and "inactive account"."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None:
        verify_dummy_password(password)  # keep timing consistent
        raise InvalidCredentialsError()

    if not verify_password(user.hashed_password, password):
        raise InvalidCredentialsError()

    if not user.is_active:
        raise InvalidCredentialsError()

    if password_needs_rehash(user.hashed_password):
        # Transparent upgrade path if Argon2 parameters are ever bumped.
        user.hashed_password = hash_password(password)
        await db.flush()

    return user


@dataclass
class NewSession:
    session: UserSession
    raw_token: str  # given to the caller exactly once; never stored


async def create_session(
    db: AsyncSession,
    user: User,
    *,
    user_agent: str | None,
    ip_address: str | None,
) -> NewSession:
    settings = get_settings()
    raw_token = generate_session_token()
    now = datetime.now(timezone.utc)

    session = UserSession(
        user_id=user.id,
        session_token_hash=hash_session_token(raw_token),
        user_agent=(user_agent or None),
        ip_address=(ip_address or None),
        expires_at=now + timedelta(hours=settings.session_ttl_hours),
    )
    db.add(session)
    await db.flush()
    return NewSession(session=session, raw_token=raw_token)


async def get_session_by_raw_token(db: AsyncSession, raw_token: str) -> UserSession | None:
    token_hash = hash_session_token(raw_token)
    result = await db.execute(
        select(UserSession).where(UserSession.session_token_hash == token_hash)
    )
    return result.scalar_one_or_none()


def _as_aware_utc(value: datetime) -> datetime:
    """Postgres (timestamptz) always hands back tz-aware datetimes; SQLite
    (used by the fast unit test suite) hands back naive ones for the same
    `DateTime(timezone=True)` column, since it has no real tz-aware
    storage. Normalizing here means session-validity checks work
    identically under both, instead of only being caught by whichever
    dialect happens to run first."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def is_session_valid(session: UserSession, *, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    settings = get_settings()

    if session.revoked_at is not None:
        return False
    if _as_aware_utc(session.expires_at) <= now:
        return False
    idle_cutoff = _as_aware_utc(session.last_seen_at) + timedelta(
        minutes=settings.session_idle_timeout_minutes
    )
    if idle_cutoff <= now:
        return False
    return True


async def touch_session(db: AsyncSession, session: UserSession) -> None:
    """Call on every authenticated request to keep the idle timeout
    sliding. Caller still owns the final commit."""
    session.last_seen_at = datetime.now(timezone.utc)
    await db.flush()


async def revoke_session(db: AsyncSession, session: UserSession) -> None:
    session.revoked_at = datetime.now(timezone.utc)
    await db.flush()
