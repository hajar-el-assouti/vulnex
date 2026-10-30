"""Shared FastAPI dependencies.

`get_db` lives in app.db.session and is re-exported here next to the
auth dependencies, so endpoints import everything from one place.
"""

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import verify_csrf_token
from app.db.session import get_db
from app.models.user import User
from app.models.user_session import UserSession
from app.services import auth as auth_service

__all__ = [
    "get_db",
    "get_current_user",
    "get_current_session",
    "require_csrf",
]

_NOT_AUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
)


async def _get_current_user_and_session(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> tuple[User, UserSession]:
    """The actual work, cached per-request by FastAPI's dependency
    resolution (same callable -> same request means this body runs once
    even though both get_current_user and get_current_session depend on
    it) -- so the session lookup / `last_seen_at` update happens exactly
    once per request, not once per dependant."""
    settings = get_settings()
    raw_token = request.cookies.get(settings.session_cookie_name)
    if not raw_token:
        raise _NOT_AUTHENTICATED

    session = await auth_service.get_session_by_raw_token(db, raw_token)
    if session is None or not auth_service.is_session_valid(session):
        raise _NOT_AUTHENTICATED

    result = await db.execute(select(User).where(User.id == session.user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise _NOT_AUTHENTICATED

    await auth_service.touch_session(db, session)
    await db.commit()

    return user, session


async def get_current_user(
    bundle: tuple[User, UserSession] = Depends(_get_current_user_and_session),
) -> User:
    return bundle[0]


async def get_current_session(
    bundle: tuple[User, UserSession] = Depends(_get_current_user_and_session),
) -> UserSession:
    return bundle[1]


async def require_csrf(
    request: Request,
    session: UserSession = Depends(get_current_session),
) -> None:
    """Use on every authenticated endpoint that changes data.

    Double-submit pattern: the CSRF cookie (readable by JS, unlike the
    session cookie) must match the header the client sends, and both
    must match the HMAC computed for the current session. A cross-site
    page can't forge a matching pair, and a token from another session
    can't be replayed."""
    settings = get_settings()
    cookie_token = request.cookies.get(settings.csrf_cookie_name)
    header_token = request.headers.get(settings.csrf_header_name)

    if not cookie_token or not header_token or cookie_token != header_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed"
        )

    if not verify_csrf_token(
        session.session_token_hash, cookie_token, settings.require_secret_key()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed"
        )
