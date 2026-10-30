"""POST /register, POST /login, POST /logout, GET /me."""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_session, get_current_user, get_db, require_csrf
from app.core.config import Settings, get_settings
from app.core.rate_limit import RateLimiterUnavailableError, RedisSlidingWindowRateLimiter
from app.core.redis_client import get_redis_client
from app.core.security import generate_csrf_token
from app.models.user import User
from app.models.user_session import UserSession
from app.schemas.auth import LoginRequest, MessageResponse, RegisterRequest, UserPublic
from app.services import auth as auth_service

router = APIRouter()
logger = logging.getLogger("app.auth")


@dataclass
class _Limiters:
    login_by_email: RedisSlidingWindowRateLimiter
    login_by_ip: RedisSlidingWindowRateLimiter
    register_by_ip: RedisSlidingWindowRateLimiter


# Built lazily on first use (not at import time): constructing these
# calls get_redis_client(), which raises if REDIS_URL isn't configured.
# Importing this module -- and therefore the app -- must not itself
# require Redis, same lazy-construction pattern already used for the
# DB engine (app/db/session.py) and for SECRET_KEY.
_limiters: _Limiters | None = None


def _get_limiters() -> _Limiters:
    global _limiters
    if _limiters is None:
        settings = get_settings()
        redis_client = get_redis_client()
        _limiters = _Limiters(
            login_by_email=RedisSlidingWindowRateLimiter(
                redis_client,
                max_attempts=settings.login_rate_limit_max_attempts,
                window_seconds=settings.login_rate_limit_window_seconds,
                key_prefix="ratelimit:login:email",
            ),
            login_by_ip=RedisSlidingWindowRateLimiter(
                redis_client,
                max_attempts=settings.login_rate_limit_max_attempts,
                window_seconds=settings.login_rate_limit_window_seconds,
                key_prefix="ratelimit:login:ip",
            ),
            register_by_ip=RedisSlidingWindowRateLimiter(
                redis_client,
                max_attempts=settings.register_rate_limit_max_attempts,
                window_seconds=settings.register_rate_limit_window_seconds,
                key_prefix="ratelimit:register:ip",
            ),
        )
    return _limiters


def _reset_limiters_for_testing() -> None:
    """Test-only hook: drops the cached limiters/Redis client so a test
    can point REDIS_URL at a different instance (or simulate Redis being
    absent) without leftover state from a previous test. Not called from
    any request path."""
    global _limiters
    _limiters = None


# --- Fail-open / fail-closed handling for a Redis outage ----------------
#
# SECURE DEFAULT: fail CLOSED (Settings.rate_limit_fail_open = False).
# Every limiter call below goes through one of the _safe_* wrappers, so a
# Redis outage turns into a 503 on every login/register request rather
# than silently disabling brute-force protection. Settable per
# Settings.rate_limit_fail_open for a deployment that prefers to keep
# auth available during a Redis outage over keeping the rate limit
# enforced; see README for the tradeoff.


def _on_unavailable(exc: RateLimiterUnavailableError, settings: Settings, *, default):
    if settings.rate_limit_fail_open:
        logger.warning(
            "Rate limiter unavailable (Redis unreachable) -- failing OPEN "
            "per RATE_LIMIT_FAIL_OPEN=true, request allowed without a rate "
            "limit check: %s",
            exc,
        )
        return default
    logger.error(
        "Rate limiter unavailable (Redis unreachable) -- failing CLOSED, "
        "refusing request with 503: %s",
        exc,
    )
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Service temporarily unavailable. Please try again shortly.",
    ) from exc


async def _safe_is_blocked(
    limiter: RedisSlidingWindowRateLimiter, key: str, settings: Settings
) -> bool:
    try:
        return await limiter.is_blocked(key)
    except RateLimiterUnavailableError as exc:
        return _on_unavailable(exc, settings, default=False)


async def _safe_hit(limiter: RedisSlidingWindowRateLimiter, key: str, settings: Settings) -> None:
    try:
        await limiter.hit(key)
    except RateLimiterUnavailableError as exc:
        _on_unavailable(exc, settings, default=None)


async def _safe_reset(
    limiter: RedisSlidingWindowRateLimiter, key: str, settings: Settings
) -> None:
    try:
        await limiter.reset(key)
    except RateLimiterUnavailableError as exc:
        _on_unavailable(exc, settings, default=None)


async def _safe_retry_after(
    limiter: RedisSlidingWindowRateLimiter, key: str, settings: Settings
) -> int:
    try:
        return await limiter.retry_after_seconds(key)
    except RateLimiterUnavailableError as exc:
        return _on_unavailable(exc, settings, default=0)


# --- Client IP, resistant to spoofing ------------------------------------


def _is_trusted_proxy(peer_ip: str, trusted_cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    for cidr in trusted_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if addr in network:
            return True
    return False


def _client_ip(request: Request) -> str:
    """Returns the TCP peer address by default -- X-Forwarded-For is
    NEVER trusted unless explicitly enabled (Settings.trust_x_forwarded_for)
    AND the immediate TCP peer is itself a configured trusted proxy
    (Settings.trusted_proxies). A client can set X-Forwarded-For to
    anything; trusting it unconditionally (the previous revision's bug)
    lets an attacker spoof the IP used for rate limiting and for the
    `ip_address` recorded on a session, dodging or framing another
    bucket at will.

    When trust is established, only the RIGHTMOST entry of
    X-Forwarded-For is used. A reverse proxy builds this header by
    APPENDING the address it observed to whatever value arrived with
    the request (e.g. nginx's `proxy_add_x_forwarded_for`) -- so with
    exactly one trusted proxy in front of this app, the rightmost entry
    is the one *that proxy* appended from its own observed connection,
    while anything to its left could have been forged by the original
    client before the request ever reached the proxy."""
    settings = get_settings()
    peer = request.client.host if request.client else None

    if settings.trust_x_forwarded_for and peer and _is_trusted_proxy(
        peer, settings.trusted_proxies
    ):
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            candidates = [part.strip() for part in forwarded.split(",") if part.strip()]
            if candidates:
                return candidates[-1]

    return peer or "unknown"


def _set_session_cookies(response: Response, raw_token: str, session: UserSession) -> None:
    settings = get_settings()
    csrf_token = generate_csrf_token(session.session_token_hash, settings.require_secret_key())
    max_age = settings.session_ttl_hours * 3600

    response.set_cookie(
        key=settings.session_cookie_name,
        value=raw_token,
        max_age=max_age,
        httponly=True,  # never readable by JS -- the whole point of a session cookie
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf_token,
        max_age=max_age,
        httponly=False,  # MUST be JS-readable: the client echoes this into a header
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def _clear_session_cookies(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")


@router.post(
    "/auth/register",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    data: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)
) -> User:
    """Does NOT log the new user in -- register and login are kept as two
    separate, explicit steps. Simpler to reason about than an implicit
    auto-login, and keeps the two required test scenarios independent.

    Rate-limited per IP (not per email): the goal here is throttling
    mass account creation / probing from one source, not protecting one
    specific email the way login protects one specific account. Every
    attempt counts against the bucket, successful or not -- unlike
    login, there's no "legitimate one-off mistake" to reset against."""
    settings = get_settings()
    limiters = _get_limiters()
    ip_key = _client_ip(request)

    if await _safe_is_blocked(limiters.register_by_ip, ip_key, settings):
        retry_after = await _safe_retry_after(limiters.register_by_ip, ip_key, settings)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    await _safe_hit(limiters.register_by_ip, ip_key, settings)

    try:
        user = await auth_service.register_user(db, data)
    except auth_service.EmailAlreadyRegisteredError:
        await db.rollback()
        # Registration is the one place in this API that necessarily
        # confirms an email is taken -- that's inherent to how
        # registration works, not a separate enumeration hole. Login
        # below is where enumeration resistance actually matters, and is
        # handled differently (see authenticate_user docstring).
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    await db.commit()
    return user


@router.post("/auth/login", response_model=UserPublic)
async def login(
    data: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> User:
    settings = get_settings()
    limiters = _get_limiters()
    ip = _client_ip(request)
    email_key = data.email
    ip_key = ip

    email_blocked = await _safe_is_blocked(limiters.login_by_email, email_key, settings)
    ip_blocked = await _safe_is_blocked(limiters.login_by_ip, ip_key, settings)
    if email_blocked or ip_blocked:
        retry_after = max(
            await _safe_retry_after(limiters.login_by_email, email_key, settings)
            if email_blocked
            else 0,
            await _safe_retry_after(limiters.login_by_ip, ip_key, settings) if ip_blocked else 0,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    try:
        user = await auth_service.authenticate_user(db, data.email, data.password)
    except auth_service.InvalidCredentialsError:
        await _safe_hit(limiters.login_by_email, email_key, settings)
        await _safe_hit(limiters.login_by_ip, ip_key, settings)
        await db.rollback()
        # Same message and status whether the email doesn't exist, the
        # password is wrong, or the account is inactive -- see
        # authenticate_user() for the matching timing-safety measure.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # A slip-up shouldn't linger against a now-successful legitimate
    # login; the IP bucket is NOT reset, since a shared IP (office
    # network) having one successful login doesn't vouch for other
    # attempts against other accounts from that same IP.
    await _safe_reset(limiters.login_by_email, email_key, settings)

    new_session = await auth_service.create_session(
        db,
        user,
        user_agent=request.headers.get("user-agent"),
        ip_address=ip,
    )
    await db.commit()

    _set_session_cookies(response, new_session.raw_token, new_session.session)
    return user


@router.post(
    "/auth/logout",
    response_model=MessageResponse,
    dependencies=[Depends(require_csrf)],
)
async def logout(
    response: Response,
    session: UserSession = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Revokes only the session presented in this request's cookie, not
    every session the user has elsewhere (see app/services/auth.py)."""
    await auth_service.revoke_session(db, session)
    await db.commit()
    _clear_session_cookies(response)
    return MessageResponse(detail="Logged out")


@router.get("/auth/me", response_model=UserPublic)
async def me(user: User = Depends(get_current_user)) -> User:
    return user
