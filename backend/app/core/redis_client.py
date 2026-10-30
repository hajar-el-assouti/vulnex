"""Lazy Redis connection pool, mirroring the lazy-engine pattern already
used for PostgreSQL (app/db/session.py) and the lazy SECRET_KEY check
(app/core/config.py): importing this module, or importing the app, must
never require Redis to be configured or reachable. A connection pool is
only built the first time something actually needs one, and that first
use is where a missing REDIS_URL raises loudly.

Short, explicit timeouts are set on purpose: the login/register rate
limiter depends on Redis being fast to answer "is this blocked?" on
every request. Without a timeout, a hung/unreachable Redis would hang
every login attempt instead of failing fast into the documented
fail-closed behavior (see app/core/rate_limit.py).
"""

from __future__ import annotations

import redis.asyncio as redis

from app.core.config import get_settings

_redis_client: redis.Redis | None = None


def get_redis_client() -> redis.Redis:
    """Returns a process-wide Redis client, built on first call. Raises
    RuntimeError immediately (not lazily inside a request) if REDIS_URL
    isn't configured -- same shape as Settings.require_secret_key() /
    Settings.database_url."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        redis_url = settings.require_redis_url()
        _redis_client = redis.from_url(
            redis_url,
            # Fail fast rather than hang a request: see module docstring.
            socket_connect_timeout=settings.redis_timeout_seconds,
            socket_timeout=settings.redis_timeout_seconds,
            decode_responses=True,
            health_check_interval=30,
        )
    return _redis_client


async def dispose_redis_client() -> None:
    """Closes and drops the cached client. Tests use this to get a fresh
    client against a possibly-different REDIS_URL between cases; a real
    process never needs to call it."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.aclose()
        _redis_client = None
