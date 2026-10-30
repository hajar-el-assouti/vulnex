"""A Redis-backed, atomic sliding-window rate limiter.

Replaces the in-memory version from the previous revision. That version
was explicitly flagged as per-process -- correct for one worker, but
giving each replica behind a load balancer its own `max_attempts`
budget, which is not what "5 attempts per 15 minutes" is supposed to
mean once there's more than one backend process. Redis makes the
counters shared, so the limit holds regardless of how many uvicorn
workers or containers are answering requests.

Concurrency: each check/hit is one Redis Lua script (`_SCRIPT` below),
and Redis executes a given Lua script to completion before starting
the next command -- there is no read-then-write race window between
two concurrent requests hitting the same key, unlike a naive
GET-then-SET implementation would have. The limiter keeps the sliding
window semantics of the previous version (not a fixed window, which
allows bursting across a window boundary): entries are timestamps in a
Redis sorted set, pruned to the trailing `window_seconds` on every call.

Expiration: a PEXPIRE is set on the key on every `hit()`, equal to the
window size, so an abandoned key (no more hits) disappears from Redis
on its own instead of accumulating forever.

Fail-closed by default: if Redis is unreachable or errors, every method
here raises `RateLimiterUnavailableError` rather than silently behaving
as "not blocked" -- see `Settings.rate_limit_fail_open` for why, and
`app/api/v1/endpoints/auth.py` for how the endpoints turn that into a
503 response.
"""

from __future__ import annotations

import math
import time
import uuid

import redis.asyncio as redis
from redis.exceptions import RedisError

# KEYS[1] = bucket key
# ARGV[1] = now, in milliseconds
# ARGV[2] = window size, in milliseconds
# ARGV[3] = max_attempts
# ARGV[4] = "1" to record a hit, "0" to only check/prune
# ARGV[5] = unique member to add when recording a hit
#
# Returns {count_after_pruning(+hit), retry_after_ms}. One round trip,
# executed atomically by Redis -- see module docstring.
_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local max_attempts = tonumber(ARGV[3])
local do_hit = ARGV[4] == "1"
local member = ARGV[5]

redis.call("ZREMRANGEBYSCORE", key, "-inf", now - window)

if do_hit then
    redis.call("ZADD", key, now, member)
    redis.call("PEXPIRE", key, window)
end

local count = redis.call("ZCARD", key)

local retry_after_ms = 0
if count > 0 then
    local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
    if oldest[2] then
        retry_after_ms = tonumber(oldest[2]) + window - now
        if retry_after_ms < 0 then
            retry_after_ms = 0
        end
    end
end

return {count, retry_after_ms}
"""


class RateLimiterUnavailableError(Exception):
    """Raised instead of failing open when Redis is unreachable or errors.
    Callers decide the HTTP behavior (503 by default), see
    Settings.rate_limit_fail_open."""


class RedisSlidingWindowRateLimiter:
    def __init__(
        self,
        redis_client: redis.Redis,
        *,
        max_attempts: int,
        window_seconds: float,
        key_prefix: str,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._redis = redis_client
        self._max_attempts = max_attempts
        self._window_ms = int(window_seconds * 1000)
        self._key_prefix = key_prefix
        self._script = self._redis.register_script(_SCRIPT)

    def _key(self, key: str) -> str:
        return f"{self._key_prefix}:{key}"

    async def _run(self, key: str, *, hit: bool) -> tuple[int, int]:
        now_ms = int(time.time() * 1000)
        member = f"{now_ms}:{uuid.uuid4().hex}" if hit else "0"
        try:
            count, retry_after_ms = await self._script(
                keys=[self._key(key)],
                args=[now_ms, self._window_ms, self._max_attempts, "1" if hit else "0", member],
            )
        except RedisError as exc:
            raise RateLimiterUnavailableError(
                f"Redis rate limiter unavailable: {exc}"
            ) from exc
        return int(count), int(retry_after_ms)

    async def hit(self, key: str) -> None:
        """Record one attempt against `key` (call this on a FAILED
        login, or on every registration attempt -- see call sites)."""
        await self._run(key, hit=True)

    async def is_blocked(self, key: str) -> bool:
        count, _ = await self._run(key, hit=False)
        return count >= self._max_attempts

    async def reset(self, key: str) -> None:
        """Call on a SUCCESSFUL login so one slip-up doesn't linger
        against a legitimate user who then typed their password right."""
        try:
            await self._redis.delete(self._key(key))
        except RedisError as exc:
            raise RateLimiterUnavailableError(
                f"Redis rate limiter unavailable: {exc}"
            ) from exc

    async def retry_after_seconds(self, key: str) -> int:
        """Whole seconds until `key` would stop being blocked, for a
        Retry-After header. 0 if not currently blocked."""
        _, retry_after_ms = await self._run(key, hit=False)
        return max(0, math.ceil(retry_after_ms / 1000))
