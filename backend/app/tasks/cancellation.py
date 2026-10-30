"""Live cancellation for a module run, based on polling.

A single cancellation check taken before the module starts is fine
for a module that finishes in under a second, but not for engines
that make slow network requests: a scan cancelled ten seconds in
wouldn't stop until the module finished or hit its deadline.

So the module's blocking `run()` runs in a thread executor, while a
background task polls the database on a separate session (an
AsyncSession can't be shared between coroutines) every
Settings.recon_cancellation_poll_interval_seconds. When cancellation
is seen, a threading.Event is set. Collectors' `is_cancelled()` reads
that Event, never the database, so the check stays cheap.

No Celery or Postgres specific code here: `poll_session_factory` is
any callable returning an async context manager over an AsyncSession
(an `async_sessionmaker` works), so the same code runs in Celery and
in tests."""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from typing import Awaitable, Callable

logger = logging.getLogger("app.tasks.cancellation")

# Any zero-arg callable returning an async context manager over an
# AsyncSession -- deliberately untyped beyond that (an
# sqlalchemy.ext.asyncio.async_sessionmaker instance satisfies this,
# and so does a trivial test double), so this module never has to
# import SQLAlchemy types just to describe the shape.
PollSessionFactory = Callable[[], object]


class LiveCancellation:
    """One instance per module run. `is_cancelled` (a plain, cheap,
    synchronous callable -- never awaited, never touches the database
    itself) is what gets wired into ScanContext.cancellation; `start()`
    / `stop()` bracket the one `module_impl.run(context)` call this
    instance was built for."""

    def __init__(self, *, initial_cancelled: bool) -> None:
        self._event = threading.Event()
        if initial_cancelled:
            self._event.set()
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def start(
        self,
        *,
        poll_session_factory: PollSessionFactory | None,
        scan_id: uuid.UUID,
        check_cancelled: Callable[[object, uuid.UUID], Awaitable[bool]],
        poll_interval_seconds: float,
    ) -> None:
        """No-op (by design) when `poll_session_factory` is None -- a
        caller that does not supply one gets exactly the historical,
        frozen-snapshot-only behavior (whatever `initial_cancelled` was
        at construction time), with no background task ever started
        and no extra database session ever opened. This is what keeps
        every existing test that calls run_scan_logic(db, scan_id)
        without the new keyword-only parameter passing unmodified."""
        if poll_session_factory is None:
            return

        async def _poll() -> None:
            while not self._stop.is_set():
                try:
                    async with poll_session_factory() as poll_db:
                        if await check_cancelled(poll_db, scan_id):
                            self._event.set()
                            return
                except Exception:  # noqa: BLE001 -- a polling hiccup must never abort the scan
                    logger.exception(
                        "Live cancellation poll failed for scan %s; will retry in %.1fs",
                        scan_id,
                        poll_interval_seconds,
                    )
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=poll_interval_seconds)
                except asyncio.TimeoutError:
                    pass

        self._task = asyncio.ensure_future(_poll())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None
