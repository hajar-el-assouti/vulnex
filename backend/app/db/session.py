"""Async SQLAlchemy engine/session wiring.

The engine is built lazily (first call to get_engine()/get_db()), not at
import time. This matters because Settings now has no default DB
credentials (see app/core/config.py) and raises if they're missing --
that's correct for an app that's actually about to connect to Postgres,
but importing `app.main` (to build the FastAPI app, or just to collect
pytest tests) must not itself require a live DB configuration. Tests that
never hit a real DB (the SQLite-backed suite, which overrides `get_db` via
FastAPI's dependency_overrides) therefore never need POSTGRES_* env vars
at all; only code paths that actually connect do.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings


@lru_cache
def get_engine() -> AsyncEngine:
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        echo=settings.debug,
        pool_pre_ping=True,
    )


@lru_cache
def get_session_factory() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=get_engine(),
        expire_on_commit=False,
        class_=AsyncSession,
    )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a request-scoped DB session."""
    async with get_session_factory()() as session:
        yield session


async def dispose_engine() -> None:
    """Call on shutdown if the engine was ever created (see app/main.py)."""
    if get_engine.cache_info().currsize:
        await get_engine().dispose()


@asynccontextmanager
async def worker_scoped_session_factory() -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    """Like worker_scoped_session() below, but yields a session factory
    instead of a single open session, for callers that need several
    short-lived sessions on one task-scoped engine.

    Used by the live cancellation poller in app/tasks/scan_tasks.py: it
    can't share the task's main session (an AsyncSession is not safe
    for concurrent use), and creating a new engine on every poll would
    be wasteful."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=settings.debug, pool_pre_ping=True)
    try:
        yield async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    finally:
        await engine.dispose()


@asynccontextmanager
async def worker_scoped_session() -> AsyncGenerator[AsyncSession, None]:
    """For Celery tasks only (app/tasks/*). FastAPI handlers must keep
    using get_db()/get_session_factory().

    get_engine()/get_session_factory() are cached per process, which is
    fine for uvicorn's single event loop. In Celery, each task runs in
    its own asyncio.run() loop, and asyncpg connections are tied to the
    loop that created them: reusing the cached engine fails with
    "Future attached to a different loop" on the second task.

    So this creates a short-lived engine for one task and disposes it.
    A new connection per task is an acceptable cost here.
    """
    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=settings.debug, pool_pre_ping=True)
    try:
        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
        async with session_factory() as session:
            yield session
    finally:
        await engine.dispose()
