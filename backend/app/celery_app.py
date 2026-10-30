"""Celery application: independent of the FastAPI process.

Import-time behaviour mirrors the rest of this codebase's lazy pattern
(app/db/session.py, app/core/redis_client.py): building this module must
not itself require Redis to be reachable -- `get_settings()` only raises
once something actually tries to read `celery_broker_url`, which pulls
`require_redis_url()`. Celery itself doesn't connect at import time
either; it connects when a worker starts or a task is actually sent.

Broker/result-backend live on separate Redis DB indices from the login
rate limiter's `ratelimit:*` keys (db 0) -- see Settings.celery_broker_db
/ celery_result_backend_db in app/core/config.py. Nothing here ever
touches db 0.
"""

from __future__ import annotations

from functools import lru_cache

from celery import Celery

from app.core.config import get_settings


@lru_cache
def get_celery_app() -> Celery:
    settings = get_settings()
    app = Celery(
        "pentest_saas",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend_url,
        include=["app.tasks.scan_tasks", "app.tasks.maintenance"],
    )

    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        # Hard time limit per module run, on top of whatever the engine
        # enforces itself, in case a task hangs. The soft limit fires first so
        # the task can clean up and mark itself FAILED before being killed.
        task_time_limit=settings.scan_module_run_timeout_seconds + 30,
        task_soft_time_limit=settings.scan_module_run_timeout_seconds,
        # Controlled retries, not unlimited: a task that keeps failing
        # must eventually give up and surface as FAILED, not retry
        # forever and mask a real problem.
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        result_expires=3600,
        beat_schedule={
            "reconcile-pending-scan-dispatch": {
                "task": "app.tasks.maintenance.reconcile_pending_scans",
                "schedule": 15.0,  # seconds -- kept short for local development
            },
            "reconcile-stuck-cancellations": {
                "task": "app.tasks.maintenance.reconcile_stuck_cancellations",
                "schedule": 15.0,
            },
        },
    )
    return app


# Worker entry point (`celery -A app.celery_app:get_celery_app worker ...`
# or, more simply, a tiny module-level `celery_app = get_celery_app()` in
# a worker-only entry script -- see the Celery CLI invocation in
# docker-compose.yml) builds the app eagerly, which is correct for an
# actual worker process. FastAPI's import chain never reaches this
# function unless a request handler calls it, preserving the "importing
# app.main must not require Redis" invariant tested by the unit suite.
