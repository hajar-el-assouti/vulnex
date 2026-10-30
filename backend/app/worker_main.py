"""Celery CLI entry point.

    celery -A app.worker_main worker --loglevel=info
    celery -A app.worker_main beat --loglevel=info

Deliberately separate from app/celery_app.py, whose `get_celery_app()`
is lazy (so importing it from the FastAPI process never requires a
configured broker -- see that module's docstring). This module is only
ever imported by the Celery CLI, where eagerly requiring REDIS_URL is
correct and expected.
"""

from app.celery_app import get_celery_app

app = get_celery_app()
