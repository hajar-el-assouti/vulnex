"""Minimal logging setup.

A single basicConfig call with a consistent format. Everything goes
through the standard `logging` module, so JSON formatting or log
aggregation can be added later without touching call sites.
"""

import logging

from app.core.config import get_settings


def configure_logging() -> None:
    settings = get_settings()
    level = logging.DEBUG if settings.debug else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )

    # Quiet down noisy third-party loggers unless we're in debug mode.
    if not settings.debug:
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
