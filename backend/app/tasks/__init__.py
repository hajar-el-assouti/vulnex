"""Celery task modules. Imported by the worker process only (see
app/celery_app.py's `include=[...]`) -- never by app.main / the FastAPI
process, so importing this package must not be assumed safe without a
configured broker (it isn't, and that's fine)."""
