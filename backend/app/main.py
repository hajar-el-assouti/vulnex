from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.redis_client import dispose_redis_client
from app.core.security_headers import SecurityHeadersMiddleware
from app.db.session import dispose_engine

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    yield
    # Only disposes if a DB engine / Redis client was actually created
    # during this process's lifetime -- importing/starting the app must
    # not itself require DB or Redis config (see app/db/session.py,
    # app/core/redis_client.py and app/core/config.py).
    await dispose_engine()
    await dispose_redis_client()


app = FastAPI(
    title=settings.project_name,
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Added after CORS (Starlette runs middlewares in reverse of add order,
# so this one ends up innermost/closest to the route handlers) -- it
# must still see and annotate error responses from routes and from
# register_exception_handlers below, which it does since it wraps
# call_next() unconditionally.
app.add_middleware(SecurityHeadersMiddleware)

register_exception_handlers(app)
app.include_router(api_router, prefix=settings.api_v1_prefix)
