"""Centralised exception handling.

Goals:
- Never leak internal details (stack traces, SQL, file paths) to API clients.
- Always return a consistent JSON error shape.
- Log unhandled exceptions server-side for debugging.
"""

import logging

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("app.errors")


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # jsonable_encoder, not a raw dict: when a @field_validator raises a
        # plain ValueError, Pydantic puts the exception object itself in
        # errors()[i]['ctx']['error'], and json.dumps can't serialize it.
        # FastAPI's default handler uses jsonable_encoder for the same reason.
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "Validation error",
                "errors": jsonable_encoder(exc.errors()),
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        # exc.headers matters: e.g. the 429 from login rate limiting sets
        # Retry-After, which a rebuilt response without it would silently
        # drop. Found by actually calling the endpoint, not by reading
        # this handler and assuming it was fine.
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=exc.headers,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "Unhandled error on %s %s", request.method, request.url.path
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )
