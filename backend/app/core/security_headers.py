"""Baseline HTTP security headers for every response.

This is a JSON-only API: nothing is rendered as HTML, so the CSP is
strict on purpose (`default-src 'none'; frame-ancestors 'none'`).
The Next.js frontend has its own CSP for what it renders.

HSTS is only sent when `settings.cookie_secure` is on (non-development
environments), the same signal used for the session cookie. Sending
HSTS over plain HTTP in the lab would make browsers refuse to connect
to the app.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import get_settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        settings = get_settings()

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        # Only when this process actually believes it is serving over
        # HTTPS (same signal as the session cookie's Secure flag) --
        # never in the HTTP lab.
        if settings.cookie_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
            )

        return response
