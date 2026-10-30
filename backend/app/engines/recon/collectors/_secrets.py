"""Secret redaction for the asset and API discovery collectors.

These collectors extract raw strings from untrusted page markup
(script/link URLs, API endpoint strings), which sometimes contain a
token, an API key or a signed URL. Every string goes through
`redact_secrets()` before being stored, so secrets never end up in
scan results or logs.

This is a small pattern-based filter, not a full secrets scanner: it
covers common, high-confidence shapes (bearer tokens, JWTs, AWS access
key IDs, obvious credential parameters in query strings)."""

from __future__ import annotations

import re

_SECRET_PATTERNS: tuple[re.Pattern, ...] = (
    # Common query-string/credential-shaped parameters:
    # ?api_key=..., &access_token=..., ?secret=..., ?auth=...
    re.compile(r"(?i)\b((?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd)=)[^&\"'\s]{4,}"),
    # "Bearer <token>" authorization-header-shaped strings.
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-_.=]{10,}"),
    # JWT-shaped strings (three dot-separated base64url segments).
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # AWS access key ID shape.
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


def redact_secrets(text: str) -> str:
    """Returns `text` with every matched secret-shaped substring
    replaced by "[REDACTED]". Safe to call on arbitrary, already-decoded
    text -- never raises, never partially redacts (each pattern is
    applied fully before moving to the next)."""
    redacted = text
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted
