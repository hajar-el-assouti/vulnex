"""Password hashing, session tokens, and CSRF token helpers.

Nothing here touches the database or FastAPI -- pure functions, easy to
unit test and to reuse from Celery tasks later if needed.
"""

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Library defaults (time_cost=3, memory_cost=64 MiB, parallelism=4,
# hash_len=32, salt_len=16) are argon2-cffi's own current recommendation,
# not something we invented -- see security summary for the reasoning.
_password_hasher = PasswordHasher()

# Hashed once at import time so that verifying a login for a non-existent
# email costs the same as a real one (constant-ish effort), closing a
# timing side-channel that would otherwise leak which emails are
# registered. The actual string is irrelevant; nobody is meant to know it.
_DUMMY_HASH = _password_hasher.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    """Argon2id-hash a plaintext password. Never log or persist the input."""
    return _password_hasher.hash(password)


def verify_password(hashed_password: str, password: str) -> bool:
    """True iff `password` matches `hashed_password`. Never raises."""
    try:
        return _password_hasher.verify(hashed_password, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_dummy_password(password: str) -> None:
    """Call this (and discard the result) when no user was found, so a
    login attempt against an unknown email takes roughly as long as one
    against a real email -- see _DUMMY_HASH above."""
    verify_password(_DUMMY_HASH, password)


def password_needs_rehash(hashed_password: str) -> bool:
    """True if `hashed_password` was produced with weaker-than-current
    Argon2 parameters (e.g. after a deliberate parameter bump) and should
    be silently re-hashed on the next successful login."""
    try:
        return _password_hasher.check_needs_rehash(hashed_password)
    except InvalidHashError:
        return False


def generate_session_token() -> str:
    """A fresh, opaque, high-entropy session token for the client to hold
    (in a cookie). 32 bytes of randomness, URL-safe-encoded."""
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """SHA-256 hex digest of a session token -- this is what's persisted
    in sessions.session_token_hash, never the raw token. SHA-256 (not a
    slow KDF) is appropriate here because the input is already
    high-entropy random data, not a human-chosen secret to stretch."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_csrf_token(session_token_hash: str, secret_key: str) -> str:
    """Derives a CSRF token via HMAC from the session's *stored hash*
    (sessions.session_token_hash) -- deliberately NOT the raw session
    token, which the server never has again after login (only its hash
    is persisted; see hash_session_token above). Using the hash as the
    HMAC input is just as sound: HMAC's security comes from secret_key,
    not from the input being secret, and session_token_hash is already
    unique per session. This needs no storage of its own and binds the
    CSRF token to one specific session (a token for session A is useless
    against session B)."""
    return hmac.new(
        secret_key.encode("utf-8"), session_token_hash.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_csrf_token(session_token_hash: str, csrf_token: str, secret_key: str) -> bool:
    expected = generate_csrf_token(session_token_hash, secret_key)
    return hmac.compare_digest(expected, csrf_token)
