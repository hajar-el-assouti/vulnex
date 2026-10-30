"""The `sessions` table: server-side, stateful sessions.

Not JWT. A session is valid only if a matching, non-expired,
non-revoked row exists here, which makes instant revocation possible
(a self-contained JWT would need an extra denylist for that).

The client holds one opaque, random, high-entropy token created at
login. Only its hash is stored, like a password, so a database leak
doesn't give usable tokens. There is no refresh token: the client
sends the same token until it expires or is revoked.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class UserSession(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # SHA-256 (or stronger) hash of the opaque session token held by the
    # client, e.g. in a Secure, HttpOnly, SameSite cookie. Never the raw
    # token, and never a JWT.
    session_token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    user_agent: Mapped[str | None] = mapped_column(String(512))
    ip_address: Mapped[str | None] = mapped_column(String(64))

    # Absolute expiry, set once at creation (e.g. now + 12h).
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Updated on each authenticated request; lets a future auth layer apply
    # an idle timeout (e.g. revoke after 30min of inactivity) independently
    # of the absolute expiry above, without needing a second table.
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Set when the session is explicitly killed (logout, "sign out
    # everywhere", password change, admin action). NULL = still live,
    # subject to expires_at / last_seen_at.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped["User"] = relationship(back_populates="sessions")

    def __repr__(self) -> str:  # pragma: no cover
        return f"UserSession(id={self.id!r}, user_id={self.user_id!r})"
