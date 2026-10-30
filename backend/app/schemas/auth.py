"""Request/response schemas for /api/v1/auth/*.

Password policy: OWASP ASVS leans on length over forced complexity rules
(composition requirements push people toward predictable patterns like
"Password1!"). We require length only: 10-128 characters. 128 is also a
DoS guard -- without a cap, someone could POST a multi-megabyte string as
"password" and make the server hash all of it.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        # Case-insensitive lookups/uniqueness: nobody in practice treats
        # the local part of an email as case-sensitive, whatever the RFC
        # technically allows.
        return value.strip().lower()

    @field_validator("full_name")
    @classmethod
    def _clean_full_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, value: str) -> str:
        return value.strip().lower()


class UserPublic(BaseModel):
    """Never includes hashed_password or anything session-related."""

    id: uuid.UUID
    email: str
    full_name: str | None
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class MessageResponse(BaseModel):
    detail: str
