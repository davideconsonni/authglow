"""Email verification models."""

from datetime import datetime, timedelta
from typing import Optional

from pydantic import BaseModel, EmailStr, Field

from authglow.core.datetime import utcnow


class EmailVerificationToken(BaseModel):
    """Email verification token model.

    Security: The plaintext ``token`` is never persisted. Only ``token_hash``
    (bcrypt) and ``token_lookup`` (HMAC-SHA256) are stored on disk.
    """

    token: str = Field(default="", exclude=True)
    token_hash: str = ""
    token_lookup: str = ""
    user_id: str
    email: EmailStr
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(default_factory=lambda: utcnow() + timedelta(hours=24))
    used: bool = False
    used_at: Optional[datetime] = None


class EmailVerificationRequest(BaseModel):
    """Request to verify email."""

    token: str


class ResendVerificationRequest(BaseModel):
    """Request to resend verification email."""

    email: EmailStr
