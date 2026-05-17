"""Email verification models."""

from datetime import datetime, timedelta
from typing import Optional
import secrets
from pydantic import BaseModel, EmailStr, Field

from authglow.core.datetime import utcnow


class EmailVerificationToken(BaseModel):
    """Email verification token model."""

    token: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    user_id: str
    email: EmailStr
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(default_factory=lambda: utcnow() + timedelta(hours=24))
    used: bool = False
    used_at: Optional[datetime] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}


class EmailVerificationRequest(BaseModel):
    """Request to verify email."""

    token: str


class ResendVerificationRequest(BaseModel):
    """Request to resend verification email."""

    email: EmailStr
