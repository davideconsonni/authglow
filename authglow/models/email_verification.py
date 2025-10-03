"""Email verification models."""

from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4
from pydantic import BaseModel, EmailStr, Field


class EmailVerificationToken(BaseModel):
    """Email verification token model."""

    token: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str
    email: EmailStr
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.utcnow() + timedelta(hours=24)
    )
    used: bool = False
    used_at: Optional[datetime] = None

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class EmailVerificationRequest(BaseModel):
    """Request to verify email."""
    token: str


class ResendVerificationRequest(BaseModel):
    """Request to resend verification email."""
    email: EmailStr
