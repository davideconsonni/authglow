"""Password reset token models."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, EmailStr
from uuid import uuid4

from authglow.core.datetime import utcnow


class PasswordResetToken(BaseModel):
    """Password reset token model."""

    token_id: str = Field(default_factory=lambda: str(uuid4()))
    token_lookup: str = ""
    user_id: str
    email: EmailStr
    token_hash: str  # Hashed token for security
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    used_at: Optional[datetime] = None
    is_used: bool = False
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


class PasswordResetRequest(BaseModel):
    """Request to initiate password reset."""

    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Confirm password reset with token and new password."""

    token: str
    new_password: str = Field(min_length=8, max_length=128)


class PasswordChange(BaseModel):
    """Change password for authenticated user."""

    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class PasswordResetResponse(BaseModel):
    """Response after initiating password reset."""

    message: str
    email: EmailStr
    expires_in_minutes: int = 30
