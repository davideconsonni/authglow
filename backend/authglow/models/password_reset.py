"""Password reset token models."""

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, EmailStr, Field, model_validator

from authglow.core.datetime import utcnow


class PasswordResetToken(BaseModel):
    """Password reset token model."""

    token_id: str = Field(default_factory=lambda: str(uuid4()))
    token_lookup: str = ""
    user_id: str
    email: EmailStr
    token_hash: str  # Hashed token for security
    reset_code: str = ""  # Human-friendly code shown in email (VAPT-022 fix)
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
    """Confirm password reset with the reset code and a new password.

    VAPT-022 fix: clients send the human-friendly ``reset_code`` shown in
    the email body instead of a bearer token. The legacy ``token`` field
    is still accepted (and rejected at the service layer) for backward
    compatibility with the previous API contract.
    """

    reset_code: str = Field(min_length=14, max_length=20)
    new_password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_token_field(cls, data: Any) -> Any:
        if isinstance(data, Dict) and "reset_code" not in data and "token" in data:
            data = {**data, "reset_code": data["token"]}
        return data


class PasswordChange(BaseModel):
    """Change password for authenticated user."""

    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


class PasswordResetResponse(BaseModel):
    """Response after initiating password reset."""

    message: str
    email: EmailStr
    expires_in_minutes: int = 30
