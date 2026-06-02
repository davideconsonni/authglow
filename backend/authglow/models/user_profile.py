"""User profile and account management models."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field

from authglow.core.datetime import utcnow


class UserProfileUpdate(BaseModel):
    """Update user profile request."""

    first_name: Optional[str] = Field(None, max_length=100)
    last_name: Optional[str] = Field(None, max_length=100)
    avatar_url: Optional[str] = None
    phone: Optional[str] = None
    timezone: Optional[str] = "UTC"
    language: Optional[str] = "en"


class ChangePasswordRequest(BaseModel):
    """Change password request."""

    current_password: str
    new_password: str = Field(..., min_length=8)


class ChangeEmailRequest(BaseModel):
    """Change email request."""

    new_email: EmailStr
    password: str  # Confirm with password


class DeleteAccountRequest(BaseModel):
    """Delete account request."""

    password: str  # Confirm with password
    confirmation: str  # Must be "DELETE" to confirm


class UserPreferences(BaseModel):
    """User preferences/settings."""

    preferences_id: str = Field(default_factory=lambda: str(__import__("uuid").uuid4()))
    user_id: str

    # Notification preferences
    email_notifications: bool = True
    security_alerts: bool = True
    marketing_emails: bool = False

    # UI preferences
    theme: str = "light"  # auto, light, dark
    language: str = "en"
    timezone: str = "UTC"

    # Privacy preferences
    profile_visibility: str = "private"  # public, private
    show_email: bool = False

    # Session preferences
    session_timeout: int = 3600  # seconds
    require_mfa_always: bool = False

    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}


class UserPreferencesUpdate(BaseModel):
    """Update user preferences request."""

    email_notifications: Optional[bool] = None
    security_alerts: Optional[bool] = None
    marketing_emails: Optional[bool] = None
    theme: Optional[str] = None
    language: Optional[str] = None
    timezone: Optional[str] = None
    profile_visibility: Optional[str] = None
    show_email: Optional[bool] = None
    session_timeout: Optional[int] = None
    require_mfa_always: Optional[bool] = None


class UserProfileResponse(BaseModel):
    """Complete user profile response."""

    id: str
    email: EmailStr
    email_verified: bool
    first_name: Optional[str]
    last_name: Optional[str]
    avatar_url: Optional[str]
    phone: Optional[str]
    timezone: str
    language: str
    is_active: bool
    mfa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]

    # Roles and scopes
    roles: list[str] = []
    scopes: list[str] = []

    # Preferences
    preferences: Optional[UserPreferences] = None

    # Stats
    total_logins: int = 0
    failed_login_attempts: int = 0
