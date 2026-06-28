"""User data models."""

from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from authglow.core.datetime import utcnow
from authglow.core.password import check_password_byte_length


class User(BaseModel):
    """User model."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    email: EmailStr
    hashed_password: str
    is_active: bool = True
    is_invited: bool = True  # Users can only be created via invitation
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    last_login: Optional[datetime] = None
    login_count: int = 0
    failed_login_count: int = 0

    # Additional profile fields
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    address: Optional[dict] = None

    # OAuth2 related
    scopes: List[str] = Field(default_factory=list)
    api_key_scopes: Optional[List[str]] = None

    # Federation related
    is_federated: bool = False

    # MFA related
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = (
        None  # AES-256-GCM encrypted TOTP secret (prefix "ag1:"), or plaintext for migration
    )
    mfa_verified: bool = False  # True after first successful MFA verification

    # Account lockout related
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None

    # Password management
    password_expired: bool = False
    password_changed_at: Optional[datetime] = None

    # Email verification
    email_verified: bool = False
    email_verified_at: Optional[datetime] = None

    # Temporary suspension
    suspended_until: Optional[datetime] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "is_active": True,
                "scopes": ["read", "write"],
            }
        }
    )


class UserCreate(BaseModel):
    """Schema for creating a new user (admin only)."""

    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    scopes: List[str] = Field(default_factory=lambda: ["read"])
    email_verified: bool = False

    @field_validator("password")
    @classmethod
    def _vapt039_password_byte_cap(cls, v: str) -> str:
        return check_password_byte_length(v)


class UserLogin(BaseModel):
    """Schema for user login."""

    email: EmailStr
    password: str


class UserResponse(BaseModel):
    """Public user response (without sensitive data)."""

    id: str
    email: EmailStr
    is_active: bool
    created_at: datetime
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    scopes: List[str]
    mfa_enabled: bool = False
    mfa_verified: bool = False
    email_verified: bool = False
    is_federated: bool = False


class RegisterUser(BaseModel):
    """Schema for public self-registration."""

    email: EmailStr
    password: str = Field(..., min_length=8)
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    @field_validator("password")
    @classmethod
    def _vapt039_password_byte_cap(cls, v: str) -> str:
        return check_password_byte_length(v)


class InviteUser(BaseModel):
    """Schema for inviting a new user."""

    email: EmailStr
    scopes: List[str] = Field(default_factory=lambda: ["read"])
    first_name: Optional[str] = None
    last_name: Optional[str] = None
