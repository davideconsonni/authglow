"""MFA (Multi-Factor Authentication) data models."""

from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class MFASecret(BaseModel):
    """TOTP secret for a user."""

    user_id: str
    secret: str  # Base32 encoded secret
    is_verified: bool = False  # True after first successful verification
    created_at: datetime = Field(default_factory=utcnow)
    verified_at: Optional[datetime] = None


class BackupCodes(BaseModel):
    """Backup codes for MFA recovery."""

    user_id: str
    codes: List[str] = Field(default_factory=list)  # Hashed backup codes
    created_at: datetime = Field(default_factory=utcnow)
    used_count: int = 0


class TrustedDevice(BaseModel):
    """Trusted device that doesn't require MFA for 30 days."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str
    device_fingerprint: str  # Hash of user agent + IP or other identifying info
    name: Optional[str] = None  # User-friendly device name
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    last_used: datetime = Field(default_factory=utcnow)


class MFAEnrollRequest(BaseModel):
    """Request to start MFA enrollment."""

    pass  # No parameters needed, just trigger enrollment


class MFAEnrollResponse(BaseModel):
    """Response with QR code and secret for enrollment."""

    secret: str
    qr_code: str  # Base64 encoded QR code image
    backup_codes: List[str]  # Plain text backup codes (show once!)


class MFAVerifyRequest(BaseModel):
    """Request to verify TOTP or backup code."""

    code: str = Field(..., min_length=6, max_length=9)


class MFALoginRequest(BaseModel):
    """MFA code during login."""

    session_token: str  # Temporary session token from first auth step
    code: str = Field(..., min_length=6, max_length=9)  # TOTP or backup code
    trust_device: bool = False


class BackupCodeAttempt(BaseModel):
    """Tracks failed backup code verification attempts for rate limiting."""

    user_id: str
    failed_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_attempt_at: datetime = Field(default_factory=utcnow)


class MFAStatus(BaseModel):
    """User's MFA status."""

    enabled: bool
    verified: bool
    backup_codes_remaining: int
    trusted_devices_count: int
