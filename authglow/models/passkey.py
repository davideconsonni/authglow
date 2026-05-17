"""Passkey/WebAuthn models for AuthGlow."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class Passkey(BaseModel):
    """Passkey credential stored for a user."""

    credential_id: str = Field(..., description="Base64url encoded credential ID")
    public_key: str = Field(..., description="Base64url encoded public key")
    sign_count: int = Field(
        default=0, description="Signature counter for replay protection"
    )
    transports: list[str] = Field(
        default_factory=list,
        description="Authenticator transports (usb, nfc, ble, internal)",
    )
    aaguid: str = Field(..., description="Authenticator AAGUID")
    user_id: str = Field(..., description="User ID this passkey belongs to")
    name: str = Field(
        default="My Passkey", description="User-friendly name for this passkey"
    )
    created_at: datetime = Field(default_factory=utcnow)
    last_used_at: Optional[datetime] = None
    device_type: Optional[str] = Field(
        None, description="Device type (phone, computer, security_key)"
    )
    backup_eligible: bool = Field(
        default=False, description="Whether credential can be backed up"
    )
    backup_state: bool = Field(
        default=False, description="Whether credential is currently backed up"
    )


class PasskeyRegistrationOptions(BaseModel):
    """Options for starting passkey registration."""

    challenge: str = Field(..., description="Base64url encoded challenge")
    rp_id: str = Field(..., description="Relying Party ID (domain)")
    rp_name: str = Field(..., description="Relying Party name")
    user_id: str = Field(..., description="User ID (base64url)")
    user_name: str = Field(..., description="User name (email)")
    user_display_name: str = Field(..., description="User display name")
    timeout: int = Field(default=60000, description="Timeout in milliseconds")
    attestation: str = Field(
        default="none", description="Attestation conveyance preference"
    )
    user_verification: str = Field(
        default="preferred", description="User verification requirement"
    )
    authenticator_attachment: Optional[str] = Field(
        None, description="platform or cross-platform"
    )
    resident_key: str = Field(
        default="required", description="Resident key requirement"
    )


class PasskeyRegistrationVerification(BaseModel):
    """Data sent by client to verify passkey registration."""

    credential_id: str
    client_data_json: str  # Base64url encoded
    attestation_object: str  # Base64url encoded
    transports: list[str] = Field(default_factory=list)
    name: str = Field(default="My Passkey", description="User-friendly name")


class PasskeyAuthenticationOptions(BaseModel):
    """Options for starting passkey authentication."""

    challenge: str = Field(..., description="Base64url encoded challenge")
    rp_id: str = Field(..., description="Relying Party ID (domain)")
    timeout: int = Field(default=60000, description="Timeout in milliseconds")
    user_verification: str = Field(
        default="preferred", description="User verification requirement"
    )
    allow_credentials: list[dict] = Field(
        default_factory=list, description="Allowed credentials"
    )


class PasskeyAuthenticationVerification(BaseModel):
    """Data sent by client to verify passkey authentication."""

    credential_id: str
    client_data_json: str  # Base64url encoded
    authenticator_data: str  # Base64url encoded
    signature: str  # Base64url encoded
    user_handle: Optional[str] = None  # Base64url encoded user ID


class PasskeyResponse(BaseModel):
    """Response model for passkey information."""

    credential_id: str
    name: str
    created_at: datetime
    last_used_at: Optional[datetime]
    device_type: Optional[str]
    transports: list[str]
    backup_eligible: bool
    backup_state: bool


class PasskeyChallenge(BaseModel):
    """Temporary challenge storage for WebAuthn ceremony."""

    challenge: str
    user_id: str
    expires_at: datetime
    type: str  # "registration" or "authentication"
