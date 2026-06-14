"""OAuth2 Client models."""

import re
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from authglow.core.datetime import utcnow

_COLOR_HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_BORDER_RADIUS_RE = re.compile(r"^[0-9.]+(px|em|rem|%)$")


class ClientBranding(BaseModel):
    """Structured branding for the OAuth2 consent page.

    Replaces the former raw ``custom_css`` field with a typed object
    that is safe to render as CSS custom properties — only pre-validated
    values reach the ``<style>`` tag (VAPT-037 fix).
    """

    primary_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    surface_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    text_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    font_family: Optional[str] = Field(None, max_length=200)
    border_radius: Optional[str] = Field(None, pattern=r"^[0-9.]+(px|em|rem|%)$")
    logo_url: Optional[str] = None

    @field_validator("logo_url")
    @classmethod
    def _validate_logo_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"logo_url scheme must be http or https, got: {parsed.scheme!r}")
        return v

    @field_validator("font_family")
    @classmethod
    def _validate_font_family(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if "<" in v or ">" in v:
            raise ValueError("font_family must not contain < or >")
        return v


class OAuth2Client(BaseModel):
    """OAuth2 Client model."""

    client_id: str = Field(default_factory=lambda: str(uuid4()))
    client_secret: str  # Hashed
    client_name: str

    # OAuth2 settings
    redirect_uris: List[str] = Field(default_factory=list)
    allowed_scopes: List[str] = Field(default_factory=lambda: ["read"])
    grant_types: List[str] = Field(default_factory=lambda: ["authorization_code", "refresh_token"])

    # Client type
    is_confidential: bool = True  # False for public clients (PKCE required)

    # Metadata
    description: Optional[str] = None
    logo_uri: Optional[str] = None
    homepage_uri: Optional[str] = None
    terms_uri: Optional[str] = None
    privacy_uri: Optional[str] = None
    # Structured branding (VAPT-037 — replaces raw custom_css)
    branding: Optional[ClientBranding] = None

    # Status
    is_active: bool = True
    created_at: datetime = Field(default_factory=utcnow)
    created_by: Optional[str] = None  # User ID who created the client

    # Security
    require_pkce: bool = False
    require_consent: bool = True  # Show consent screen

    # Usage tracking
    last_used_at: Optional[datetime] = None
    access_token_lifetime: int = 3600  # seconds (1 hour)
    refresh_token_lifetime: int = 2592000  # seconds (30 days)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "client_name": "My Application",
                "redirect_uris": ["https://myapp.com/callback"],
                "allowed_scopes": ["read", "write"],
                "description": "My awesome application",
            }
        }
    )


class OAuth2ClientCreate(BaseModel):
    """Schema for creating a new OAuth2 client."""

    client_name: str = Field(..., min_length=3, max_length=100)
    redirect_uris: List[str] = Field(..., min_length=1)
    allowed_scopes: List[str] = Field(default_factory=lambda: ["read"])
    grant_types: List[str] = Field(default_factory=lambda: ["authorization_code", "refresh_token"])

    is_confidential: bool = True
    require_pkce: bool = False
    require_consent: bool = True

    description: Optional[str] = Field(None, max_length=500)
    logo_uri: Optional[str] = None
    homepage_uri: Optional[str] = None
    terms_uri: Optional[str] = None
    privacy_uri: Optional[str] = None
    custom_css: Optional[str] = Field(None, max_length=20000)
    branding: Optional[ClientBranding] = None

    access_token_lifetime: int = Field(3600, ge=300, le=86400)  # 5 min to 24 hours
    refresh_token_lifetime: int = Field(2592000, ge=3600, le=7776000)  # 1 hour to 90 days

    @field_validator("logo_uri", "homepage_uri", "terms_uri", "privacy_uri")
    @classmethod
    def _validate_uri_scheme(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"URI scheme must be http or https, got: {parsed.scheme!r}")
        return v

    @field_validator("logo_uri", "homepage_uri", "terms_uri", "privacy_uri")
    @classmethod
    def _validate_uri_length(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 2048:
            raise ValueError("URI must be at most 2048 characters")
        return v


class OAuth2ClientUpdate(BaseModel):
    """Schema for updating an OAuth2 client."""

    client_name: Optional[str] = Field(None, min_length=3, max_length=100)
    redirect_uris: Optional[List[str]] = None
    allowed_scopes: Optional[List[str]] = None
    grant_types: Optional[List[str]] = None
    is_confidential: Optional[bool] = None

    require_pkce: Optional[bool] = None
    require_consent: Optional[bool] = None

    description: Optional[str] = Field(None, max_length=500)
    logo_uri: Optional[str] = None
    homepage_uri: Optional[str] = None
    terms_uri: Optional[str] = None
    privacy_uri: Optional[str] = None
    custom_css: Optional[str] = Field(None, max_length=20000)

    is_active: Optional[bool] = None

    access_token_lifetime: Optional[int] = Field(None, ge=300, le=86400)
    refresh_token_lifetime: Optional[int] = Field(None, ge=3600, le=7776000)

    @field_validator("logo_uri", "homepage_uri", "terms_uri", "privacy_uri")
    @classmethod
    def _validate_uri_scheme_update(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"URI scheme must be http or https, got: {parsed.scheme!r}")
        return v

    @field_validator("logo_uri", "homepage_uri", "terms_uri", "privacy_uri")
    @classmethod
    def _validate_uri_length_update(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 2048:
            raise ValueError("URI must be at most 2048 characters")
        return v


class OAuth2ClientResponse(BaseModel):
    """Public OAuth2 client response (without secret)."""

    client_id: str
    client_name: str
    redirect_uris: List[str]
    allowed_scopes: List[str]
    grant_types: List[str]

    is_confidential: bool
    require_pkce: bool
    require_consent: bool

    description: Optional[str] = None
    logo_uri: Optional[str] = None
    homepage_uri: Optional[str] = None
    terms_uri: Optional[str] = None
    privacy_uri: Optional[str] = None
    # Structured branding (VAPT-037 — replaces raw custom_css)
    branding: Optional[ClientBranding] = None

    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None

    access_token_lifetime: int
    refresh_token_lifetime: int


class OAuth2ClientWithSecret(OAuth2ClientResponse):
    """OAuth2 client response with plaintext secret (only shown once at creation)."""

    client_secret: str  # Plaintext, only shown at creation


class OAuth2ClientSecretRotation(BaseModel):
    """Response for client secret rotation."""

    client_id: str
    new_client_secret: str  # Plaintext
    expires_at: Optional[datetime] = None
