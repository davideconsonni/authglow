"""OAuth2 Client models."""

import re
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from authglow.core.datetime import utcnow

_COLOR_HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
_BORDER_RADIUS_RE = re.compile(r"^[0-9.]+(px|em|rem|%)$")

_GRANT_TYPES_REJECTED_MESSAGE = (
    "The 'implicit' grant_type is not supported (OAuth 2.0 Security BCP). "
    "Use 'authorization_code' with PKCE instead."
)


def _reject_implicit_grant(v: List[str]) -> List[str]:
    """Reject the ``implicit`` grant type per OAuth 2.0 Security BCP.

    Shared validator body for ``OAuth2Client`` / ``OAuth2ClientCreate`` /
    ``OAuth2ClientUpdate`` so the error message stays consistent.
    """
    if "implicit" in v:
        raise ValueError(_GRANT_TYPES_REJECTED_MESSAGE)
    return v


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
    allowed_post_logout_redirect_uris: List[str] = Field(default_factory=list)
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
    require_pkce: bool = True
    require_consent: bool = True  # Show consent screen

    # OIDC Session Management / Logout
    backchannel_logout_uri: Optional[str] = None
    frontchannel_logout_uri: Optional[str] = None

    # Usage tracking
    last_used_at: Optional[datetime] = None
    access_token_lifetime: int = 3600  # seconds (1 hour)
    refresh_token_lifetime: int = 2592000  # seconds (30 days)

    @field_validator("grant_types")
    @classmethod
    def _reject_implicit_grant_on_client(cls, v: List[str]) -> List[str]:
        return _reject_implicit_grant(v)

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
    redirect_uris: List[str] = Field(default_factory=list)
    allowed_post_logout_redirect_uris: List[str] = Field(default_factory=list)
    allowed_scopes: List[str] = Field(default_factory=lambda: ["read"])
    grant_types: List[str] = Field(default_factory=lambda: ["authorization_code", "refresh_token"])

    is_confidential: bool = True
    require_pkce: bool = True
    require_consent: bool = True

    backchannel_logout_uri: Optional[str] = None
    frontchannel_logout_uri: Optional[str] = None

    description: Optional[str] = Field(None, max_length=500)
    logo_uri: Optional[str] = None
    homepage_uri: Optional[str] = None
    terms_uri: Optional[str] = None
    privacy_uri: Optional[str] = None
    custom_css: Optional[str] = Field(None, max_length=20000)
    branding: Optional[ClientBranding] = None

    access_token_lifetime: int = Field(3600, ge=300, le=86400)  # 5 min to 24 hours
    refresh_token_lifetime: int = Field(2592000, ge=3600, le=7776000)  # 1 hour to 90 days

    @field_validator("grant_types")
    @classmethod
    def _reject_implicit_grant_on_create(cls, v: List[str]) -> List[str]:
        return _reject_implicit_grant(v)

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

    @model_validator(mode="after")
    def _redirect_uris_required_for_authorization_code(self) -> "OAuth2ClientCreate":
        """``redirect_uris`` is OPTIONAL in general (RFC 7591 §2, RFC 6749 §3.1.2.3)
        but REQUIRED when ``authorization_code`` is in ``grant_types`` — those
        clients need somewhere to redirect back to.
        """
        if "authorization_code" in self.grant_types and not self.redirect_uris:
            raise ValueError(
                "redirect_uris is required and must contain at least one entry "
                "when 'authorization_code' grant is enabled"
            )
        return self


class OAuth2ClientUpdate(BaseModel):
    """Schema for updating an OAuth2 client."""

    client_name: Optional[str] = Field(None, min_length=3, max_length=100)
    redirect_uris: Optional[List[str]] = None
    allowed_post_logout_redirect_uris: Optional[List[str]] = None
    allowed_scopes: Optional[List[str]] = None
    grant_types: Optional[List[str]] = None
    is_confidential: Optional[bool] = None

    require_pkce: Optional[bool] = None
    require_consent: Optional[bool] = None

    backchannel_logout_uri: Optional[str] = None
    frontchannel_logout_uri: Optional[str] = None

    description: Optional[str] = Field(None, max_length=500)
    logo_uri: Optional[str] = None
    homepage_uri: Optional[str] = None
    terms_uri: Optional[str] = None
    privacy_uri: Optional[str] = None
    custom_css: Optional[str] = Field(None, max_length=20000)

    is_active: Optional[bool] = None

    access_token_lifetime: Optional[int] = Field(None, ge=300, le=86400)
    refresh_token_lifetime: Optional[int] = Field(None, ge=3600, le=7776000)

    @field_validator("grant_types")
    @classmethod
    def _reject_implicit_grant_on_update(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        return _reject_implicit_grant(v)

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

    @model_validator(mode="after")
    def _redirect_uris_required_for_authorization_code(self) -> "OAuth2ClientUpdate":
        """If the resulting client would have ``authorization_code`` enabled,
        ``redirect_uris`` must not become empty. ``None`` (field not sent)
        is always allowed — the caller is not changing the URI list.
        """
        if (
            "authorization_code" in (self.grant_types or [])
            and self.redirect_uris is not None
            and len(self.redirect_uris) == 0
        ):
            raise ValueError(
                "redirect_uris must contain at least one entry when "
                "'authorization_code' grant is enabled"
            )
        return self


class OAuth2ClientResponse(BaseModel):
    """Public OAuth2 client response (without secret)."""

    client_id: str
    client_name: str
    redirect_uris: List[str]
    allowed_post_logout_redirect_uris: List[str]
    allowed_scopes: List[str]
    grant_types: List[str]

    is_confidential: bool
    require_pkce: bool
    require_consent: bool

    backchannel_logout_uri: Optional[str] = None
    frontchannel_logout_uri: Optional[str] = None

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
