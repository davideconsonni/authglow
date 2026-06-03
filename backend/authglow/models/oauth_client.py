"""OAuth2 Client models."""

from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


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
    custom_css: Optional[str] = None

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

    class Config:
        json_schema_extra = {
            "example": {
                "client_name": "My Application",
                "redirect_uris": ["https://myapp.com/callback"],
                "allowed_scopes": ["read", "write"],
                "description": "My awesome application",
            }
        }


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

    access_token_lifetime: int = Field(3600, ge=300, le=86400)  # 5 min to 24 hours
    refresh_token_lifetime: int = Field(2592000, ge=3600, le=7776000)  # 1 hour to 90 days


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
    custom_css: Optional[str] = None

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
