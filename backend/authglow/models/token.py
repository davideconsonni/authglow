"""Token data models."""

import secrets
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class Token(BaseModel):
    """OAuth2 token response."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None  # OpenID Connect ID token
    password_expired: bool = False


class TokenData(BaseModel):
    """Data stored in JWT token."""

    sub: str  # user id
    email: str
    scopes: List[str] = Field(default_factory=list)
    exp: datetime
    iat: datetime
    token_type: str = "access"  # access or refresh
    jti: Optional[str] = None  # JWT ID for revocation blacklist
    aud: Optional[str] = None  # audience — client_id for ID tokens, RP-initiated logout
    permissions: Optional[List[str]] = None  # RBAC permissions from assigned roles
    roles: Optional[List[str]] = None  # RBAC role names
    # T.3 / RFC 9449 / RFC 7800: ``cnf`` confirmation claim binds the
    # token to a specific key. Present for DPoP-bound tokens
    # (e.g. ``{"jkt": "<thumbprint>"}``). ``None`` for legacy bearer.
    cnf: Optional[dict] = None


class AuthorizationCode(BaseModel):
    """OAuth2 authorization code (stored temporarily)."""

    code: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    client_id: str
    user_id: str
    redirect_uri: str
    scope: str
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    used: bool = False

    # PKCE support
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None

    # OIDC support
    nonce: Optional[str] = None
    state: Optional[str] = None

    # acr/amr — OIDC authentication context
    acr: Optional[str] = None
    amr: Optional[List[str]] = None


class DeviceAuthorization(BaseModel):
    """OAuth 2.0 Device Authorization Grant (RFC 8628).

    Stored temporarily while the user completes the
    browser-based approval flow on a secondary device.
    """

    device_code: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    user_code: str  # 8-char human-friendly code, set by the service
    client_id: str
    scope: str
    verification_uri: str
    expires_at: datetime
    interval: int = 5  # minimum polling interval in seconds
    status: str = "pending"  # pending | authorized | denied | expired
    user_id: Optional[str] = None
    authorized_at: Optional[datetime] = None
    last_poll_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)


class OAuth2AuthorizationRequest(BaseModel):
    """OAuth2 authorization request parameters."""

    response_type: str = "code"
    client_id: str
    redirect_uri: str
    scope: Optional[str] = "read"
    state: Optional[str] = None


class OAuth2TokenRequest(BaseModel):
    """OAuth2 token request parameters."""

    grant_type: str
    code: Optional[str] = None  # For authorization_code
    redirect_uri: Optional[str] = None  # For authorization_code
    client_id: Optional[str] = None  # For client_credentials
    client_secret: Optional[str] = None  # For client_credentials
    refresh_token: Optional[str] = None  # For refresh_token
    scope: Optional[str] = None
