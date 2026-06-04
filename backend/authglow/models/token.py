"""Token data models."""

import secrets
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class Token(BaseModel):
    """OAuth2 token response."""

    access_token: str
    token_type: str = "bearer"
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
