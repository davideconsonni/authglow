"""OpenID Connect (OIDC) models."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr


class IDTokenClaims(BaseModel):
    """ID Token claims following OpenID Connect specification.

    Standard claims: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    """

    # Required claims
    iss: str  # Issuer identifier
    sub: str  # Subject identifier (user_id)
    aud: str  # Audience (client_id)
    exp: int  # Expiration time (unix timestamp)
    iat: int  # Issued at time (unix timestamp)

    # Optional claims
    auth_time: Optional[int] = None  # Time when authentication occurred
    nonce: Optional[str] = None  # String value used to associate a Client session
    acr: Optional[str] = None  # Authentication Context Class Reference
    amr: Optional[List[str]] = None  # Authentication Methods References
    azp: Optional[str] = None  # Authorized party (client_id if multiple audiences)

    class Config:
        json_encoders = {
            datetime: lambda v: int(v.timestamp()) if v else None
        }


class UserInfoResponse(BaseModel):
    """UserInfo endpoint response following OpenID Connect specification.

    Standard claims: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    """

    # Required
    sub: str  # Subject identifier (user_id)

    # Profile scope claims
    name: Optional[str] = None  # Full name
    given_name: Optional[str] = None  # First name
    family_name: Optional[str] = None  # Last name
    middle_name: Optional[str] = None
    nickname: Optional[str] = None
    preferred_username: Optional[str] = None
    profile: Optional[str] = None  # Profile page URL
    picture: Optional[str] = None  # Avatar URL
    website: Optional[str] = None
    gender: Optional[str] = None
    birthdate: Optional[str] = None  # YYYY-MM-DD format
    zoneinfo: Optional[str] = None  # Timezone
    locale: Optional[str] = None  # Locale/language
    updated_at: Optional[int] = None  # Unix timestamp

    # Email scope claims
    email: Optional[EmailStr] = None
    email_verified: Optional[bool] = None

    # Phone scope claims
    phone_number: Optional[str] = None
    phone_number_verified: Optional[bool] = None

    # Address scope claims
    address: Optional[dict] = None

    model_config = {
        "json_encoders": {
            datetime: lambda v: int(v.timestamp()) if v else None
        }
    }


class OpenIDConfiguration(BaseModel):
    """OpenID Connect Discovery document.

    Spec: https://openid.net/specs/openid-connect-discovery-1_0.html
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    registration_endpoint: Optional[str] = None
    scopes_supported: List[str]
    response_types_supported: List[str]
    response_modes_supported: List[str] = ["query", "fragment"]
    grant_types_supported: List[str]
    subject_types_supported: List[str] = ["public"]
    id_token_signing_alg_values_supported: List[str]
    token_endpoint_auth_methods_supported: List[str]
    claims_supported: List[str]
    code_challenge_methods_supported: List[str] = ["S256"]

    # Additional endpoints
    revocation_endpoint: Optional[str] = None
    introspection_endpoint: Optional[str] = None
    end_session_endpoint: Optional[str] = None


class JWKSResponse(BaseModel):
    """JSON Web Key Set response."""

    keys: List[dict]  # List of JWK objects


# Scope to claims mapping
SCOPE_TO_CLAIMS = {
    "openid": ["sub"],
    "profile": [
        "name", "given_name", "family_name", "middle_name", "nickname",
        "preferred_username", "profile", "picture", "website", "gender",
        "birthdate", "zoneinfo", "locale", "updated_at"
    ],
    "email": ["email", "email_verified"],
    "phone": ["phone_number", "phone_number_verified"],
    "address": ["address"]
}


# Standard OpenID Connect scopes
OIDC_SCOPES = {
    "openid": "OpenID Connect authentication",
    "profile": "Access to profile information",
    "email": "Access to email address",
    "phone": "Access to phone number",
    "address": "Access to postal address",
    "offline_access": "Access to refresh tokens"
}
