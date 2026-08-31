"""OAuth2 Client models."""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional
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

# Allowed values for ``token_endpoint_auth_method`` (RFC 7591 §2 + FAPI 2.0).
# ``client_secret_jwt`` and ``private_key_jwt`` are the FAPI-aligned
# alternatives to ``client_secret_basic``/``client_secret_post``
# (conformance workstream T.2).
_ALLOWED_AUTH_METHODS = (
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "none",
)
_AUTH_METHOD_MESSAGE = (
    "token_endpoint_auth_method must be one of "
    "client_secret_basic, client_secret_post, client_secret_jwt, "
    "private_key_jwt, none"
)

# Minimal JWK validation: must be a dict with ``kty`` present and ``use``/``alg``
# consistent with asymmetric signature use. Full JWKS spec validation is out of
# scope for this module — the ``services.client_jwt_auth`` module performs
# the cryptographic verification.
_ALLOWED_JWK_KTY = ("RSA", "EC", "OKP")


def _validate_token_endpoint_auth_method(v: Optional[str]) -> Optional[str]:
    """Shared whitelist check for ``token_endpoint_auth_method``."""
    if v is None:
        return v
    if v not in _ALLOWED_AUTH_METHODS:
        raise ValueError(_AUTH_METHOD_MESSAGE)
    return v


def _validate_public_jwk(v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Light JWK shape check. The cryptographic verification happens later."""
    if v is None:
        return v
    if not isinstance(v, dict):
        raise ValueError("public_jwk must be a dict")
    kty = v.get("kty")
    if kty not in _ALLOWED_JWK_KTY:
        raise ValueError(f"public_jwk.kty must be one of {_ALLOWED_JWK_KTY}")
    if kty == "RSA" and "n" not in v and "e" not in v:
        raise ValueError("public_jwk for RSA must contain 'n' and 'e'")
    if kty == "EC" and "crv" not in v and "x" not in v:
        raise ValueError("public_jwk for EC must contain 'crv' and 'x'")
    if kty == "OKP" and "x" not in v:
        raise ValueError("public_jwk for OKP must contain 'x'")
    if "use" in v and v["use"] not in ("sig", "enc"):
        raise ValueError("public_jwk.use must be 'sig' or 'enc'")
    return v


def _reject_implicit_grant(v: List[str]) -> List[str]:
    """Reject the ``implicit`` grant type per OAuth 2.0 Security BCP.

    Shared validator body for ``OAuth2Client`` / ``OAuth2ClientCreate`` /
    ``OAuth2ClientUpdate`` so the error message stays consistent.
    """
    if "implicit" in v:
        raise ValueError(_GRANT_TYPES_REJECTED_MESSAGE)
    return v


class BrandingVariant(BaseModel):
    """Theme-specific overrides for client branding (Auth0-style light/dark).

    Every field is optional and inherits from the flat base
    ``ClientBranding`` when unset. Font and logo are intentionally
    shared across both modes (only colors differ per mode).
    """

    primary_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    surface_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    text_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    border_radius: Optional[str] = Field(None, pattern=r"^[0-9.]+(px|em|rem|%)$")


class ClientBranding(BaseModel):
    """Structured branding for the OAuth2 consent page.

    Replaces the former raw ``custom_css`` field with a typed object
    that is safe to render as CSS custom properties — only pre-validated
    values reach the ``<style>`` tag (VAPT-037 fix).

    The flat fields act as the base; optional ``light``/``dark`` variants
    override them per theme mode.
    """

    primary_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    surface_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    text_color: Optional[str] = Field(None, pattern=r"^#[0-9a-fA-F]{6}$")
    font_family: Optional[str] = Field(None, max_length=200)
    border_radius: Optional[str] = Field(None, pattern=r"^[0-9.]+(px|em|rem|%)$")
    logo_url: Optional[str] = None
    light: Optional[BrandingVariant] = None
    dark: Optional[BrandingVariant] = None

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

    # token_endpoint_auth_method (RFC 7591 §2, FAPI 2.0). Defaults to
    # ``client_secret_basic`` for backward compatibility with clients
    # registered before conformance workstream T.2.
    token_endpoint_auth_method: str = "client_secret_basic"
    # Fernet-encrypted symmetric key used to verify HS256 client_assertion
    # JWTs when ``token_endpoint_auth_method == "client_secret_jwt"``.
    # Stored as a string with the ``agcj1:`` prefix from
    # ``core.crypto.encrypt_client_jwt_key``. Never sent over the wire.
    client_secret_jwt_key: Optional[str] = None
    # Public JWK used to verify RS256 client_assertion JWTs when
    # ``token_endpoint_auth_method == "private_key_jwt"``. Embedded to
    # avoid the round-trip of a JWKS URI fetch.
    public_jwk: Optional[Dict[str, Any]] = None
    # T.3: opt-in DPoP-bound tokens (RFC 9449 / FAPI 2.0 §5.2.2). When
    # ``True``, the token endpoint requires a DPoP proof JWT on every
    # request and the access token is issued with a ``cnf`` claim
    # binding it to the client's public key. Default ``False`` for
    # backward compatibility.
    dpop_bound: bool = False

    @field_validator("grant_types")
    @classmethod
    def _reject_implicit_grant_on_client(cls, v: List[str]) -> List[str]:
        return _reject_implicit_grant(v)

    @field_validator("token_endpoint_auth_method")
    @classmethod
    def _validate_token_endpoint_auth_method_on_client(cls, v: str) -> str:
        result = _validate_token_endpoint_auth_method(v)
        assert result is not None  # type narrowing for mypy
        return result

    @field_validator("public_jwk")
    @classmethod
    def _validate_public_jwk_on_client(
        cls, v: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        return _validate_public_jwk(v)

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

    # See ``OAuth2Client`` for the semantics. Optional on the create payload
    # because ``is_confidential`` is still the primary signal — admins can
    # leave this at the default and rely on the legacy secret-only flow.
    token_endpoint_auth_method: Optional[str] = "client_secret_basic"
    # Public JWK is optional; only meaningful when
    # ``token_endpoint_auth_method == "private_key_jwt"``. The server-side
    # ``client_secret_jwt_key`` is server-generated on creation and never
    # accepted from the wire.
    public_jwk: Optional[Dict[str, Any]] = None
    # T.3: opt-in DPoP binding. When ``True`` the token endpoint
    # requires a DPoP proof JWT on every request.
    dpop_bound: bool = False

    @field_validator("grant_types")
    @classmethod
    def _reject_implicit_grant_on_create(cls, v: List[str]) -> List[str]:
        return _reject_implicit_grant(v)

    @field_validator("token_endpoint_auth_method")
    @classmethod
    def _validate_token_endpoint_auth_method_on_create(cls, v: Optional[str]) -> Optional[str]:
        return _validate_token_endpoint_auth_method(v)

    @field_validator("public_jwk")
    @classmethod
    def _validate_public_jwk_on_create(
        cls, v: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        return _validate_public_jwk(v)

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

    # T.2: allow admins to switch a client between auth methods.
    # ``client_secret_jwt_key`` is server-managed and never accepted on
    # the wire (use the rotate-JWT-key admin flow for that).
    token_endpoint_auth_method: Optional[str] = None
    public_jwk: Optional[Dict[str, Any]] = None
    # T.3: opt-in DPoP binding. Admins can flip it on/off after
    # creation. Toggling off does NOT invalidate already-issued
    # tokens; they remain valid until expiry.
    dpop_bound: Optional[bool] = None
    # Optional explicit ``None`` to clear the public JWK. Pydantic does
    # not distinguish ``None`` from "field not sent" for ``Optional``;
    # admins can clear the JWK via the admin endpoint with
    # ``public_jwk = {}`` (validated to fail) — instead, the admin route
    # uses a separate "clear_jwk" boolean. This pattern is consistent
    # with the rest of the update schema.

    @field_validator("grant_types")
    @classmethod
    def _reject_implicit_grant_on_update(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        return _reject_implicit_grant(v)

    @field_validator("token_endpoint_auth_method")
    @classmethod
    def _validate_token_endpoint_auth_method_on_update(cls, v: Optional[str]) -> Optional[str]:
        return _validate_token_endpoint_auth_method(v)

    @field_validator("public_jwk")
    @classmethod
    def _validate_public_jwk_on_update(
        cls, v: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        return _validate_public_jwk(v)

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

    # T.2: advertise the configured auth method and whether a server-side
    # JWT key is present. The encrypted ``client_secret_jwt_key`` is
    # never returned — the boolean is the only signal the admin UI needs.
    token_endpoint_auth_method: str = "client_secret_basic"
    has_client_secret_jwt_key: bool = False
    public_jwk: Optional[Dict[str, Any]] = None
    # T.3: DPoP binding flag.
    dpop_bound: bool = False


def _client_response_from_model(client: "OAuth2Client") -> "OAuth2ClientResponse":
    """Build an ``OAuth2ClientResponse`` from a stored ``OAuth2Client``.

    Centralised here (rather than re-implemented at every call site) so
    the secret-bearing fields (``client_secret``, ``client_secret_jwt_key``)
    are never accidentally surfaced.
    """
    return OAuth2ClientResponse(
        client_id=client.client_id,
        client_name=client.client_name,
        redirect_uris=client.redirect_uris,
        allowed_post_logout_redirect_uris=client.allowed_post_logout_redirect_uris,
        allowed_scopes=client.allowed_scopes,
        grant_types=client.grant_types,
        is_confidential=client.is_confidential,
        require_pkce=client.require_pkce,
        require_consent=client.require_consent,
        backchannel_logout_uri=client.backchannel_logout_uri,
        frontchannel_logout_uri=client.frontchannel_logout_uri,
        description=client.description,
        logo_uri=client.logo_uri,
        homepage_uri=client.homepage_uri,
        terms_uri=client.terms_uri,
        privacy_uri=client.privacy_uri,
        branding=client.branding,
        is_active=client.is_active,
        created_at=client.created_at,
        last_used_at=client.last_used_at,
        access_token_lifetime=client.access_token_lifetime,
        refresh_token_lifetime=client.refresh_token_lifetime,
        token_endpoint_auth_method=client.token_endpoint_auth_method,
        has_client_secret_jwt_key=bool(client.client_secret_jwt_key),
        public_jwk=client.public_jwk,
        dpop_bound=client.dpop_bound,
    )


class OAuth2ClientWithSecret(OAuth2ClientResponse):
    """OAuth2 client response with plaintext secret (only shown once at creation)."""

    client_secret: str  # Plaintext, only shown at creation
    # T.2: plaintext JWT key for ``client_secret_jwt`` clients. Shown
    # exactly once at creation (the admin must hand it to the client
    # operator). ``None`` for clients that do not use the JWT method
    # or for any read-back operation.
    client_secret_jwt_key: Optional[str] = None


class OAuth2ClientSecretRotation(BaseModel):
    """Response for client secret rotation."""

    client_id: str
    new_client_secret: str  # Plaintext
    expires_at: Optional[datetime] = None
