"""OpenID Connect API endpoints."""

import asyncio
import base64
import hashlib
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator

from authglow.core.config import get_settings
from authglow.core.jwt_singleton import get_jwt_service
from authglow.core.rate_limit import limiter
from authglow.models.keystore import KeyPairMeta, KeyringInfo
from authglow.models.oauth_client import (
    OAuth2Client,
    OAuth2ClientUpdate,
    _client_response_from_model,
    _validate_public_jwk,
    _validate_token_endpoint_auth_method,
)
from authglow.models.oidc import IDTokenClaims, JWKSResponse, OpenIDConfiguration, UserInfoResponse
from authglow.repositories.dependencies import get_keystore_repository
from authglow.services.audit import AuditService
from authglow.services.oauth_client import OAuth2ClientStorage
from authglow.services.oidc import OIDCService

router = APIRouter(tags=["OpenID Connect"])
security = HTTPBearer()


@router.get("/.well-known/openid-configuration", response_model=OpenIDConfiguration)
@limiter.limit("60/minute")
async def openid_configuration(request: Request, response: Response):
    """OpenID Connect Discovery endpoint.

    Returns metadata about the OpenID Provider's configuration.
    Spec: https://openid.net/specs/openid-connect-discovery-1_0.html

    The response is publicly cacheable for one hour (Tier 1.6 of
    PERFORMANCE_OPTIMIZATION_PLAN.md): the discovery document only
    changes on operator-driven configuration changes, not on
    per-request activity.  Public intermediaries (CDNs, reverse
    proxies) can serve the cached document to many clients.
    """
    response.headers["Cache-Control"] = "public, max-age=3600"
    settings = get_settings()
    base_url = settings.issuer

    scopes_supported = (
        [s.strip() for s in settings.oidc_scopes_supported.split(",") if s.strip()]
        if settings.oidc_scopes_supported
        else ["openid", "profile", "email", "phone", "address", "offline_access"]
    )
    response_types_supported = (
        [s.strip() for s in settings.oidc_response_types_supported.split(",") if s.strip()]
        if settings.oidc_response_types_supported
        else ["code"]
    )
    grant_types_supported = (
        [s.strip() for s in settings.oidc_grant_types_supported.split(",") if s.strip()]
        if settings.oidc_grant_types_supported
        else [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
        ]
    )
    claims_supported = (
        [s.strip() for s in settings.oidc_claims_supported.split(",") if s.strip()]
        if settings.oidc_claims_supported
        else [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "sid",
            "name",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "email",
            "email_verified",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "phone_number",
            "phone_number_verified",
            "address",
            "updated_at",
        ]
    )

    return OpenIDConfiguration(
        issuer=settings.issuer,
        authorization_endpoint=f"{base_url}/oauth2/authorize",
        token_endpoint=f"{base_url}/oauth2/token",
        userinfo_endpoint=f"{base_url}/oauth2/userinfo",
        jwks_uri=f"{base_url}/.well-known/jwks.json",
        registration_endpoint=f"{base_url}/oauth2/register",
        scopes_supported=scopes_supported,
        response_types_supported=response_types_supported,
        response_modes_supported=["query", "fragment", "form_post"],
        grant_types_supported=grant_types_supported,
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=[settings.jwt_algorithm],
        # T.2: advertise ``client_secret_jwt`` (HS256) and
        # ``private_key_jwt`` (RS256) per FAPI 2.0 / OpenID Connect Core
        # §9. Clients can opt into either at registration time.
        token_endpoint_auth_methods_supported=[
            "client_secret_basic",
            "client_secret_post",
            "client_secret_jwt",
            "private_key_jwt",
            "none",
        ],
        claims_supported=claims_supported,
        code_challenge_methods_supported=["S256"],
        device_authorization_endpoint=f"{base_url}/oauth2/device/authorize",
        revocation_endpoint=f"{base_url}/oauth2/revoke",
        introspection_endpoint=f"{base_url}/oauth2/introspect",
        end_session_endpoint=f"{base_url}/oauth2/logout",
        service_documentation=settings.oidc_service_documentation or None,
        op_policy_uri=settings.oidc_op_policy_uri or None,
        op_tos_uri=settings.oidc_op_tos_uri or None,
    )


@router.get("/.well-known/jwks.json", response_model=JWKSResponse)
@limiter.limit("60/minute")
async def jwks(request: Request, response: Response):
    """JSON Web Key Set (JWKS) endpoint.

    Returns all active and verifying public keys in JWK format.
    Revoked keys are excluded.
    Spec: https://tools.ietf.org/html/rfc7517

    The response is publicly cacheable for five minutes and
    carries an ETag derived from the keyring ``_version`` field
    (Tier 1.6 of PERFORMANCE_OPTIMIZATION_PLAN.md).  Clients
    (RPs) that re-fetch the JWKS within the cache window get
    a ``304 Not Modified`` from intermediaries, avoiding the
    cost of re-reading every public key file.
    """
    response.headers["Cache-Control"] = "public, max-age=300"
    settings = get_settings()
    jwt_service = await get_jwt_service()
    keyring_info = jwt_service.get_keyring_info()

    # ETag: any change to the keyring (rotation, revocation) bumps
    # ``_version``; combine with the active kid so the ETag is
    # also invalidated when a new active key is promoted.
    keyring_version = keyring_info.get("_version", 0)
    etag_source = f"{keyring_version}:{keyring_info['active_kid']}"
    response.headers["ETag"] = f'W/"{hashlib.sha256(etag_source.encode()).hexdigest()[:16]}"'

    # Honour conditional GET: if the client's If-None-Match matches
    # the current ETag, return 304 without re-serializing the body.
    if_none_match = request.headers.get("if-none-match")
    if if_none_match and if_none_match == response.headers["ETag"]:
        return Response(status_code=304, headers=dict(response.headers))

    def int_to_base64(n):
        return (
            base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
            .rstrip(b"=")
            .decode("utf-8")
        )

    # Tier 1.8: route the per-kid PEM read through the async
    # repository (existence check + read both via fsspec on a
    # background thread) and parse the RSA key in ``asyncio.to_thread``
    # so the CPU-bound ``load_pem_public_key`` call does not block
    # the event loop. The previous implementation used
    # ``os.path.exists`` + ``open(..., "rb")`` which blocked the
    # loop for the full fsspec I/O latency on every kid.
    keystore = get_keystore_repository(settings=settings)
    keys = []
    for kid, meta in keyring_info["keys"].items():
        kid_status = meta.get("status", "")
        if kid_status not in ("active", "verifying"):
            continue

        pub_pem = await keystore.read_public_key(kid)
        if pub_pem is None:
            continue

        try:
            public_key = await asyncio.to_thread(
                serialization.load_pem_public_key, pub_pem, backend=default_backend()
            )
        except Exception:
            continue

        if not isinstance(public_key, RSAPublicKey):
            continue

        public_numbers = public_key.public_numbers()
        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": settings.jwt_algorithm,
            "kid": kid,
            "n": int_to_base64(public_numbers.n),
            "e": int_to_base64(public_numbers.e),
        }
        keys.append(jwk)

    if not keys:
        raise HTTPException(status_code=500, detail="No public keys available.")

    return JWKSResponse(keys=keys)


@router.get("/oauth2/jwks/status", response_model=KeyringInfo)
@limiter.limit("60/minute")
async def jwks_status(request: Request):
    """JWKS Status endpoint.

    Returns the full keyring with status for each kid,
    including revoked keys. Unlike ``/.well-known/jwks.json``
    which only returns active and verifying keys in JWK format,
    this endpoint exposes status metadata for all keys so that
    clients can detect when a cached ``kid`` has been revoked.
    """
    jwt_service = await get_jwt_service()
    keyring_info = jwt_service.get_keyring_info()

    keys_meta = []
    for kid, meta in keyring_info["keys"].items():
        keys_meta.append(
            KeyPairMeta(
                kid=kid,
                created_at=meta.get("created_at", ""),
                status=meta.get("status", ""),
                algorithm=meta.get("algorithm", "RS256"),
                key_size=meta.get("key_size", 2048),
                retired_at=meta.get("retired_at"),
                revoked_at=meta.get("revoked_at"),
            )
        )

    return KeyringInfo(active_kid=keyring_info["active_kid"], keys=keys_meta)


@router.get("/oauth2/userinfo", response_model=UserInfoResponse)
@limiter.limit("120/minute")
async def userinfo(
    request: Request,
    response: Response,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """OpenID Connect UserInfo endpoint.

    Returns claims about the authenticated user.
    Spec: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

    Requires:
        - Bearer token in Authorization header
        - Token must have been issued with 'openid' scope

    Returns:
        User information based on the scopes in the access token

    Tier 1.6 of PERFORMANCE_OPTIMIZATION_PLAN.md: the response is
    explicitly non-cacheable (``private, max-age=0, no-cache``).
    UserInfo is personalised and the response MUST NOT leak
    across users via shared caches.
    """
    response.headers["Cache-Control"] = "private, max-age=0, no-cache"
    jwt_service = await get_jwt_service()
    oidc_service = OIDCService()

    # Decode and validate access token
    token = credentials.credentials
    token_data = jwt_service.decode_token(token)

    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # OIDC Core §5.3: access tokens presented at the UserInfo endpoint must
    # be aud-bound. We don't have the originating client_id in scope (the
    # bearer token is the only credential), so we assert the aud claim is
    # present and signed. The token's own aud is the trusted source of the
    # authorized party.
    if not token_data.aud:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token is not bound to a client audience",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if token has 'openid' scope
    if "openid" not in token_data.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Token does not have 'openid' scope"
        )

    # Get user info based on scopes
    user_info = await oidc_service.get_user_info(token_data.sub, token_data.scopes)

    if not user_info:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Return user info excluding None values
    result = user_info.model_dump(exclude_none=True)
    if token_data.permissions:
        result["permissions"] = token_data.permissions
    if token_data.roles:
        result["roles"] = token_data.roles
    return result


@router.get("/oauth2/logout")
@limiter.limit("30/minute")
async def logout_get(
    request: Request,
    id_token_hint: str | None = None,
    post_logout_redirect_uri: str | None = None,
    state: str | None = None,
):
    """OpenID Connect RP-Initiated Logout (GET method).

    Spec: https://openid.net/specs/openid-connect-rpinitiated-1_0.html

    Query Parameters:
        - id_token_hint: ID Token previously issued to the client
        - post_logout_redirect_uri: URL to redirect after logout
        - state: Opaque value to maintain state between request and callback

    Every ``post_logout_redirect_uri`` is validated against the client's
    ``allowed_post_logout_redirect_uris`` (OIDC RP-Initiated Logout §4).
    The ``id_token_hint`` is **required** when a redirect is requested —
    without it the AS cannot identify the client and must refuse.
    """
    from fastapi.responses import RedirectResponse

    from authglow.services.audit import AuditService
    from authglow.services.oauth2 import OAuth2Service

    jwt_service = await get_jwt_service()
    oauth2_service = OAuth2Service()
    audit_service = AuditService()

    # If a redirect is requested, the id_token_hint is mandatory so the AS
    # can identify the client and check allowed_post_logout_redirect_uris.
    if post_logout_redirect_uri:
        if not id_token_hint:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="id_token_hint is required when post_logout_redirect_uri is provided.",
            )

        unverified_aud: str | None = None
        try:
            unverified_payload = jwt.decode(
                id_token_hint,
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_exp": False,
                },
            )
            raw_aud = unverified_payload.get("aud")
            if isinstance(raw_aud, str):
                unverified_aud = raw_aud
        except jwt.PyJWTError:
            unverified_aud = None

        token_data: IDTokenClaims | None = None
        if unverified_aud is not None:
            token_data = jwt_service.decode_id_token(id_token_hint, expected_aud=unverified_aud)

        if token_data is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid id_token_hint.",
            )

        client = await oauth2_service.client_storage.get_client(token_data.aud)
        if client is None or not client.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Client identified by id_token_hint not found or inactive.",
            )

        if post_logout_redirect_uri not in client.allowed_post_logout_redirect_uris:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="post_logout_redirect_uri is not allowed for this client.",
            )

        await audit_service.log_event(
            event_type="oidc_logout",
            user_id=token_data.sub,
            metadata={
                "client_id": token_data.aud,
                "has_redirect": True,
            },
        )

        # --- Front-Channel Logout (OIDC Front-Channel Logout 1.0) ---
        sid = token_data.sid or ""
        all_clients = await oauth2_service.client_storage.list_clients(limit=200, active_only=True)
        frontchannel_clients = [c for c in all_clients if c.frontchannel_logout_uri]

        if frontchannel_clients:
            from fastapi.responses import HTMLResponse

            issuer = get_settings().issuer
            iframes = "\n".join(
                f'<iframe src="{c.frontchannel_logout_uri}?iss={issuer}&sid={sid}" '
                f'style="display:none"></iframe>'
                for c in frontchannel_clients
            )
            redirect_url = post_logout_redirect_uri
            if state:
                from urllib.parse import urlencode as _enc

                sep = "&" if "?" in redirect_url else "?"
                redirect_url = f"{redirect_url}{sep}{_enc({'state': state})}"
            html = (
                "<!DOCTYPE html>\n<html><head><title>Logout</title></head><body>\n"
                f"{iframes}\n"
                '<script>setTimeout(function(){{location="{redirect_url}";}},2000)</script>\n'
                "</body></html>"
            ).replace("{redirect_url}", redirect_url)
            return HTMLResponse(content=html)

        from urllib.parse import urlencode

        redirect_url = post_logout_redirect_uri
        if state:
            separator = "&" if "?" in redirect_url else "?"
            redirect_url = f"{redirect_url}{separator}{urlencode({'state': state})}"

        return RedirectResponse(url=redirect_url, status_code=303)

    # No redirect URI — just log a hint audit if id_token_hint was provided.
    if id_token_hint:
        try:
            unverified_payload = jwt.decode(
                id_token_hint,
                options={
                    "verify_signature": False,
                    "verify_aud": False,
                    "verify_exp": False,
                },
            )
        except jwt.PyJWTError:
            return {
                "message": "Logged out successfully",
                "note": "Please delete access and refresh tokens on the client side",
            }

        raw_aud = unverified_payload.get("aud")
        hint_aud: str | None = raw_aud if isinstance(raw_aud, str) else None

        hint_token_data: IDTokenClaims | None = None
        if hint_aud is not None:
            hint_token_data = jwt_service.decode_id_token(id_token_hint, expected_aud=hint_aud)

        if hint_token_data is not None:
            await audit_service.log_event(
                event_type="oidc_logout",
                user_id=hint_token_data.sub,
                metadata={
                    "client_id": hint_token_data.aud,
                    "has_redirect": False,
                },
            )

    return {
        "message": "Logged out successfully",
        "note": "Please delete access and refresh tokens on the client side",
    }


@router.post("/oauth2/logout")
@limiter.limit("30/minute")
async def logout_post(
    request: Request, credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """OpenID Connect End Session endpoint (logout) - POST method.

    Spec: https://openid.net/specs/openid-connect-session-1_0.html#RPLogout

    Note: Since we're stateless, logout is client-side (delete tokens).
    This endpoint can be used for audit logging.
    """
    from authglow.services.audit import AuditService

    jwt_service = await get_jwt_service()
    audit_service = AuditService()

    # Decode token for audit logging
    token = credentials.credentials
    token_data = jwt_service.decode_token(token)

    if token_data:
        await audit_service.log_event(
            event_type="oidc_logout_post",
            user_id=token_data.sub,
            metadata={"token_type": token_data.token_type},
        )

    return {
        "message": "Logged out successfully",
        "note": "Please delete access and refresh tokens on the client side",
    }


# --- Dynamic Client Registration (RFC 7591) ---


class ClientRegistrationRequest(BaseModel):
    """RFC 7591 Dynamic Client Registration request.

    https://datatracker.ietf.org/doc/html/rfc7591
    """

    redirect_uris: List[str] = Field(..., min_length=1)
    client_name: Optional[str] = Field(None, max_length=100)
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    tos_uri: Optional[str] = None
    policy_uri: Optional[str] = None
    contacts: Optional[List[str]] = None
    scope: Optional[str] = None
    grant_types: Optional[List[str]] = None
    response_types: Optional[List[str]] = None
    token_endpoint_auth_method: Optional[str] = "client_secret_basic"
    software_statement: Optional[str] = None
    # T.2: public JWK for ``private_key_jwt`` clients. The server
    # validates shape (kty, n/e or crv/x) — full cryptographic
    # verification happens at the first ``client_assertion`` request.
    public_jwk: Optional[Dict[str, Any]] = None

    @field_validator("token_endpoint_auth_method")
    @classmethod
    def _validate_dcr_auth_method(cls, v: Optional[str]) -> Optional[str]:
        return _validate_token_endpoint_auth_method(v)

    @field_validator("public_jwk")
    @classmethod
    def _validate_dcr_public_jwk(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        return _validate_public_jwk(v)


def _validate_redirect_uri(uri: str) -> None:
    """Validate a redirect URI per RFC 7591 / OAuth2 best practices.

    Allows https always and http only for localhost loopback (RFC 8252).
    """
    parsed = urlparse(uri)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()

    if scheme == "https":
        return
    if scheme == "http" and host in ("localhost", "127.0.0.1", "::1"):
        return
    if scheme in ("http", "https"):
        raise ValueError(
            f"redirect_uri '{uri}' must use https (http is only allowed for localhost)"
        )
    raise ValueError(f"redirect_uri '{uri}' has invalid scheme '{scheme}'")


@router.post("/oauth2/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("60/minute")
async def register_oauth_client(
    request: Request,
    payload: ClientRegistrationRequest,
    storage: OAuth2ClientStorage = Depends(lambda: OAuth2ClientStorage()),
    audit_service: AuditService = Depends(lambda: AuditService()),
):
    """OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591).

    Creates a new OAuth2 client dynamically. The plaintext client_secret is
    returned ONLY in this response and cannot be retrieved later.
    """
    for uri in payload.redirect_uris:
        try:
            _validate_redirect_uri(uri)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            )

    # --- DCR hardening (P.1 + P.2 + P.3) ---

    # P.1: token_endpoint_auth_method=none cannot be used with grants that
    # always require client authentication at the token endpoint.
    # authorization_code + PKCE is fine for public clients.
    if payload.token_endpoint_auth_method == "none":
        grants = payload.grant_types or ["authorization_code", "refresh_token"]
        if "client_credentials" in grants:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="token_endpoint_auth_method='none' cannot be used "
                "with 'client_credentials' grant_type. "
                "Use 'client_secret_basic' or another confidential auth method.",
            )

    # P.2: metadata URIs must be https (or http localhost).
    for field_name in ("client_uri", "logo_uri", "tos_uri", "policy_uri"):
        metadata_uri: Optional[str] = getattr(payload, field_name, None)
        if metadata_uri:
            try:
                _validate_redirect_uri(metadata_uri)
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"{field_name}: {exc}",
                )

    # P.3: software_statement must be a valid JWT if provided.
    if payload.software_statement:
        try:
            jwt.decode(
                payload.software_statement,
                options={"verify_signature": False},
            )
        except jwt.PyJWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"software_statement is not a valid JWT: {exc}",
            )

    allowed_grant_types = (
        payload.grant_types
        if payload.grant_types is not None
        else ["authorization_code", "refresh_token"]
    )
    invalid_grants = [
        g
        for g in allowed_grant_types
        if g
        not in (
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
        )
    ]
    if invalid_grants:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported grant_type(s): {invalid_grants}",
        )

    allowed_scopes = payload.scope.split() if payload.scope else ["read"]

    is_confidential = payload.token_endpoint_auth_method != "none"

    plaintext_secret = storage.generate_client_secret()

    # T.2: if the DCR request selects ``client_secret_jwt``, mint a
    # fresh symmetric key and return it in plaintext exactly once,
    # matching the ``client_secret`` pattern. The encrypted copy is
    # persisted in ``client.client_secret_jwt_key`` (Fernet with the
    # server's ``SECRET_KEY``); the plaintext is never stored.
    from authglow.services.client_jwt_auth import (
        encrypt_client_jwt_key_value,
        generate_client_jwt_symmetric_key,
    )

    plaintext_jwt_key: Optional[str] = None
    if payload.token_endpoint_auth_method == "client_secret_jwt":
        plaintext_jwt_key = generate_client_jwt_symmetric_key()

    # T.2: ``public_jwk`` is only meaningful for ``private_key_jwt``.
    # We do not reject mismatched combinations at DCR time — admins
    # can keep the JWK and switch the method later, and clients can
    # experiment. The token endpoint enforces the method/key
    # consistency at first use.
    client = OAuth2Client(
        client_name=payload.client_name or "Dynamically Registered Client",
        client_secret=plaintext_secret,
        redirect_uris=payload.redirect_uris,
        allowed_scopes=allowed_scopes,
        grant_types=allowed_grant_types,
        is_confidential=is_confidential,
        require_pkce=True,
        require_consent=True,
        logo_uri=payload.logo_uri,
        terms_uri=payload.tos_uri,
        privacy_uri=payload.policy_uri,
        description=None,
        homepage_uri=payload.client_uri,
        token_endpoint_auth_method=payload.token_endpoint_auth_method or "client_secret_basic",
        public_jwk=payload.public_jwk,
        client_secret_jwt_key=(
            encrypt_client_jwt_key_value(plaintext_jwt_key)
            if plaintext_jwt_key is not None
            else None
        ),
    )

    await storage.create_client(client, plaintext_secret)

    issued_at = int(client.created_at.timestamp())

    try:
        await audit_service.log_event(
            event_type="oauth_client_dynamic_registration",
            user_id=None,
            email=None,
            metadata={
                "client_id": client.client_id,
                "client_name": client.client_name,
                "grant_types": allowed_grant_types,
                "token_endpoint_auth_method": client.token_endpoint_auth_method,
            },
            ip_address=request.client.host if request.client else None,
        )
    except Exception:
        pass

    return {
        "client_id": client.client_id,
        "client_id_issued_at": issued_at,
        "client_secret": plaintext_secret,
        "client_secret_expires_at": 0,
        "redirect_uris": client.redirect_uris,
        "client_name": client.client_name,
        "client_uri": payload.client_uri,
        "logo_uri": payload.logo_uri,
        "tos_uri": payload.tos_uri,
        "policy_uri": payload.policy_uri,
        "contacts": payload.contacts or [],
        "scope": " ".join(allowed_scopes),
        "grant_types": client.grant_types,
        "response_types": payload.response_types or ["code"],
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        # T.2: only populated for ``client_secret_jwt`` clients. The
        # server never returns the encrypted blob — only the
        # plaintext (single-use, like ``client_secret``).
        "client_secret_jwt_key": plaintext_jwt_key,
        # T.2: echo the public JWK back so the client operator can
        # confirm what was stored.
        "public_jwk": client.public_jwk,
    }


# --- RFC 7592: DCR Management ---


async def _authenticate_client_for_dcr(
    request: Request,
    storage: OAuth2ClientStorage,
    client_id: str,
) -> OAuth2Client:
    """Authenticate the client on a DCR Management endpoint.

    Supports two transports:

    1. **HTTP Basic** (``client_secret_basic``) — the legacy
       flow from RFC 7592.
    2. **Bearer JWT** (``client_secret_jwt`` / ``private_key_jwt``)
       — a T.2 extension. The client signs a JWT asserting its
       identity and sends it as ``Authorization: Bearer <jwt>``.
       The ``sub`` claim is used to identify the client; the
       request ``client_id`` is cross-checked for symmetry.

    The first matching transport wins. If neither succeeds, a
    401 is raised with a ``WWW-Authenticate`` header advertising
    the supported methods.
    """
    from authglow.api.auth import _extract_basic_auth, _extract_bearer_auth

    # --- HTTP Basic path ---
    basic_id, basic_secret = _extract_basic_auth(request)
    if basic_id is not None or basic_secret is not None:
        if not basic_id or not basic_secret:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed HTTP Basic credentials.",
                headers={"WWW-Authenticate": ('Basic realm="OAuth2", Bearer realm="OAuth2"')},
            )
        if basic_id != client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=("Authenticated client does not match the requested client_id."),
            )
        client = await storage.get_client(client_id)
        if not client or not client.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Client not found or inactive.",
            )
        from authglow.services.password import verify_password_async

        if not await verify_password_async(basic_secret, client.client_secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid client credentials.",
            )
        return client

    # --- Bearer JWT path (T.2) ---
    bearer_token = _extract_bearer_auth(request)
    if bearer_token is not None:
        # T.2: extract the client_id from the JWT (without
        # cryptographic verification) so we can locate the
        # registered key material. The full verification happens
        # in ``verify_client_assertion`` below.
        import jwt as _jwt

        try:
            unverified = _jwt.decode(
                bearer_token,
                options={"verify_signature": False, "verify_exp": False},
            )
        except _jwt.InvalidTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid client_assertion: {exc}",
                headers={"WWW-Authenticate": ('Basic realm="OAuth2", Bearer realm="OAuth2"')},
            ) from exc
        jwt_client_id = unverified.get("sub") or unverified.get("iss")
        if not jwt_client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="client_assertion is missing sub/iss claim.",
            )
        if jwt_client_id != client_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=("Authenticated client does not match the requested client_id."),
            )
        client = await storage.get_client(client_id)
        if not client or not client.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Client not found or inactive.",
            )
        from authglow.services.client_jwt_auth import verify_client_assertion

        verify_client_assertion(
            request,
            client,
            client_assertion_type=("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
            client_assertion=bearer_token,
        )
        return client

    # --- Neither transport present ---
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=(
            "Client authentication required. Supported: HTTP Basic, "
            "Bearer JWT (client_secret_jwt / private_key_jwt)."
        ),
        headers={
            "WWW-Authenticate": (
                'Basic realm="OAuth2", Bearer realm="OAuth2", '
                'client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"'
            )
        },
    )


@router.get("/oauth2/register/{client_id}")
@limiter.limit("120/minute")
async def get_oauth_client_registration(
    client_id: str,
    request: Request,
    storage: OAuth2ClientStorage = Depends(lambda: OAuth2ClientStorage()),
):
    """RFC 7592: Read the client's registration.

    Authenticates the client via HTTP Basic (client_id:client_secret).
    Returns the registration metadata excluding the secret.
    """
    client = await _authenticate_client_for_dcr(request, storage, client_id)
    return _client_response_from_model(client)


@router.put("/oauth2/register/{client_id}")
@limiter.limit("60/minute")
async def update_oauth_client_registration(
    client_id: str,
    request: Request,
    update: OAuth2ClientUpdate,
    storage: OAuth2ClientStorage = Depends(lambda: OAuth2ClientStorage()),
    audit_service: AuditService = Depends(lambda: AuditService()),
):
    """RFC 7592: Update the client's registration.

    Only the client itself (via HTTP Basic) may update its own config.
    """
    client = await _authenticate_client_for_dcr(request, storage, client_id)

    update_dict = update.model_dump(exclude_unset=True)
    for field, value in update_dict.items():
        setattr(client, field, value)

    await storage.update_client(client)

    await audit_service.log_event(
        event_type="oauth_client_updated_dcr",
        user_id=None,
        metadata={
            "client_id": client_id,
            "client_name": client.client_name,
            "updated_fields": list(update_dict.keys()),
        },
        severity="info",
    )

    return _client_response_from_model(client)


@router.delete("/oauth2/register/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
async def delete_oauth_client_registration(
    client_id: str,
    request: Request,
    storage: OAuth2ClientStorage = Depends(lambda: OAuth2ClientStorage()),
    audit_service: AuditService = Depends(lambda: AuditService()),
):
    """RFC 7592: Delete the client's registration.

    Only the client itself (via HTTP Basic) may delete its own config.
    """
    client = await _authenticate_client_for_dcr(request, storage, client_id)

    success = await storage.delete_client(client_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete client registration.",
        )

    await audit_service.log_event(
        event_type="oauth_client_deleted_dcr",
        user_id=None,
        metadata={"client_id": client_id, "client_name": client.client_name},
        severity="info",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
