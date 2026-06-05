"""OpenID Connect API endpoints."""

import base64
import os
from typing import List, Optional
from urllib.parse import urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.models.oauth_client import OAuth2Client
from authglow.models.oidc import JWKSResponse, OpenIDConfiguration, UserInfoResponse
from authglow.services.audit import AuditService
from authglow.services.jwt import JWTService
from authglow.services.oauth_client import OAuth2ClientStorage
from authglow.services.oidc import OIDCService

router = APIRouter(tags=["OpenID Connect"])
security = HTTPBearer()


@router.get("/.well-known/openid-configuration", response_model=OpenIDConfiguration)
async def openid_configuration():
    """OpenID Connect Discovery endpoint.

    Returns metadata about the OpenID Provider's configuration.
    Spec: https://openid.net/specs/openid-connect-discovery-1_0.html
    """
    settings = get_settings()
    base_url = settings.issuer

    return OpenIDConfiguration(
        issuer=settings.issuer,
        authorization_endpoint=f"{base_url}/oauth2/authorize",
        token_endpoint=f"{base_url}/oauth2/token",
        userinfo_endpoint=f"{base_url}/oauth2/userinfo",
        jwks_uri=f"{base_url}/.well-known/jwks.json",
        registration_endpoint=f"{base_url}/oauth2/register",
        scopes_supported=["openid", "profile", "email", "phone", "address", "offline_access"],
        response_types_supported=[
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token",
        ],
        response_modes_supported=["query", "fragment", "form_post"],
        grant_types_supported=[
            "authorization_code",
            "implicit",
            "refresh_token",
            "client_credentials",
        ],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=[settings.jwt_algorithm],
        token_endpoint_auth_methods_supported=["client_secret_basic", "client_secret_post", "none"],
        claims_supported=[
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
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
        ],
        code_challenge_methods_supported=["S256"],
        revocation_endpoint=f"{base_url}/oauth2/revoke",
        introspection_endpoint=f"{base_url}/oauth2/introspect",
        end_session_endpoint=f"{base_url}/oauth2/logout",
    )


@router.get("/.well-known/jwks.json", response_model=JWKSResponse)
async def jwks():
    """JSON Web Key Set (JWKS) endpoint.

    Returns all active and verifying public keys in JWK format.
    Revoked keys are excluded.
    Spec: https://tools.ietf.org/html/rfc7517
    """
    settings = get_settings()
    jwt_service = JWTService()
    keyring_info = jwt_service.get_keyring_info()

    def int_to_base64(n):
        return (
            base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
            .rstrip(b"=")
            .decode("utf-8")
        )

    keys = []
    for kid, meta in keyring_info["keys"].items():
        status = meta.get("status", "")
        if status not in ("active", "verifying"):
            continue

        pub_path = os.path.join(settings.keys_dir, kid, "public_key.pem")
        if not os.path.exists(pub_path):
            continue

        try:
            with open(pub_path, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
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


@router.get("/oauth2/userinfo", response_model=UserInfoResponse)
async def userinfo(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """OpenID Connect UserInfo endpoint.

    Returns claims about the authenticated user.
    Spec: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo

    Requires:
        - Bearer token in Authorization header
        - Token must have been issued with 'openid' scope

    Returns:
        User information based on the scopes in the access token
    """
    jwt_service = JWTService()
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
async def logout_get(
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

    Note: Since we're stateless, logout is client-side (delete tokens).
    This endpoint validates the ID token and redirects to the post_logout_redirect_uri.
    """
    from fastapi.responses import RedirectResponse

    from authglow.services.audit import AuditService
    from authglow.services.oauth2 import OAuth2Service

    jwt_service = JWTService()
    oauth2_service = OAuth2Service()
    audit_service = AuditService()

    # Validate ID token if provided
    if id_token_hint:
        token_data = jwt_service.decode_token(id_token_hint)

        if token_data:
            # Log logout event
            await audit_service.log_event(
                event_type="oidc_logout",
                user_id=token_data.sub,
                metadata={
                    "client_id": token_data.aud,
                    "has_redirect": post_logout_redirect_uri is not None,
                },
            )

            # Validate post_logout_redirect_uri if provided
            if post_logout_redirect_uri and token_data.aud:
                client_id = token_data.aud
                client = await oauth2_service.client_storage.get_client(client_id)
                if client:
                    if post_logout_redirect_uri not in client.redirect_uris:
                        settings = get_settings()
                        parsed = urlparse(post_logout_redirect_uri)
                        if settings.is_production or parsed.hostname not in (
                            "localhost",
                            "127.0.0.1",
                        ):
                            raise HTTPException(
                                status_code=400, detail="Invalid post_logout_redirect_uri"
                            )

    # Redirect to post_logout_redirect_uri if provided
    if post_logout_redirect_uri:
        from urllib.parse import urlencode

        redirect_url = post_logout_redirect_uri
        if state:
            separator = "&" if "?" in redirect_url else "?"
            redirect_url = f"{redirect_url}{separator}{urlencode({'state': state})}"

        return RedirectResponse(url=redirect_url, status_code=303)

    # No redirect URI provided, return success message
    return {
        "message": "Logged out successfully",
        "note": "Please delete access and refresh tokens on the client side",
    }


@router.post("/oauth2/logout")
async def logout_post(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """OpenID Connect End Session endpoint (logout) - POST method.

    Spec: https://openid.net/specs/openid-connect-session-1_0.html#RPLogout

    Note: Since we're stateless, logout is client-side (delete tokens).
    This endpoint can be used for audit logging.
    """
    from authglow.services.audit import AuditService

    jwt_service = JWTService()
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
@limiter.limit("10/hour")
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

    allowed_grant_types = (
        payload.grant_types
        if payload.grant_types is not None
        else ["authorization_code", "refresh_token"]
    )
    invalid_grants = [
        g
        for g in allowed_grant_types
        if g not in ("authorization_code", "implicit", "refresh_token", "client_credentials")
    ]
    if invalid_grants:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported grant_type(s): {invalid_grants}",
        )

    allowed_scopes = payload.scope.split() if payload.scope else ["read"]

    is_confidential = payload.token_endpoint_auth_method != "none"

    plaintext_secret = storage.generate_client_secret()

    client = OAuth2Client(
        client_name=payload.client_name or "Dynamically Registered Client",
        client_secret=plaintext_secret,
        redirect_uris=payload.redirect_uris,
        allowed_scopes=allowed_scopes,
        grant_types=allowed_grant_types,
        is_confidential=is_confidential,
        require_pkce=not is_confidential,
        require_consent=True,
        client_uri=payload.client_uri,
        logo_uri=payload.logo_uri,
        terms_uri=payload.tos_uri,
        privacy_uri=payload.policy_uri,
        description=None,
        homepage_uri=payload.client_uri,
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
        "token_endpoint_auth_method": payload.token_endpoint_auth_method,
    }
