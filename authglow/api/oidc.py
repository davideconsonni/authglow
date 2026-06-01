"""OpenID Connect API endpoints."""

import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from authglow.core.config import get_settings
from authglow.models.oidc import JWKSResponse, OpenIDConfiguration, UserInfoResponse
from authglow.services.jwt import JWTService
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

    Returns the public key used to verify JWT signatures in JWK format.
    Spec: https://tools.ietf.org/html/rfc7517
    """
    settings = get_settings()

    try:
        with open(settings.public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Public key not found.")

    if not isinstance(public_key, RSAPublicKey):
        raise HTTPException(
            status_code=500, detail="Public key is not RSA. Only RSA keys are supported for JWK."
        )

    public_numbers = public_key.public_numbers()

    # Helper to convert int to urlsafe_base64
    def int_to_base64(n):
        return (
            base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
            .rstrip(b"=")
            .decode("utf-8")
        )

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": settings.jwt_algorithm,
        "kid": "main-key",  # Key ID
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
    }

    return JWKSResponse(keys=[jwk])


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
    return user_info.model_dump(exclude_none=True)


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
                    "client_id": token_data.aud if hasattr(token_data, "aud") else None,
                    "has_redirect": post_logout_redirect_uri is not None,
                },
            )

            # Validate post_logout_redirect_uri if provided
            if post_logout_redirect_uri and hasattr(token_data, "aud"):
                client_id = token_data.aud
                # Verify the redirect URI is registered for this client
                client = await oauth2_service.client_storage.get_client(client_id)
                if client:
                    # Check if post_logout_redirect_uri is in allowed redirect URIs
                    # or in a separate list of post_logout_redirect_uris
                    if post_logout_redirect_uri not in client.redirect_uris:
                        # Allow localhost for development
                        from urllib.parse import urlparse

                        parsed = urlparse(post_logout_redirect_uri)
                        if parsed.hostname not in ["localhost", "127.0.0.1"]:
                            raise HTTPException(
                                status_code=400, detail="Invalid post_logout_redirect_uri"
                            )

    # Redirect to post_logout_redirect_uri if provided
    if post_logout_redirect_uri:
        redirect_url = post_logout_redirect_uri
        if state:
            # Add state parameter to redirect URL
            separator = "&" if "?" in redirect_url else "?"
            redirect_url = f"{redirect_url}{separator}state={state}"

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
