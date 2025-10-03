"""OpenID Connect API endpoints."""

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from authglow.models.oidc import (
    UserInfoResponse,
    OpenIDConfiguration,
    JWKSResponse
)
from authglow.services.oidc import OIDCService
from authglow.services.jwt import JWTService
from authglow.core.config import get_settings
from authglow.core.permissions import get_current_user

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
        scopes_supported=[
            "openid",
            "profile",
            "email",
            "phone",
            "address",
            "offline_access"
        ],
        response_types_supported=[
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token"
        ],
        response_modes_supported=[
            "query",
            "fragment",
            "form_post"
        ],
        grant_types_supported=[
            "authorization_code",
            "implicit",
            "refresh_token",
            "client_credentials"
        ],
        subject_types_supported=["public"],
        id_token_signing_alg_values_supported=[settings.jwt_algorithm],
        token_endpoint_auth_methods_supported=[
            "client_secret_basic",
            "client_secret_post",
            "none"
        ],
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
            "updated_at"
        ],
        code_challenge_methods_supported=["S256"],
        revocation_endpoint=f"{base_url}/oauth2/revoke",
        introspection_endpoint=f"{base_url}/oauth2/introspect",
        end_session_endpoint=f"{base_url}/oauth2/logout"
    )


@router.get("/.well-known/jwks.json", response_model=JWKSResponse)
async def jwks():
    """JSON Web Key Set (JWKS) endpoint.

    Returns the public keys used to verify JWT signatures.
    Spec: https://tools.ietf.org/html/rfc7517

    Note: This is a placeholder implementation for symmetric keys (HS256).
    For production, use asymmetric keys (RS256) and expose only the public key.
    """
    settings = get_settings()

    # WARNING: This is NOT recommended for production.
    # In production, use RS256 (asymmetric) and only expose public keys.
    # For HS256 (symmetric), the secret must remain private.

    return JWKSResponse(
        keys=[
            {
                "kty": "oct",  # Key type: octet sequence (symmetric)
                "use": "sig",  # Usage: signature
                "alg": settings.jwt_algorithm,
                "kid": "main-key",  # Key ID
                # NOTE: Secret should NOT be exposed for HS256
                # This is here for development only
            }
        ]
    )


@router.get("/oauth2/userinfo", response_model=UserInfoResponse)
async def userinfo(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
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
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check if token has 'openid' scope
    if "openid" not in token_data.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not have 'openid' scope"
        )

    # Get user info based on scopes
    user_info = await oidc_service.get_user_info(
        token_data.sub,
        token_data.scopes
    )

    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user_info


@router.post("/oauth2/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """OpenID Connect End Session endpoint (logout).

    Spec: https://openid.net/specs/openid-connect-session-1_0.html#RPLogout

    Note: Since we're stateless, logout is client-side (delete tokens).
    This endpoint can be used for audit logging.
    """
    jwt_service = JWTService()

    # Decode token for audit logging
    token = credentials.credentials
    token_data = jwt_service.decode_token(token)

    if token_data:
        # TODO: Log logout event to audit service
        pass

    return {
        "message": "Logged out successfully",
        "note": "Please delete access and refresh tokens on the client side"
    }
