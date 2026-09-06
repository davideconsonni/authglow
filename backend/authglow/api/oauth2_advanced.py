"""Advanced OAuth2 endpoints (revocation, introspection)."""

from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse

from authglow.api.auth import _extract_basic_auth, get_current_user
from authglow.api.oauth_errors import INVALID_CLIENT, OAuth2Error
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.core.jwt_singleton import get_jwt_service
from authglow.core.rate_limit import limiter
from authglow.models.audit_events import AuditEventType
from authglow.models.audit_metadata import TokenIntrospectedMetadata, TokenRevokedMetadata
from authglow.models.user import User
from authglow.services.audit import AuditService
from authglow.services.auth.token_blacklist import token_blacklist
from authglow.services.jwt import JWTService
from authglow.services.oauth2 import OAuth2Service
from authglow.services.refresh_token import RefreshTokenService
from authglow.services.user import UserService

# Back-compat alias for Fase 21 transition window
UserStorage = UserService

router = APIRouter()


def get_refresh_token_service():
    """Get refresh token service instance."""
    return RefreshTokenService()


def get_oauth2_service():
    """Get OAuth2 service instance."""
    return OAuth2Service()


def get_audit_service():
    """Get audit service instance."""
    return AuditService()


def get_user_storage():
    """Get user storage instance."""
    return UserStorage()


def _audience_allowed(token_aud: Optional[str], caller_client_id: str, settings) -> bool:
    """Audience binding rule shared by revocation and introspection.

    A client may only act on a token that was issued to it:

    * ``aud``-bearing tokens (third-party flows): the token's
      audience must equal the authenticated ``client_id``;
    * aud-less tokens (``client_credentials`` and legacy internal
      JWTs, which carry no ``aud`` — see the token-endpoint
      ``client_credentials`` branch): only the configured
      first-party client may act on them.
    """
    return token_aud == caller_client_id or (
        token_aud is None and caller_client_id == settings.oauth2_client_id
    )


@router.post("/oauth2/revoke")
@limiter.limit("20/minute")
async def revoke_token(
    request: Request,
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    refresh_token_service: RefreshTokenService = Depends(get_refresh_token_service),
    jwt_service: JWTService = Depends(get_jwt_service),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """RFC 7009: Token Revocation Endpoint.

    Allows clients to revoke access or refresh tokens.
    Requires authenticated client credentials (HTTP Basic or form post).

    RFC 7009 §2.1: client authentication failures are answered with
    the RFC 6749 §5.2 ``invalid_client`` envelope (401) — the previous
    "always 200" behaviour silently accepted unauthenticated callers.

    https://datatracker.ietf.org/doc/html/rfc7009
    """
    basic_client_id, basic_client_secret = _extract_basic_auth(request)
    resolved_client_id = client_id or basic_client_id
    resolved_client_secret = client_secret or basic_client_secret

    if not resolved_client_id or not resolved_client_secret:
        raise OAuth2Error(
            INVALID_CLIENT,
            "Client authentication required",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="OAuth2"'},
        )

    if not await oauth2_service.verify_client(resolved_client_id, resolved_client_secret):
        raise OAuth2Error(INVALID_CLIENT, "Invalid client credentials", status_code=401)

    # Determine token type
    if token_type_hint == "refresh_token" or not token_type_hint:
        # Try as refresh token first
        rt = await refresh_token_service.get_refresh_token(token)
        if rt and rt.client_id == resolved_client_id:
            success = await refresh_token_service.revoke_token(
                token, reason="Revoked via revocation endpoint"
            )

            if success:
                # Log revocation
                await audit_service.log_event(
                    event_type=AuditEventType.REFRESH_TOKEN_REVOKED,
                    user_id=rt.user_id,
                    email=rt.user_id,  # Will be masked by audit service
                    client_id=rt.client_id,
                    ip_address=request.client.host if request.client else None,
                    metadata=TokenRevokedMetadata(
                        client_id=rt.client_id,
                        token_id=rt.token_id,
                        token_type_hint="refresh_token",
                        revoked_by=resolved_client_id,
                        revocation_reason="Revoked via revocation endpoint",
                    ),
                    severity="warning",
                )

            # Return success regardless (per RFC 7009)
            return JSONResponse(status_code=200, content={})

    # Try as access token
    if token_type_hint == "access_token" or not token_type_hint:
        token_data = jwt_service.decode_token(token)
        if token_data and token_data.jti:
            # Ownership check — a client may only revoke tokens issued
            # to itself. Without it, any authenticated client could
            # blacklist any other client's bearer tokens (cross-client
            # DoS primitive):
            #   * ``aud``-bearing tokens (third-party flows): ``aud``
            #     must equal the authenticated ``client_id``;
            #   * legacy internal tokens without ``aud`` (first-party
            #     refresh / MFA-session JWTs): only the configured
            #     first-party client may revoke them.
            # Disallowed combinations are silently ignored and the
            # endpoint still answers 200 per RFC 7009 §2.2.
            settings = get_settings()
            if not _audience_allowed(token_data.aud, resolved_client_id, settings):
                return JSONResponse(status_code=200, content={})
            # Actually revoke: add jti to in-process blacklist
            await token_blacklist().revoke(token_data.jti, token_data.exp.timestamp())
            await audit_service.log_event(
                event_type=AuditEventType.ACCESS_TOKEN_REVOKED,
                user_id=token_data.sub,
                email=token_data.email,
                client_id=resolved_client_id,
                ip_address=request.client.host if request.client else None,
                metadata=TokenRevokedMetadata(
                    client_id=resolved_client_id,
                    token_id=token_data.jti,
                    token_type_hint="access_token",
                    revoked_by=resolved_client_id,
                    revocation_reason="Revoked via revocation endpoint",
                ),
                severity="warning",
            )

    # Always return 200 OK per RFC 7009
    return JSONResponse(status_code=200, content={})


@router.post("/oauth2/introspect")
@limiter.limit("60/minute")
async def introspect_token(
    request: Request,
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    refresh_token_service: RefreshTokenService = Depends(get_refresh_token_service),
    jwt_service: JWTService = Depends(get_jwt_service),
    user_storage: UserStorage = Depends(get_user_storage),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """RFC 7662: Token Introspection Endpoint.

    Allows resource servers to query token metadata.
    Requires client authentication.

    https://datatracker.ietf.org/doc/html/rfc7662
    """
    basic_client_id, basic_client_secret = _extract_basic_auth(request)

    resolved_client_id = client_id or basic_client_id
    resolved_client_secret = client_secret or basic_client_secret

    if not resolved_client_id or not resolved_client_secret:
        raise OAuth2Error(
            INVALID_CLIENT,
            "Client authentication required",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="OAuth2"'},
        )

    if not await oauth2_service.verify_client(resolved_client_id, resolved_client_secret):
        raise OAuth2Error(INVALID_CLIENT, "Invalid client credentials", status_code=401)

    # Try as refresh token
    if token_type_hint == "refresh_token" or not token_type_hint:
        rt = await refresh_token_service.get_refresh_token(token)
        if rt:
            # Ownership check (mirrors revoke_token): a client may
            # only introspect refresh tokens issued to itself.
            # RFC 7662 §2.2: an unauthorized introspection is answered
            # with ``{"active": false}`` — never with an error, and
            # never revealing *why* the token is considered inactive.
            if rt.client_id != resolved_client_id:
                return {"active": False}

            # Check if token is active
            active = not rt.revoked and not rt.used and utcnow() < rt.expires_at

            # Get user info
            user = await user_storage.get_user(rt.user_id)

            response = {
                "active": active,
                "scope": " ".join(rt.scopes),
                "client_id": rt.client_id,
                "token_type": "refresh_token",
                "exp": int(rt.expires_at.timestamp()),
                "iat": int(rt.created_at.timestamp()),
                "sub": rt.user_id,
            }

            if user and active:
                response["username"] = user.email
                response["email"] = user.email

            # Audit: token introspected
            await audit_service.log_event(
                event_type=AuditEventType.TOKEN_INTROSPECTED,
                user_id=rt.user_id,
                email=user.email if user else None,
                client_id=resolved_client_id,
                ip_address=request.client.host if request.client else None,
                metadata=TokenIntrospectedMetadata(
                    client_id=resolved_client_id,
                    token_id=rt.token_id,
                    active=active,
                    token_type="refresh_token",
                ),
            )

            return response

    # Try as access token (JWT)
    if token_type_hint == "access_token" or not token_type_hint:
        token_data = jwt_service.decode_token(token)
        if token_data:
            # RFC 7662 §2.2: the introspection response MUST NOT leak why a
            # token is inactive. The same audience binding as the
            # revocation endpoint is enforced silently: aud-bearing
            # tokens are only introspectable by their audience, and
            # aud-less tokens only by the configured first-party
            # client.
            if not _audience_allowed(token_data.aud, resolved_client_id, get_settings()):
                return {"active": False}

            active = utcnow() < token_data.exp

            # Also check revocation blacklist
            if active and token_data.jti and token_blacklist().is_revoked(token_data.jti):
                active = False

            # Get user info
            user = await user_storage.get_user(token_data.sub)

            response = {
                "active": active,
                "scope": " ".join(token_data.scopes),
                "token_type": "access_token",
                "exp": int(token_data.exp.timestamp()),
                "iat": int(token_data.iat.timestamp()),
                "sub": token_data.sub,
                "email": token_data.email,
                "client_id": token_data.aud,
            }

            if user and active:
                response["username"] = user.email

            # Audit: token introspected
            await audit_service.log_event(
                event_type=AuditEventType.TOKEN_INTROSPECTED,
                user_id=token_data.sub,
                email=token_data.email,
                client_id=resolved_client_id,
                ip_address=request.client.host if request.client else None,
                metadata=TokenIntrospectedMetadata(
                    client_id=resolved_client_id,
                    token_id=token_data.jti or "unknown",
                    active=active,
                    token_type="access_token",
                ),
            )

            return response

    # Token not found or invalid
    return {"active": False}


@router.get("/api/tokens/refresh/list")
async def list_user_refresh_tokens(
    current_user: User = Depends(get_current_user),
    refresh_token_service: RefreshTokenService = Depends(get_refresh_token_service),
):
    """List all active refresh tokens for current user.

    Useful for "active sessions" or "logged in devices" feature.
    """
    page_tokens, total = await refresh_token_service.list_all_tokens(
        active_only=True, limit=100, user_id=current_user.id
    )
    return {
        "sessions": [
            {
                "id": rt.token_id,
                "client": rt.client_id,
                "ip_address": rt.issued_ip,
                "created_at": rt.created_at.isoformat(),
                "last_active": (
                    rt.used_at.isoformat() if rt.used_at else rt.created_at.isoformat()
                ),
            }
            for rt in page_tokens
        ],
        "total": total,
    }


@router.post("/api/tokens/refresh/revoke-all")
@limiter.limit("5/minute")
async def revoke_all_user_refresh_tokens(
    request: Request,
    current_user: User = Depends(get_current_user),
    refresh_token_service: RefreshTokenService = Depends(get_refresh_token_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Revoke all refresh tokens for the current user.

    Useful for "log out from all devices" functionality.
    """
    count = await refresh_token_service.revoke_user_tokens(current_user.id)

    # Log the action
    await audit_service.log_event(
        event_type="all_refresh_tokens_revoked",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"revoked_count": count},
        severity="warning",
        ip_address=request.client.host if request.client else None,
    )

    return {"message": f"Successfully revoked {count} refresh tokens", "count": count}


@router.delete("/api/tokens/refresh/{token_id}")
@limiter.limit("10/minute")
async def revoke_user_refresh_token(
    request: Request,
    token_id: str,
    current_user: User = Depends(get_current_user),
    refresh_token_service: RefreshTokenService = Depends(get_refresh_token_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Revoke a single refresh token (current user only)."""
    rt = await refresh_token_service.get_refresh_token_by_id(token_id)
    if not rt:
        raise HTTPException(status_code=404, detail="Token not found")
    if rt.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not your token")

    success = await refresh_token_service.revoke_token_by_id(
        token_id, reason="User-initiated revocation"
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to revoke token")

    await audit_service.log_event(
        event_type="refresh_token_revoked",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"token_id": token_id},
        severity="info",
        ip_address=request.client.host if request.client else None,
    )
    return JSONResponse(status_code=204, content=None)
