"""Advanced OAuth2 endpoints (revocation, introspection)."""

from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import JSONResponse

from authglow.api.auth import _extract_basic_auth, get_current_user
from authglow.core.datetime import utcnow
from authglow.core.rate_limit import limiter
from authglow.core.token_blacklist import token_blacklist
from authglow.models.user import User
from authglow.services.audit import AuditService
from authglow.services.jwt import JWTService
from authglow.services.oauth2 import OAuth2Service
from authglow.services.refresh_token import RefreshTokenService
from authglow.services.storage import UserStorage

router = APIRouter()


def get_refresh_token_service():
    """Get refresh token service instance."""
    return RefreshTokenService()


def get_jwt_service():
    """Get JWT service instance."""
    return JWTService()


def get_oauth2_service():
    """Get OAuth2 service instance."""
    return OAuth2Service()


def get_audit_service():
    """Get audit service instance."""
    return AuditService()


def get_user_storage():
    """Get user storage instance."""
    return UserStorage()


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

    https://datatracker.ietf.org/doc/html/rfc7009
    """
    basic_client_id, basic_client_secret = _extract_basic_auth(request)
    resolved_client_id = client_id or basic_client_id
    resolved_client_secret = client_secret or basic_client_secret

    if not resolved_client_id or not resolved_client_secret:
        return JSONResponse(status_code=200, content={})

    if not await oauth2_service.verify_client(resolved_client_id, resolved_client_secret):
        return JSONResponse(status_code=200, content={})

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
                    event_type="refresh_token_revoked",
                    user_id=rt.user_id,
                    metadata={"client_id": rt.client_id, "token_id": rt.token_id},
                    severity="info",
                    ip_address=request.client.host if request.client else None,
                )

            # Return success regardless (per RFC 7009)
            return JSONResponse(status_code=200, content={})

    # Try as access token
    if token_type_hint == "access_token" or not token_type_hint:
        token_data = jwt_service.decode_token(token)
        if token_data and token_data.jti:
            # Actually revoke: add jti to in-process blacklist
            await token_blacklist().revoke(token_data.jti, token_data.exp.timestamp())
            await audit_service.log_event(
                event_type="access_token_revoked",
                user_id=token_data.sub,
                email=token_data.email,
                metadata={
                    "token_type": "access_token",
                    "jti": token_data.jti,
                },
                severity="info",
                ip_address=request.client.host if request.client else None,
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Client authentication required",
            headers={"WWW-Authenticate": 'Basic realm="OAuth2"'},
        )

    if not await oauth2_service.verify_client(resolved_client_id, resolved_client_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
        )

    # Try as refresh token
    if token_type_hint == "refresh_token" or not token_type_hint:
        rt = await refresh_token_service.get_refresh_token(token)
        if rt:
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

            return response

    # Try as access token (JWT)
    if token_type_hint == "access_token" or not token_type_hint:
        token_data = jwt_service.decode_token(token)
        if token_data:
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
            }

            if user and active:
                response["username"] = user.email

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
