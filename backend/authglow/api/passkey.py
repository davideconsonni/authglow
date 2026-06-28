"""Passkey/WebAuthn API endpoints for AuthGlow."""

from datetime import timedelta
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.core.jwt_singleton import get_jwt_service
from authglow.core.rate_limit import limiter
from authglow.models.passkey import (
    PasskeyAuthenticationVerification,
    PasskeyChallenge,
    PasskeyRegistrationVerification,
    PasskeyResponse,
)
from authglow.models.user import User
from authglow.services.audit import AuditService
from authglow.services.jwt import JWTService, resolve_rbac_permissions
from authglow.services.passkey import PasskeyService
from authglow.services.refresh_token import RefreshTokenService
from authglow.services.user import UserService

# Back-compat alias for Fase 21 transition window
UserStorage = UserService

router = APIRouter(prefix="/api/passkey")
security = HTTPBearer(auto_error=False)
settings = get_settings()


def get_passkey_service(request: Request) -> PasskeyService:
    """Get passkey service instance with dynamic origin detection.

    Prefers the Origin header (set by the browser) for correct WebAuthn
    origin verification behind reverse proxies and test playgrounds.
    Falls back to the Host header when no Origin header is present.
    """
    from urllib.parse import urlparse

    origin_header = request.headers.get("origin")
    if origin_header:
        parsed = urlparse(origin_header)
        origin = origin_header
        rp_id = parsed.hostname or "localhost"
    else:
        host = request.headers.get("host", "localhost:8000")
        scheme = "https" if request.url.scheme == "https" else "http"
        origin = f"{scheme}://{host}"
        rp_id = host.split(":")[0]

    return PasskeyService(
        rp_id=rp_id,
        rp_name=settings.passkey_rp_name,
        origin=origin,
    )


def get_user_storage() -> UserStorage:
    """Get user storage instance."""
    return UserStorage()


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    storage: Annotated[UserStorage, Depends(get_user_storage)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> User:
    """Get current authenticated user."""
    token: Optional[str] = credentials.credentials if credentials else None
    if not token:
        token = request.cookies.get(settings.auth_cookie_access_name)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    token_data = jwt_service.decode_token(token)

    if not token_data or token_data.token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user = await storage.get_user(token_data.sub)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user",
        )

    return user


@router.post("/register/begin")
async def begin_registration(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    passkey_service: Annotated[PasskeyService, Depends(get_passkey_service)],
):
    """
    Begin passkey registration ceremony.

    Returns WebAuthn credential creation options.
    """
    # Fetch existing passkeys to prevent duplicate registration
    existing_passkeys = await passkey_service.get_user_passkeys(current_user.id)

    # Generate registration options
    options_dict, challenge_str = passkey_service.generate_registration_options_dict(
        current_user, user_passkeys=existing_passkeys
    )

    # Save challenge
    challenge = PasskeyChallenge(
        challenge=challenge_str,
        user_id=current_user.id,
        expires_at=utcnow() + timedelta(minutes=5),
        type="registration",
    )
    await passkey_service.save_challenge(challenge)

    return options_dict


@router.post("/register/complete")
async def complete_registration(
    request: Request,
    verification: PasskeyRegistrationVerification,
    current_user: Annotated[User, Depends(get_current_user)],
    passkey_service: Annotated[PasskeyService, Depends(get_passkey_service)],
):
    """
    Complete passkey registration ceremony.

    Verifies the credential created by the authenticator.
    """
    try:
        # The challenge is embedded in client_data_json, extract it
        import base64
        import json

        client_data = json.loads(base64.urlsafe_b64decode(verification.client_data_json + "=="))
        challenge_str = client_data["challenge"]

        # Verify and save passkey
        passkey = await passkey_service.verify_registration(
            credential_id=verification.credential_id,
            client_data_json=verification.client_data_json,
            attestation_object=verification.attestation_object,
            challenge_str=challenge_str,
            transports=verification.transports,
            name=verification.name,
        )

        return {
            "success": True,
            "passkey": PasskeyResponse(
                credential_id=passkey.credential_id,
                name=passkey.name,
                created_at=passkey.created_at,
                last_used_at=passkey.last_used_at,
                device_type=passkey.device_type,
                transports=passkey.transports,
                backup_eligible=passkey.backup_eligible,
                backup_state=passkey.backup_state,
            ),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration verification failed: {str(e)}",
        )


class EmailRequest(BaseModel):
    """Email request for passkey authentication."""

    email: str


@router.post("/auth/begin")
@limiter.limit("10/minute")  # Max 10 passkey auth attempts per minute per IP
async def begin_authentication(
    request: Request,
    email_request: EmailRequest,
    passkey_service: Annotated[PasskeyService, Depends(get_passkey_service)],
    storage: Annotated[UserStorage, Depends(get_user_storage)],
):
    """
    Begin passkey authentication ceremony.

    Returns WebAuthn credential request options for the user.
    """
    # Get user by email
    user = await storage.get_user_by_email(email_request.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credentials or no passkeys registered",
        )

    # Get user's passkeys
    passkeys = await passkey_service.get_user_passkeys(user.id)
    if not passkeys:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credentials or no passkeys registered",
        )

    # Generate authentication options
    options_dict, challenge_str = passkey_service.generate_authentication_options_dict(passkeys)

    # Save challenge
    challenge = PasskeyChallenge(
        challenge=challenge_str,
        user_id=user.id,
        expires_at=utcnow() + timedelta(minutes=5),
        type="authentication",
    )
    await passkey_service.save_challenge(challenge)

    return options_dict


@router.post("/auth/complete")
@limiter.limit("10/minute")  # Max 10 passkey verification attempts per minute per IP
async def complete_authentication(
    request: Request,
    response: Response,
    verification: PasskeyAuthenticationVerification,
    passkey_service: Annotated[PasskeyService, Depends(get_passkey_service)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
    storage: Annotated[UserStorage, Depends(get_user_storage)],
    refresh_token_service: Annotated[RefreshTokenService, Depends(lambda: RefreshTokenService())],
    audit_service: Annotated[AuditService, Depends(lambda: AuditService())],
):
    """
    Complete passkey authentication ceremony.

    Verifies the authentication assertion, sets httpOnly auth cookies,
    and returns access + refresh token.
    """
    settings = get_settings()
    from authglow.api.auth import _set_auth_cookies

    try:
        # Extract challenge from client_data_json
        import base64
        import json

        client_data = json.loads(base64.urlsafe_b64decode(verification.client_data_json + "=="))
        challenge_str = client_data["challenge"]

        # Verify authentication
        user_id, new_sign_count = await passkey_service.verify_authentication(
            credential_id=verification.credential_id,
            client_data_json=verification.client_data_json,
            authenticator_data=verification.authenticator_data,
            signature=verification.signature,
            challenge_str=challenge_str,
        )

        # Get user
        user = await storage.get_user(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Check if account is suspended
        if user.suspended_until and utcnow() < user.suspended_until:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account suspended until {user.suspended_until.isoformat()}",
            )

        await storage.update_last_login(user.id)

        # Generate access token
        rbac_perms, rbac_roles = await resolve_rbac_permissions(user.id)
        # VAPT-046: tag the passkey-minted access token with
        # the internal-flow audience (same convention as the
        # password login + API-key + refresh paths).
        from authglow.services.jwt import INTERNAL_AUDIENCE

        access_token = jwt_service.create_access_token(
            user_id=user.id,
            email=user.email,
            scopes=user.scopes,
            permissions=rbac_perms,
            roles=rbac_roles,
            audience=INTERNAL_AUDIENCE,
        )

        # Create persistent refresh token for session tracking
        rt = await refresh_token_service.create_refresh_token(
            user_id=user.id,
            client_id="passkey_grant",
            scopes=user.scopes,
            issued_ip=request.client.host if request.client else None,
            expires_in_days=30,
        )

        # Log successful passkey login
        # VAPT-085: truncate credential_id to 8 chars. The full
        # WebAuthn credential_id is a stable per-user-device
        # fingerprint; combined with the cleartext email and IP
        # in the audit log it was a permanent tracking primitive.
        # The first 8 chars are enough to correlate events from
        # the same passkey; the full id is still in the
        # ``passkeys`` table for lookups.
        await audit_service.log_event(
            event_type="passkey_login_success",
            user_id=user.id,
            email=user.email,
            ip_address=request.client.host if request.client else None,
            metadata={"credential_id": verification.credential_id[:8]},
            severity="info",
        )

        from authglow.services.login_history import LoginHistoryService

        login_svc = LoginHistoryService()
        await login_svc.record_login(
            user_id=user.id,
            email=user.email,
            success=True,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        _set_auth_cookies(response, access_token, rt.token, settings)

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "refresh_token": rt.token,
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "scopes": user.scopes,
            },
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Authentication verification failed: {str(e)}",
        )


@router.get("/list")
async def list_passkeys(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    passkey_service: Annotated[PasskeyService, Depends(get_passkey_service)],
):
    """List all passkeys for the current user."""
    passkeys = await passkey_service.get_user_passkeys(current_user.id)

    return [
        PasskeyResponse(
            credential_id=pk.credential_id,
            name=pk.name,
            created_at=pk.created_at,
            last_used_at=pk.last_used_at,
            device_type=pk.device_type,
            transports=pk.transports,
            backup_eligible=pk.backup_eligible,
            backup_state=pk.backup_state,
        )
        for pk in passkeys
    ]


@router.delete("/{credential_id}")
async def delete_passkey(
    request: Request,
    credential_id: str,
    current_user: Annotated[User, Depends(get_current_user)],
    passkey_service: Annotated[PasskeyService, Depends(get_passkey_service)],
):
    """Delete a passkey."""
    success = await passkey_service.delete_passkey(current_user.id, credential_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Passkey not found",
        )

    return {"success": True, "message": "Passkey deleted"}
