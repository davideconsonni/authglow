"""Passkey/WebAuthn API endpoints for AuthGlow."""

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from authglow.core.rate_limit import limiter

from authglow.models.passkey import (
    PasskeyResponse,
    PasskeyRegistrationVerification,
    PasskeyAuthenticationVerification,
    PasskeyChallenge,
)
from authglow.models.user import User
from authglow.services.storage import UserStorage
from authglow.services.passkey import PasskeyService
from authglow.services.jwt import JWTService
from authglow.core.config import get_settings

router = APIRouter(prefix="/api/passkey")
security = HTTPBearer()
settings = get_settings()


def get_passkey_service(request: Request) -> PasskeyService:
    """Get passkey service instance with dynamic origin detection."""
    # Detect origin from request
    host = request.headers.get("host", "localhost:8000")
    scheme = "https" if request.url.scheme == "https" else "http"
    origin = f"{scheme}://{host}"

    # Extract RP ID from host (remove port)
    rp_id = host.split(":")[0]

    return PasskeyService(
        storage_path=settings.storage_path,
        rp_id=rp_id,
        rp_name=settings.passkey_rp_name,
        origin=origin,
    )


def get_user_storage() -> UserStorage:
    """Get user storage instance."""
    return UserStorage()


def get_jwt_service() -> JWTService:
    """Get JWT service instance."""
    return JWTService()


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    storage: Annotated[UserStorage, Depends(get_user_storage)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
) -> User:
    """Get current authenticated user."""
    token = credentials.credentials
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
    # Generate registration options
    options_dict, challenge_str = passkey_service.generate_registration_options_dict(
        current_user
    )

    # Save challenge
    challenge = PasskeyChallenge(
        challenge=challenge_str,
        user_id=current_user.id,
        expires_at=datetime.utcnow() + timedelta(minutes=5),
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
        import json
        import base64

        client_data = json.loads(
            base64.urlsafe_b64decode(verification.client_data_json + "==")
        )
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
    options_dict, challenge_str = passkey_service.generate_authentication_options_dict(
        passkeys
    )

    # Save challenge
    challenge = PasskeyChallenge(
        challenge=challenge_str,
        user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(minutes=5),
        type="authentication",
    )
    await passkey_service.save_challenge(challenge)

    return options_dict


@router.post("/auth/complete")
@limiter.limit("10/minute")  # Max 10 passkey verification attempts per minute per IP
async def complete_authentication(
    request: Request,
    verification: PasskeyAuthenticationVerification,
    passkey_service: Annotated[PasskeyService, Depends(get_passkey_service)],
    jwt_service: Annotated[JWTService, Depends(get_jwt_service)],
    storage: Annotated[UserStorage, Depends(get_user_storage)],
):
    """
    Complete passkey authentication ceremony.

    Verifies the authentication assertion and returns access token.
    """
    try:
        # Extract challenge from client_data_json
        import json
        import base64

        client_data = json.loads(
            base64.urlsafe_b64decode(verification.client_data_json + "==")
        )
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

        # Generate access token
        access_token = jwt_service.create_access_token(
            user_id=user.id,
            email=user.email,
            scopes=user.scopes,
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
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
