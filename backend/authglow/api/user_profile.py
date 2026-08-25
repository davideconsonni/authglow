"""User profile and account management API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from authglow.api.auth import _clear_auth_cookies, get_current_user
from authglow.core.config import get_settings
from authglow.core.jwt_singleton import get_jwt_service
from authglow.models.user import User
from authglow.models.user_profile import (
    ChangeEmailRequest,
    ChangePasswordRequest,
    DeleteAccountRequest,
    UserPreferences,
    UserPreferencesUpdate,
    UserProfileResponse,
    UserProfileUpdate,
)
from authglow.services.auth.token_blacklist import token_blacklist
from authglow.services.user_profile import UserProfileService

router = APIRouter(tags=["User Profile"])


@router.get("/api/profile/me", response_model=UserProfileResponse)
async def get_my_profile(current_user: User = Depends(get_current_user)):
    """Get current user's profile."""
    profile_service = UserProfileService()
    profile = await profile_service.get_user_profile(current_user.id)

    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")

    profile.scopes = current_user.scopes

    return profile


@router.patch("/api/profile/me", response_model=UserProfileResponse)
async def update_my_profile(
    profile_update: UserProfileUpdate, current_user: User = Depends(get_current_user)
):
    """Update current user's profile."""
    profile_service = UserProfileService()
    profile = await profile_service.update_user_profile(current_user.id, profile_update)

    if not profile:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")

    return profile


@router.post("/api/profile/me/change-password")
async def change_my_password(
    password_request: ChangePasswordRequest,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """Change current user's password.

    Session revocation (ported from the removed POST /api/password/change):
    all refresh tokens are revoked by the service, the current access token
    JTI is blacklisted, and auth cookies are cleared — the user is signed
    out everywhere, including this browser.
    """
    profile_service = UserProfileService()

    ip_address = request.client.host if request.client else None

    success, message = await profile_service.change_password(
        current_user.id,
        password_request.current_password,
        password_request.new_password,
        ip_address,
    )

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    settings = get_settings()
    access_token = request.cookies.get(settings.auth_cookie_access_name)
    if access_token:
        jwt_service = await get_jwt_service()
        token_data = jwt_service.decode_token(access_token)
        if token_data and token_data.jti:
            await token_blacklist().revoke(token_data.jti, token_data.exp.timestamp())
    _clear_auth_cookies(response, settings)

    return {"message": "Password changed. Please sign in again with your new password."}


@router.post("/api/profile/me/change-email")
async def change_my_email(
    email_request: ChangeEmailRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """Change current user's email (requires verification)."""
    profile_service = UserProfileService()

    ip_address = request.client.host if request.client else None

    success, message = await profile_service.change_email(
        current_user.id, email_request.new_email, email_request.password, ip_address
    )

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    return {"message": message}


@router.delete("/api/profile/me", status_code=status.HTTP_200_OK)
async def delete_my_account(
    delete_request: DeleteAccountRequest,
    current_user: User = Depends(get_current_user),
):
    """Delete current user's account (permanent)."""
    profile_service = UserProfileService()

    success, message = await profile_service.delete_account(
        current_user.id, delete_request.password, delete_request.confirmation
    )

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    return {"message": message}


@router.post("/api/profile/me/deactivate")
async def deactivate_my_account(current_user: User = Depends(get_current_user)):
    """Deactivate current user's account (can be reactivated)."""
    profile_service = UserProfileService()

    success, message = await profile_service.deactivate_account(current_user.id)

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    return {"message": message}


@router.post("/api/profile/me/reactivate")
async def reactivate_my_account(current_user: User = Depends(get_current_user)):
    """Reactivate current user's account."""
    profile_service = UserProfileService()

    success, message = await profile_service.reactivate_account(current_user.id)

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    return {"message": message}


@router.get("/api/profile/me/preferences", response_model=UserPreferences)
async def get_my_preferences(current_user: User = Depends(get_current_user)):
    """Get current user's preferences."""
    profile_service = UserProfileService()
    preferences = await profile_service.get_user_preferences(current_user.id)

    return preferences


@router.patch("/api/profile/me/preferences", response_model=UserPreferences)
async def update_my_preferences(
    preferences_update: UserPreferencesUpdate,
    current_user: User = Depends(get_current_user),
):
    """Update current user's preferences."""
    profile_service = UserProfileService()
    preferences = await profile_service.update_user_preferences(current_user.id, preferences_update)

    return preferences
