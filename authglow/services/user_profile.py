"""User profile and account management service."""

import json
import os
from datetime import datetime
from typing import Optional
import fsspec

from authglow.core.config import get_settings
from authglow.services.password import verify_password, hash_password
from authglow.models.user_profile import (
    UserProfileUpdate,
    UserPreferences,
    UserPreferencesUpdate,
    UserProfileResponse
)
from authglow.services.storage import UserStorage
from authglow.services.email_verification import EmailVerificationService
from authglow.services.security_notifications import SecurityNotificationService


class UserProfileService:
    """Service for managing user profiles and accounts."""

    def __init__(self):
        """Initialize user profile service."""
        self.settings = get_settings()
        self.preferences_path = f"{self.settings.storage_path}/user_preferences"
        self.storage_options = self.settings.get_storage_options()
        self.user_storage = UserStorage()
        self.email_service = EmailVerificationService()
        self.security_service = SecurityNotificationService()

        # Initialize filesystem
        if self.settings.storage_backend == "file":
            os.makedirs(self.preferences_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend,
                **self.storage_options
            )

    # Profile Management

    async def get_user_profile(self, user_id: str) -> Optional[UserProfileResponse]:
        """Get a complete user profile."""
        user = await self.user_storage.get_user(user_id)
        if not user:
            return None

        # Get preferences
        preferences = await self.get_user_preferences(user_id)

        return UserProfileResponse(
            id=user.id,
            email=user.email,
            email_verified=user.email_verified,
            first_name=user.first_name,
            last_name=user.last_name,
            avatar_url=user.avatar_url,
            phone=user.phone,
            timezone=user.timezone,
            language=user.language,
            is_active=user.is_active,
            mfa_enabled=user.mfa_enabled,
            created_at=user.created_at,
            last_login=user.last_login,
            preferences=preferences,
            total_logins=user.total_logins,
            failed_login_attempts=user.failed_login_attempts
        )

    async def update_user_profile(
        self,
        user_id: str,
        profile_update: UserProfileUpdate
    ) -> Optional[UserProfileResponse]:
        """Update user profile."""
        user = await self.user_storage.get_user(user_id)
        if not user:
            return None

        # Update fields that are provided
        update_data = profile_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(user, field, value)

        user.updated_at = datetime.utcnow()

        # Save updated user
        await self.user_storage.update_user(user)

        return await self.get_user_profile(user_id)

    # Password Management

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
        ip_address: Optional[str] = None
    ) -> tuple[bool, str]:
        """Change user password.

        Returns:
            (success, message)
        """
        user = await self.user_storage.get_user(user_id)
        if not user:
            return False, "User not found"

        # Verify current password
        if not verify_password(current_password, user.password_hash):
            return False, "Current password is incorrect"

        # Update password
        user.password_hash = hash_password(new_password)
        user.updated_at = datetime.utcnow()

        await self.user_storage.update_user(user)

        # Send security notification
        await self.security_service.send_password_changed_alert(
            user.email,
            user.first_name or "User",
            ip_address
        )

        return True, "Password changed successfully"

    # Email Management

    async def change_email(
        self,
        user_id: str,
        new_email: str,
        password: str,
        ip_address: Optional[str] = None
    ) -> tuple[bool, str]:
        """Change user email (requires verification).

        Returns:
            (success, message)
        """
        user = await self.user_storage.get_user(user_id)
        if not user:
            return False, "User not found"

        # Verify password
        if not verify_password(password, user.password_hash):
            return False, "Password is incorrect"

        # Check if new email is already in use
        existing_user = await self.user_storage.get_user_by_email(new_email)
        if existing_user:
            return False, "Email already in use"

        old_email = user.email

        # Update email and mark as unverified
        user.email = new_email
        user.email_verified = False
        user.updated_at = datetime.utcnow()

        await self.user_storage.update_user(user)

        # Send verification email to new address
        await self.email_service.send_verification_email(user_id, new_email)

        # Send notification to old email
        await self.security_service.send_email_changed_alert(
            old_email,
            user.first_name or "User",
            new_email,
            ip_address
        )

        return True, "Email changed. Please verify your new email address."

    # Account Deletion

    async def delete_account(
        self,
        user_id: str,
        password: str,
        confirmation: str
    ) -> tuple[bool, str]:
        """Delete user account (permanent).

        Returns:
            (success, message)
        """
        if confirmation != "DELETE":
            return False, "Confirmation must be 'DELETE'"

        user = await self.user_storage.get_user(user_id)
        if not user:
            return False, "User not found"

        # Verify password
        if not verify_password(password, user.password_hash):
            return False, "Password is incorrect"

        # Delete user preferences
        try:
            prefs_path = f"{self.preferences_path}/{user_id}.json"
            if self.fs.exists(prefs_path):
                self.fs.rm(prefs_path)
        except Exception:
            pass

        # Delete user
        await self.user_storage.delete_user(user_id)

        return True, "Account deleted successfully"

    # User Preferences

    async def get_user_preferences(self, user_id: str) -> Optional[UserPreferences]:
        """Get user preferences."""
        try:
            file_path = f"{self.preferences_path}/{user_id}.json"
            if not self.fs.exists(file_path):
                # Return default preferences
                return UserPreferences(user_id=user_id)

            with self.fs.open(file_path, "r") as f:
                data = json.load(f)
                return UserPreferences(**data)
        except Exception:
            # Return default preferences on error
            return UserPreferences(user_id=user_id)

    async def update_user_preferences(
        self,
        user_id: str,
        preferences_update: UserPreferencesUpdate
    ) -> UserPreferences:
        """Update user preferences."""
        # Get existing preferences or create new
        preferences = await self.get_user_preferences(user_id)
        if not preferences:
            preferences = UserPreferences(user_id=user_id)

        # Update fields that are provided
        update_data = preferences_update.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            setattr(preferences, field, value)

        preferences.updated_at = datetime.utcnow()

        # Save preferences
        file_path = f"{self.preferences_path}/{user_id}.json"
        with self.fs.open(file_path, "w") as f:
            json.dump(preferences.model_dump(), f, default=str)

        return preferences

    # Account Status

    async def deactivate_account(self, user_id: str) -> tuple[bool, str]:
        """Deactivate user account (can be reactivated)."""
        user = await self.user_storage.get_user(user_id)
        if not user:
            return False, "User not found"

        user.is_active = False
        user.updated_at = datetime.utcnow()

        await self.user_storage.update_user(user)

        return True, "Account deactivated successfully"

    async def reactivate_account(self, user_id: str) -> tuple[bool, str]:
        """Reactivate user account."""
        user = await self.user_storage.get_user(user_id)
        if not user:
            return False, "User not found"

        user.is_active = True
        user.updated_at = datetime.utcnow()

        await self.user_storage.update_user(user)

        return True, "Account reactivated successfully"
