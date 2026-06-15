"""User profile and account management service.

The ``UserProfileService`` coordinates the user profile
aggregate (User + Preferences) and account-lifecycle operations
(change password, change email, deactivate, reactivate,
delete). The User CRUD is delegated to ``UserStorage``
(deprecated alias for ``UserService``, see
``services/user.py``); the per-user ``UserPreferences`` I/O is
delegated to :class:`FileUserPreferencesRepository` (Fase 19).

The service keeps the in-process ``named_lock`` for
cross-entity atomicity (e.g. ``change_email`` coordinates
``user_storage.update_user`` + email index update; ``delete_account``
coordinates preferences + user deletion).
"""

from typing import TYPE_CHECKING, Optional

from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.user_profile import (
    UserPreferences,
    UserPreferencesUpdate,
    UserProfileResponse,
    UserProfileUpdate,
)
from authglow.services.email_verification import EmailVerificationService
from authglow.services.password import hash_password, verify_password
from authglow.services.security_notifications import SecurityNotificationService
from authglow.services.user import UserService as UserStorage

if TYPE_CHECKING:
    from authglow.repositories.protocols import UserPreferencesRepository


class UserProfileService:
    """Service for managing user profiles and accounts."""

    def __init__(
        self,
        user_preferences_repository: Optional["UserPreferencesRepository"] = None,
    ):
        """Initialise the service.

        ``user_preferences_repository`` is optional; when
        ``None`` a fresh
        :class:`FileUserPreferencesRepository` is created via
        the FastAPI factory. Tests can pass a stub or an
        in-memory implementation directly.
        """
        self.settings = get_settings()
        self.user_storage = UserStorage()
        self.email_service = EmailVerificationService()
        self.security_service = SecurityNotificationService()
        self._lock = named_lock()

        if user_preferences_repository is None:
            from authglow.repositories.dependencies import (
                get_user_preferences_repository,
            )

            self._preferences_repo: "UserPreferencesRepository" = get_user_preferences_repository(
                settings=self.settings
            )
        else:
            self._preferences_repo = user_preferences_repository

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
            avatar_url=getattr(user, "avatar_url", None),
            phone=getattr(user, "phone", None),
            timezone=getattr(user, "timezone", None) or "UTC",
            language=getattr(user, "language", None) or "en",
            is_active=user.is_active,
            mfa_enabled=user.mfa_enabled,
            created_at=user.created_at,
            last_login=user.last_login,
            roles=user.scopes or [],  # Using scopes as roles for now
            scopes=user.scopes or [],
            preferences=preferences,
            total_logins=getattr(user, "total_logins", 0),
            failed_login_attempts=user.failed_login_attempts,
        )

    async def update_user_profile(
        self, user_id: str, profile_update: UserProfileUpdate
    ) -> Optional[UserProfileResponse]:
        """Update user profile."""
        async with self._lock(f"user:{user_id}"):
            user = await self.user_storage.get_user(user_id)
            if not user:
                return None

            # Update fields that are provided
            update_data = profile_update.model_dump(exclude_unset=True)
            for field, value in update_data.items():
                setattr(user, field, value)

            user.updated_at = utcnow()

            # Persist via the underlying UserRepository (the
            # ``_write_user`` shortcut on the service is no longer
            # the canonical path; the repository is responsible
            # for PII encryption + atomic write).
            await self.user_storage._user_repo.update(user)

        return await self.get_user_profile(user_id)

    # Password Management

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
        ip_address: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Change user password.

        Returns:
            (success, message)
        """
        async with self._lock(f"user:{user_id}"):
            user = await self.user_storage.get_user(user_id)
            if not user:
                return False, "User not found"

            # Verify current password
            if not verify_password(current_password, user.hashed_password):
                return False, "Current password is incorrect"

            # Update password
            user.hashed_password = hash_password(new_password)
            user.updated_at = utcnow()

            await self.user_storage._user_repo.update(user)

        # Send security notification
        await self.security_service.send_password_changed_alert(user, ip_address)

        return True, "Password changed successfully"

    # Email Management

    async def change_email(
        self,
        user_id: str,
        new_email: str,
        password: str,
        ip_address: Optional[str] = None,
    ) -> tuple[bool, str]:
        """Change user email (requires verification).

        Returns:
            (success, message)
        """
        async with self._lock(f"user:{user_id}"):
            user = await self.user_storage.get_user(user_id)
            if not user:
                return False, "User not found"

            # Verify password
            if not verify_password(password, user.hashed_password):
                return False, "Password is incorrect"

            # Check if new email is already in use
            existing_user = await self.user_storage.get_user_by_email(new_email)
            if existing_user:
                return False, "Email already in use"

            old_email = user.email

            # Update email and mark as unverified
            user.email = new_email
            user.email_verified = False
            user.updated_at = utcnow()

            await self.user_storage._user_repo.update(user)

        # Send verification email to new address
        token = await self.email_service.create_verification_token(user)
        await self.email_service.send_verification_email(user, token.verification_code)

        # Send notification to old email
        await self.security_service.send_email_changed_alert(
            old_email, user.first_name or "User", new_email, ip_address
        )

        return True, "Email changed. Please verify your new email address."

    # Account Deletion

    async def delete_account(
        self, user_id: str, password: str, confirmation: str
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

        if user.is_federated:
            return (
                False,
                "Federated accounts are managed externally and cannot be deleted from AuthGlow",
            )

        # Verify password
        if not verify_password(password, user.hashed_password):
            return False, "Password is incorrect"

        # Delete user preferences (delegated to the
        # UserPreferencesRepository — backend-agnostic)
        await self._preferences_repo.delete(user_id)

        # Delete user
        await self.user_storage.delete_user(user_id)

        return True, "Account deleted successfully"

    # User Preferences

    async def get_user_preferences(self, user_id: str) -> Optional[UserPreferences]:
        """Get user preferences.

        Returns the persisted ``UserPreferences`` if available,
        else a default ``UserPreferences(user_id=user_id)`` with
        all Pydantic defaults. Corrupt-JSON tolerance is the
        repository's responsibility (``_read_json`` returns
        ``None`` on missing / corrupt file).
        """
        preferences = await self._preferences_repo.get(user_id)
        if preferences is None:
            return UserPreferences(user_id=user_id)
        return preferences

    async def update_user_preferences(
        self, user_id: str, preferences_update: UserPreferencesUpdate
    ) -> UserPreferences:
        """Update user preferences."""
        async with self._lock(f"preferences:{user_id}"):
            # Get existing preferences or create new
            preferences = await self.get_user_preferences(user_id)
            if not preferences:
                preferences = UserPreferences(user_id=user_id)

            # Update fields that are provided
            update_data = preferences_update.model_dump(exclude_unset=True)
            for field, value in update_data.items():
                setattr(preferences, field, value)

            preferences.updated_at = utcnow()

            # Save preferences
            await self._preferences_repo.save(preferences)

        return preferences

    # Account Status

    async def deactivate_account(self, user_id: str) -> tuple[bool, str]:
        """Deactivate user account (can be reactivated)."""
        async with self._lock(f"user:{user_id}"):
            user = await self.user_storage.get_user(user_id)
            if not user:
                return False, "User not found"

            if user.is_federated:
                return (
                    False,
                    "Federated accounts are managed externally and cannot be deactivated from AuthGlow",
                )

            user.is_active = False
            user.updated_at = utcnow()

            await self.user_storage._user_repo.update(user)

        return True, "Account deactivated successfully"

    async def reactivate_account(self, user_id: str) -> tuple[bool, str]:
        """Reactivate user account."""
        async with self._lock(f"user:{user_id}"):
            user = await self.user_storage.get_user(user_id)
            if not user:
                return False, "User not found"

            user.is_active = True
            user.updated_at = utcnow()

            await self.user_storage._user_repo.update(user)

        return True, "Account reactivated successfully"
