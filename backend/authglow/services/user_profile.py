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
from authglow.services.audit import AuditService
from authglow.services.email_verification import EmailVerificationService
from authglow.services.password import hash_password_async, verify_password_async
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
        # VAPT-130: inject AuditService for change_email self-service.
        self.audit_service = AuditService()
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
            await self.user_storage.update_user(user, acquire_lock=False)

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
            if not await verify_password_async(current_password, user.hashed_password):
                return False, "Current password is incorrect"

            # Update password
            user.hashed_password = await hash_password_async(new_password)
            user.updated_at = utcnow()

            await self.user_storage.update_user(user, acquire_lock=False)

        # Send security notification (fire-and-forget — don't block
        # the response on SMTP / email provider availability).
        import asyncio
        asyncio.create_task(self.security_service.send_password_changed_alert(user, ip_address))

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
            if not await verify_password_async(password, user.hashed_password):
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

            await self.user_storage.update_user(user)

        # Send verification email to new address
        token = await self.email_service.create_verification_token(user)
        await self.email_service.send_verification_email(user, token.verification_code)

        # Send notification to old email (fire-and-forget)
        import asyncio
        asyncio.create_task(self.security_service.send_email_changed_alert(
            old_email, user.first_name or "User", new_email, ip_address
        ))

        # VAPT-130: audit the self-service email change. The admin
        # route already logs; this closes the gap where a
        # session-hijacker could change the email + password and
        # leave no audit trail. ``old_email`` and ``new_email``
        # are masked by the audit service (default hash) so the
        # log line is itself PII-safe.
        await self.audit_service.log_event(
            event_type="user_email_changed",
            user_id=user_id,
            email=new_email,
            ip_address=ip_address,
            metadata={
                "old_email": old_email,
                "new_email": new_email,
            },
            severity="warning",
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
        if not await verify_password_async(password, user.hashed_password):
            return False, "Password is incorrect"

        # Delete user preferences (delegated to the
        # UserPreferencesRepository — backend-agnostic)
        await self._preferences_repo.delete(user_id)

        # VAPT-087: revoke refresh tokens *before* deleting the
        # user record so the (still-existent) user's token-family
        # files are reaped. Without this the refresh token
        # records (and their on-disk JSON files) become orphans.
        await self._revoke_user_tokens(user_id)

        # Delete user
        await self.user_storage.delete_user(user_id)

        # VAPT-082: GDPR Art. 17 right-to-erasure. Drop the
        # remaining per-user PII in parallel. ``return_exceptions``
        # so a single failure (e.g. transient I/O) does not
        # block the rest of the purge — every record still
        # needs to be reaped.
        await self._purge_user_pii(user_id)

        return True, "Account deleted successfully"

    async def _revoke_user_tokens(self, user_id: str) -> int:
        """Revoke every refresh token belonging to ``user_id``.

        Helper for ``delete_account`` (VAPT-087). The
        ``RefreshTokenService.revoke_user_tokens`` API already
        exists; we just call it here so the deletion path also
        tears down the token family on disk.
        """
        from authglow.services.refresh_token import RefreshTokenService

        return await RefreshTokenService().revoke_user_tokens(user_id)

    async def _purge_user_pii(self, user_id: str) -> dict[str, int]:
        """GDPR Art. 17 right-to-erasure (VAPT-082).

        Drops every PII-bearing record we own for ``user_id``:
        login history, security events, admin actions against
        the user, OAuth2 consents. Runs in parallel so a single
        failing service does not block the others. Returns a
        per-service deletion count for observability.

        Calls go through the *public* ``delete_for_user`` method
        on each service (never ``self._repo.*`` directly) so the
        service layer stays the single point of access to the
        repository. When the persistence backend swaps from
        File to Postgres, only the service / repository change —
        this method does not.
        """
        import asyncio

        from authglow.services.admin_action import AdminActionService
        from authglow.services.login_history import LoginHistoryService
        from authglow.services.oauth_consent import OAuth2ConsentService
        from authglow.services.security_event import SecurityEventService

        login_svc = LoginHistoryService()
        security_svc = SecurityEventService()
        admin_svc = AdminActionService()
        consent_svc = OAuth2ConsentService()

        results = await asyncio.gather(
            login_svc.delete_for_user(user_id),
            security_svc.delete_for_user(user_id),
            admin_svc.delete_for_user(user_id),
            consent_svc.delete_for_user(user_id),
            return_exceptions=True,
        )

        counts: dict[str, int] = {}
        names = ("login_history", "security_event", "admin_action", "oauth_consent")
        for name, result in zip(names, results):
            if isinstance(result, BaseException):
                counts[name] = -1  # sentinel for failure
            else:
                counts[name] = int(result)
        return counts

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

            if user.is_bootstrap:
                return (
                    False,
                    "The bootstrap admin account cannot be deactivated",
                )

            if user.is_federated:
                return (
                    False,
                    "Federated accounts are managed externally and cannot be deactivated from AuthGlow",
                )

            user.is_active = False
            user.updated_at = utcnow()

            await self.user_storage.update_user(user)

        return True, "Account deactivated successfully"

    async def reactivate_account(self, user_id: str) -> tuple[bool, str]:
        """Reactivate user account."""
        async with self._lock(f"user:{user_id}"):
            user = await self.user_storage.get_user(user_id)
            if not user:
                return False, "User not found"

            user.is_active = True
            user.updated_at = utcnow()

            await self.user_storage.update_user(user)

        return True, "Account reactivated successfully"
