"""Email verification service."""

import os
from typing import Optional

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.email_verification import EmailVerificationToken
from authglow.models.user import User
from authglow.services.email.factory import get_email_service
from authglow.services.storage import UserStorage


class EmailVerificationService:
    """Service for email verification.

    The ``mark_token_used`` operation is protected by a named lock and
    optimistic-concurrency versioning to prevent token reuse.
    """

    MAX_CAS_RETRIES = 3

    def __init__(self):
        """Initialize email verification service."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/email_verifications"
        self.storage_options = self.settings.get_storage_options()
        self.user_storage = UserStorage()

        # Initialize filesystem
        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend, **self.storage_options
            )

        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

    async def create_verification_token(self, user: User) -> EmailVerificationToken:
        """Create a new email verification token.

        Args:
            user: User to create token for

        Returns:
            EmailVerificationToken
        """
        token = EmailVerificationToken(user_id=user.id, email=user.email)

        # Save token
        file_path = f"{self.storage_path}/{token.token}.json"
        await self._afs.write_json(file_path, token.model_dump())

        return token

    async def get_token(self, token: str) -> Optional[EmailVerificationToken]:
        """Get a verification token by token string.

        Args:
            token: Token string

        Returns:
            EmailVerificationToken if found, None otherwise
        """
        try:
            file_path = f"{self.storage_path}/{token}.json"
            data = await self._afs.read_json(file_path)
            return EmailVerificationToken(**data)
        except Exception:
            return None

    async def mark_token_used(self, token: str) -> bool:
        """Mark a token as used.

        Protected by a named lock and optimistic-concurrency versioning
        to prevent the same verification token from being used twice.

        Args:
            token: Token string

        Returns:
            True if successful, False otherwise
        """
        async with self._lock(f"email_token:{token}"):
            for attempt in range(self.MAX_CAS_RETRIES):
                verification_token = await self.get_token(token)
                if not verification_token:
                    return False

                if verification_token.used:
                    return False

                verification_token.used = True
                verification_token.used_at = utcnow()

                # Save updated token
                file_path = f"{self.storage_path}/{token}.json"
                try:
                    _, version = await self._afs.read_json_versioned(file_path)
                    await self._afs.write_json_versioned(
                        file_path, verification_token.model_dump(), version
                    )
                    return True
                except ConcurrentWriteError:
                    continue

            return False

    async def verify_email(self, token: str) -> tuple[bool, Optional[str]]:
        """Verify an email using a token.

        Args:
            token: Verification token

        Returns:
            Tuple of (success, error_message)
        """
        # Get token
        verification_token = await self.get_token(token)
        if not verification_token:
            return False, "Invalid verification token"

        # Check if already used
        if verification_token.used:
            return False, "Token already used"

        # Check if expired
        if utcnow() > verification_token.expires_at:
            return False, "Token expired"

        # Get user
        user = await self.user_storage.get_user(verification_token.user_id)
        if not user:
            return False, "User not found"

        # Mark email as verified
        user.email_verified = True
        user.email_verified_at = utcnow()
        await self.user_storage.update_user(user)

        # Mark token as used
        await self.mark_token_used(token)

        return True, None

    async def send_verification_email(self, user: User, token: str) -> bool:
        """Send verification email to user.

        Args:
            user: User to send email to
            token: Verification token

        Returns:
            True if email sent successfully, False otherwise
        """
        email_service = get_email_service()

        # Generate verification URL
        verification_url = f"{self.settings.base_url}/verify-email?token={token}"

        context = {
            "user_name": user.first_name or user.email.split("@")[0],
            "verification_url": verification_url,
            "company_name": self.settings.company_name,
            "expires_hours": 24,
        }

        try:
            result = await email_service.send_template(
                to=[user.email],
                subject=f"Verify your email - {self.settings.company_name}",
                template_name="email_verification",
                context=context,
            )
            return result.success
        except Exception as e:
            print(f"Failed to send verification email: {e}")
            return False

    async def resend_verification_email(self, email: str) -> tuple[bool, Optional[str]]:
        """Resend verification email for a user.

        Args:
            email: User email address

        Returns:
            Tuple of (success, error_message)
        """
        # Find user by email
        user = await self.user_storage.get_user_by_email(email)
        if not user:
            return False, "User not found"

        # Check if already verified
        if user.email_verified:
            return False, "Email already verified"

        # Create new token
        token = await self.create_verification_token(user)

        # Send email
        success = await self.send_verification_email(user, token.token)
        if not success:
            return False, "Failed to send email"

        return True, None

    async def cleanup_expired_tokens(self) -> int:
        """Delete all expired tokens.

        Returns:
            Number of tokens deleted
        """
        deleted = 0
        try:
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    token = EmailVerificationToken(**data)

                    # Delete if expired
                    if utcnow() > token.expires_at:
                        await self._afs.rm(file_path)
                        deleted += 1
                except Exception:
                    continue
        except Exception:
            pass

        return deleted
