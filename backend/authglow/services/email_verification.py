"""Email verification service."""

import hashlib
import hmac
import os
import secrets
from typing import Optional, Tuple

import bcrypt
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

    Tokens are stored using HMAC-SHA256 for the filename and bcrypt
    for verification — the plaintext token is NEVER persisted to disk.
    """

    MAX_CAS_RETRIES = 3

    def __init__(self):
        """Initialize email verification service."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/email_verifications"
        self.storage_options = self.settings.get_storage_options()
        self.user_storage = UserStorage()
        self._secret_bytes = self.settings.secret_key.encode()

        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(self.settings.storage_backend, **self.storage_options)

        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

    def _generate_token(self) -> Tuple[str, str, str]:
        """Generate a secure verification token.

        Returns:
            tuple: (plaintext_token, token_hash, token_lookup)
        """
        plaintext = secrets.token_urlsafe(32)
        token_hash = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt()).decode()
        token_lookup = hmac.new(self._secret_bytes, plaintext.encode(), hashlib.sha256).hexdigest()
        return plaintext, token_hash, token_lookup

    def _find_lookup(self, token: str) -> str:
        """Compute HMAC lookup key from a plaintext token."""
        return hmac.new(self._secret_bytes, token.encode(), hashlib.sha256).hexdigest()

    async def create_verification_token(self, user: User) -> EmailVerificationToken:
        """Create a new email verification token."""
        plaintext, token_hash, token_lookup = self._generate_token()

        token = EmailVerificationToken(
            token=plaintext,
            token_hash=token_hash,
            token_lookup=token_lookup,
            user_id=user.id,
            email=user.email,
        )

        file_path = f"{self.storage_path}/{token_lookup}.json"
        await self._afs.write_json(file_path, token.model_dump())

        return token

    async def get_token(self, token: str) -> Optional[EmailVerificationToken]:
        """Get a verification token by plaintext string.

        Uses O(1) HMAC lookup — no directory scanning.
        """
        token_lookup = self._find_lookup(token)
        file_path = f"{self.storage_path}/{token_lookup}.json"

        try:
            data = await self._afs.read_json(file_path)
            vt = EmailVerificationToken(**data)
        except Exception:
            return None

        if not bcrypt.checkpw(token.encode(), vt.token_hash.encode()):
            return None

        vt.token = token
        return vt

    async def mark_token_used(self, token: str) -> bool:
        """Mark a token as used."""
        token_lookup = self._find_lookup(token)

        async with self._lock(f"email_token:{token_lookup}"):
            for _ in range(self.MAX_CAS_RETRIES):
                verification_token = await self.get_token(token)
                if not verification_token:
                    return False

                if verification_token.used:
                    return False

                verification_token.used = True
                verification_token.used_at = utcnow()

                file_path = f"{self.storage_path}/{token_lookup}.json"
                try:
                    _, version = await self._afs.read_json_versioned(file_path)
                    await self._afs.write_json_versioned(
                        file_path, verification_token.model_dump(), version
                    )
                    return True
                except ConcurrentWriteError:
                    continue

            return False

    async def verify_email(self, token: str) -> Tuple[bool, Optional[str]]:
        """Verify an email using a token."""
        verification_token = await self.get_token(token)
        if not verification_token:
            return False, "Invalid verification token"

        if verification_token.used:
            return False, "Token already used"

        if utcnow() > verification_token.expires_at:
            return False, "Token expired"

        user = await self.user_storage.get_user(verification_token.user_id)
        if not user:
            return False, "User not found"

        user.email_verified = True
        user.email_verified_at = utcnow()
        await self.user_storage.update_user(user)

        await self.mark_token_used(token)

        return True, None

    async def send_verification_email(self, user: User, token: str) -> bool:
        """Send verification email to user."""
        email_service = get_email_service()

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

    async def resend_verification_email(self, email: str) -> Tuple[bool, Optional[str]]:
        """Resend verification email for a user."""
        user = await self.user_storage.get_user_by_email(email)
        if not user:
            return False, "User not found"

        if user.email_verified:
            return False, "Email already verified"

        token = await self.create_verification_token(user)

        success = await self.send_verification_email(user, token.token)  # type: ignore[arg-type]
        if not success:
            return False, "Failed to send email"

        return True, None

    async def cleanup_expired_tokens(self) -> int:
        """Delete all expired tokens."""
        deleted = 0
        try:
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    token = EmailVerificationToken(**data)

                    if utcnow() > token.expires_at:
                        await self._afs.rm(file_path)
                        deleted += 1
                except Exception:
                    continue
        except Exception:
            pass

        return deleted
