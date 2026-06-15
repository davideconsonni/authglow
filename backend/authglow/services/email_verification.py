"""Email verification service.

Tokens are persisted via the ``EmailVerificationRepository``
Protocol. The service owns:

* the cryptographic helpers (``_generate_token`` with bcrypt + HMAC,
  ``_find_lookup``) — pure functions, no I/O;
* the bcrypt verification of a presented plaintext against the
  stored hash;
* the in-process ``named_lock`` that serialises cross-coroutine
  ``mark_token_used`` calls;
* the CAS retry loop that catches ``ConcurrentWriteError`` raised
  by ``repository.update()`` on cross-process races;
* the multi-entity orchestration in ``verify_email`` (Token + User);
* the public ``create_verification_token`` / ``get_token`` /
  ``mark_token_used`` / ``verify_email`` /
  ``send_verification_email`` / ``resend_verification_email`` /
  ``cleanup_expired_tokens`` API.

The repository is responsible for the file layout, JSON
serialisation, versioned read / write, and bulk expired-token
cleanup. A default ``FileEmailVerificationRepository`` is
constructed when no repository is injected — FastAPI's
``Depends(get_verification_service)`` factory uses the default.
Tests can inject a custom repository (e.g. an in-memory mock) by
passing ``repository=...`` to the service constructor.

Security: the plaintext ``token`` is never persisted. Only
``token_hash`` (bcrypt) and ``token_lookup`` (HMAC-SHA256) are
stored on disk; the ``token`` Pydantic field is ``exclude=True`` so
the on-disk JSON omits it entirely.
"""

import hashlib
import hmac
import secrets
from typing import Optional, Tuple

import bcrypt

from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import Settings, get_settings
from authglow.core.datetime import utcnow
from authglow.models.email_verification import EmailVerificationToken
from authglow.models.user import User
from authglow.repositories.protocols import EmailVerificationRepository
from authglow.services.email.factory import get_email_service
from authglow.services.user import UserService as UserStorage


class EmailVerificationService:
    """Service for email verification.

    Tokens are stored using HMAC-SHA256 for the filename and bcrypt
    for verification — the plaintext token is NEVER persisted to disk.
    """

    MAX_CAS_RETRIES = 3

    def __init__(
        self,
        repository: Optional[EmailVerificationRepository] = None,
        *,
        settings: Optional[Settings] = None,
    ) -> None:
        """Initialize email verification service."""
        self._settings: Settings = settings or get_settings()
        self._repository: EmailVerificationRepository = (
            repository if repository is not None else _default_repository(self._settings)
        )
        self._secret_bytes = self._settings.secret_key.encode()
        self._lock = named_lock()

        # Peer service — used by verify_email / resend_verification_email.
        # Kept as a public attribute for backward compatibility with the
        # existing test mocks (see tests/unit/test_email_verification.py).
        self.user_storage = UserStorage()

    @property
    def repository(self) -> EmailVerificationRepository:
        """The underlying repository (exposed for tests / admin tools)."""
        return self._repository

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

        await self._repository.create(token)

        return token

    async def get_token(self, token: str) -> Optional[EmailVerificationToken]:
        """Get a verification token by plaintext string.

        Uses O(1) HMAC lookup — no directory scanning — then
        verifies the plaintext against the stored bcrypt hash.
        """
        token_lookup = self._find_lookup(token)
        vt = await self._repository.get_by_lookup(token_lookup)
        if vt is None:
            return None

        if not bcrypt.checkpw(token.encode(), vt.token_hash.encode()):
            return None

        vt.token = token
        return vt

    async def mark_token_used(self, token: str) -> bool:
        """Mark a token as used.

        Combines an in-process ``named_lock`` (cross-coroutine
        serialisation) with the repository's versioned-write CAS
        (cross-process race detection). The CAS retry loop catches
        ``ConcurrentWriteError`` raised by ``repository.update()``
        when another process won the race.
        """
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

                try:
                    await self._repository.update(verification_token)
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
        """Send verification email to user.

        The verification token is sent as a plain-text code in the email body,
        NOT embedded in a clickable URL.  This prevents token leakage through
        browser history, ``Referer`` headers, and proxy/CDN access logs.
        """
        email_service = get_email_service()

        context = {
            "user_name": user.first_name or user.email.split("@")[0],
            "verification_code": token,
            "verify_page_url": f"{self._settings.frontend_base_url}/auth/verify-email",
            "company_name": self._settings.company_name,
            "expires_hours": 24,
        }

        try:
            result = await email_service.send_template(
                to=[user.email],
                subject=f"Verify your email - {self._settings.company_name}",
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

        success = await self.send_verification_email(user, token.token)
        if not success:
            return False, "Failed to send email"

        return True, None

    async def cleanup_expired_tokens(self) -> int:
        """Delete all expired tokens. Returns the deletion count."""
        return await self._repository.cleanup_expired()


def _default_repository(settings: Settings) -> EmailVerificationRepository:
    from authglow.repositories.file.email_verification import (
        FileEmailVerificationRepository,
    )

    return FileEmailVerificationRepository(settings)
