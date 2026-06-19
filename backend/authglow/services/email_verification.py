"""Email verification service.

Tokens are persisted via the ``EmailVerificationRepository``
Protocol. The service owns:

* the cryptographic helpers (``generate_verification_code``,
  ``_code_lookup_key``) — pure functions, no I/O;
* the constant-time ``secrets.compare_digest`` check of a presented
  code against the stored ``verification_code``;
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

VAPT-022 alignment: the credential emailed to the user is a
human-friendly ``XXXX-XXXX-XXXX`` code (14 chars, 31-symbol
alphabet, ``31^12`` entropy). The on-disk file is named after the
HMAC of the normalised code; the plaintext code is in the JSON
body for O(1) lookup. No bearer token exists for this flow.
"""

import secrets
from typing import Optional, Tuple

from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import Settings, get_settings
from authglow.core.crypto import verification_code_lookup_key
from authglow.core.datetime import utcnow
from authglow.models.email_verification import EmailVerificationToken
from authglow.models.user import User
from authglow.repositories.protocols import EmailVerificationRepository
from authglow.services.email.factory import get_email_service
from authglow.services.user import UserService as UserStorage

_VERIFICATION_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_VERIFICATION_CODE_SEGMENT_LEN = 4
_VERIFICATION_CODE_SEGMENTS = 3
_EXCLUDED_CONFUSABLE = frozenset("01OIL")


def generate_verification_code() -> str:
    """Generate a human-friendly verification code (VAPT-022 aligned).

    Format: ``XXXX-XXXX-XXXX`` (4+4+4 chars) drawn from a 31-symbol
    alphabet that excludes visually ambiguous characters (``0``,
    ``O``, ``1``, ``I``, ``L``). Entropy: ``31^12 ~= 7.9e17``
    possibilities, far exceeding the 24-hour token window. The
    code is emailed in the message body (never in the URL) and
    entered by the user into the verify-email form.
    """
    parts = []
    for _ in range(_VERIFICATION_CODE_SEGMENTS):
        parts.append(
            "".join(
                secrets.choice(_VERIFICATION_CODE_ALPHABET)
                for _ in range(_VERIFICATION_CODE_SEGMENT_LEN)
            )
        )
    code = "-".join(parts)
    assert not (set(code) - {"-"} & _EXCLUDED_CONFUSABLE), (
        f"verification_code {code!r} contains excluded confusable characters"
    )
    return code


class EmailVerificationService:
    """Service for email verification.

    The credential is a 14-char human-friendly code; the on-disk
    file is named after the HMAC of the normalised code. The
    plaintext code is stored in the JSON body for O(1) lookup.
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
        self._lock = named_lock()

        # Peer service — used by verify_email / resend_verification_email.
        # Kept as a public attribute for backward compatibility with the
        # existing test mocks (see tests/unit/test_email_verification.py).
        self.user_storage = UserStorage()

    @property
    def repository(self) -> EmailVerificationRepository:
        """The underlying repository (exposed for tests / admin tools)."""
        return self._repository

    def _code_lookup_key(self, code: str) -> str:
        """HMAC-SHA256 lookup key for a verification code (VAPT-022)."""
        return verification_code_lookup_key(self._settings.secret_key, code)

    @staticmethod
    def _normalise_code(code: str) -> str:
        """Strip whitespace and uppercase a presented verification code."""
        return code.strip().upper().replace(" ", "").replace("\t", "")

    async def create_verification_token(self, user: User) -> EmailVerificationToken:
        """Create a new email verification token."""
        verification_code = generate_verification_code()
        code_lookup = self._code_lookup_key(verification_code)

        token = EmailVerificationToken(
            verification_code=verification_code,
            code_lookup=code_lookup,
            user_id=user.id,
            email=user.email,
        )

        await self._repository.create(token)
        return token

    async def get_token(self, code: str) -> Optional[EmailVerificationToken]:
        """Get a verification token by the presented code.

        Uses O(1) HMAC lookup (no directory scanning), then a
        constant-time ``secrets.compare_digest`` of the normalised
        presented code against the stored ``verification_code``.
        """
        normalised = self._normalise_code(code)
        code_lookup = self._code_lookup_key(normalised)
        vt = await self._repository.get_by_lookup(code_lookup)
        if vt is None:
            return None

        if not secrets.compare_digest((vt.verification_code or "").strip().upper(), normalised):
            return None

        return vt

    async def mark_token_used(self, code: str) -> bool:
        """Mark a token as used.

        Combines an in-process ``named_lock`` (cross-coroutine
        serialisation) with the repository's versioned-write CAS
        (cross-process race detection). The CAS retry loop catches
        ``ConcurrentWriteError`` raised by ``repository.update()``
        when another process won the race.
        """
        normalised = self._normalise_code(code)
        code_lookup = self._code_lookup_key(normalised)

        async with self._lock(f"email_verification:{code_lookup}"):
            for _ in range(self.MAX_CAS_RETRIES):
                verification_token = await self.get_token(normalised)
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

    async def verify_email(self, code: str) -> Tuple[bool, Optional[str]]:
        """Verify an email using a verification code."""
        verification_token = await self.get_token(code)
        if not verification_token:
            return False, "Invalid verification code"

        if verification_token.used:
            return False, "Verification code already used"

        if utcnow() > verification_token.expires_at:
            return False, "Verification code expired"

        user = await self.user_storage.get_user(verification_token.user_id)
        if not user:
            return False, "User not found"

        user.email_verified = True
        user.email_verified_at = utcnow()
        await self.user_storage.update_user(user)

        await self.mark_token_used(code)

        return True, None

    async def send_verification_email(self, user: User, code: str) -> bool:
        """Send verification email to user.

        The verification code is sent as a plain-text code in the
        email body, NOT embedded in a clickable URL. This prevents
        token leakage through browser history, ``Referer`` headers,
        and proxy/CDN access logs (VAPT-022).
        """
        email_service = get_email_service()

        from urllib.parse import quote

        context = {
            "user_name": user.first_name or user.email.split("@")[0],
            "verification_code": code,
            "verify_page_url": (
                f"{self._settings.frontend_base_url}/auth/verify-email"
                f"?email={quote(user.email)}"
            ),
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

        success = await self.send_verification_email(user, token.verification_code)
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
