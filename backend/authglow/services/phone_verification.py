"""Phone verification service (OTP via pluggable provider).

The service owns OTP generation, storage, expiry, attempt counting,
per-number rate limiting, and the ``phone_verified`` user-state
transition. Transport is delegated to a ``PhoneVerificationProvider``
(single active backend selected by ``PHONE_VERIFICATION_BACKEND``).

Persistence goes through the ``PhoneVerificationRepository``
Protocol. A default ``FilePhoneVerificationRepository`` is
constructed when no repository is injected. Tests can inject a
custom repository or provider directly.
"""

import secrets
from datetime import timedelta
from typing import TYPE_CHECKING, Optional, Tuple

from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import Settings, get_settings
from authglow.core.crypto import verification_code_lookup_key
from authglow.core.datetime import utcnow
from authglow.models.phone_verification import PhoneVerificationToken
from authglow.repositories.protocols import PhoneVerificationRepository
from authglow.services.user import UserService as UserStorage

if TYPE_CHECKING:
    from authglow.services.phone.base import PhoneVerificationProvider

MAX_CAS_RETRIES = 3


def generate_phone_code(length: int = 6) -> str:
    """Generate a zero-padded numeric OTP code.

    Uses ``secrets`` CSPRNG. Numeric-only so the code can be typed on
    any keypad and dictated over a voice channel.
    """
    if length < 4 or length > 10:
        raise ValueError(f"OTP length must be between 4 and 10 (got {length})")
    return str(secrets.randbelow(10**length)).zfill(length)


def render_phone_message(template: str, code: str) -> str:
    """Render the OTP message from a template.

    ``{code}`` is replaced with the code. Templates without the
    placeholder get the code appended so a misconfigured template
    can never send a codeless message.
    """
    if "{code}" in template:
        return template.replace("{code}", code)
    return f"{template.rstrip()} {code}"


class PhoneVerificationService:
    """Service for phone number verification via OTP codes."""

    def __init__(
        self,
        repository: Optional[PhoneVerificationRepository] = None,
        *,
        settings: Optional[Settings] = None,
        provider: Optional["PhoneVerificationProvider"] = None,
    ) -> None:
        """Initialize phone verification service."""
        self._settings: Settings = settings or get_settings()
        self._repository: PhoneVerificationRepository = (
            repository if repository is not None else _default_repository(self._settings)
        )
        self._provider: "PhoneVerificationProvider" = (
            provider if provider is not None else _default_provider(self._settings)
        )
        self._lock = named_lock()

        # Peer service — used by request_code / verify_code.
        self.user_storage = UserStorage()

    @property
    def repository(self) -> PhoneVerificationRepository:
        """The underlying repository (exposed for tests / admin tools)."""
        return self._repository

    @property
    def provider(self) -> "PhoneVerificationProvider":
        """The active send provider (exposed for tests)."""
        return self._provider

    def _code_lookup(self, phone: str, code: str) -> str:
        """HMAC-SHA256 lookup key for a phone + code pair."""
        return verification_code_lookup_key(self._settings.secret_key, f"{phone}:{code}")

    async def request_code(self, user_id: str, phone: str) -> Tuple[bool, Optional[str]]:
        """Generate and send a verification code to a phone number.

        Enforces per-number rate limiting (max sends per hour +
        resend cooldown). When the number differs from the user's
        stored phone, the stored phone is updated and
        ``phone_verified`` is reset to ``False``.

        Returns:
            (success, error) — error is None on success.
        """
        user = await self.user_storage.get_user(user_id)
        if user is None:
            return False, "User not found"

        now = utcnow()
        recent = await self._repository.list_for_phone(phone)
        window_start = now - timedelta(hours=1)
        sends_in_window = sum(1 for t in recent if t.created_at >= window_start)
        if sends_in_window >= self._settings.phone_max_sends_per_hour:
            return False, "Too many codes requested. Try again later"

        latest = max((t.created_at for t in recent), default=None)
        if latest is not None:
            cooldown = timedelta(seconds=self._settings.phone_resend_cooldown_seconds)
            if now - latest < cooldown:
                return False, "A code was just sent. Wait before requesting a new one"

        code = generate_phone_code(self._settings.phone_code_length)
        token = PhoneVerificationToken(
            code_lookup=self._code_lookup(phone, code),
            code=code,
            user_id=user.id,
            phone=phone,
            expires_at=now + timedelta(minutes=self._settings.phone_code_expire_minutes),
        )
        await self._repository.create(token)

        message = render_phone_message(self._settings.phone_message_template, code)
        result = await self._provider.send_code(phone, code, message)
        if not result.success:
            return False, result.error or "Failed to send verification code"

        if user.phone != phone or user.phone_verified:
            user.phone = phone
            user.phone_verified = False
            user.phone_verified_at = None
            user.updated_at = now
            await self.user_storage.update_user(user)

        return True, None

    async def verify_code(self, user_id: str, phone: str, code: str) -> Tuple[bool, Optional[str]]:
        """Verify a phone number with the received code.

        On success sets ``phone_verified=True`` (+ timestamp) on the
        user and marks the token used. Failed guesses are counted on
        the newest active token for the number (a wrong code maps to
        a different HMAC lookup, so per-token counting alone would
        never trigger); the number locks after ``phone_max_attempts``
        failures. A CAS retry loop protects against cross-process
        races.

        Returns:
            (success, error) — error is None on success.
        """
        code_lookup = self._code_lookup(phone, code)

        async with self._lock(f"phone_verification:{phone}"):
            for _ in range(MAX_CAS_RETRIES):
                token = await self._repository.get_by_lookup(code_lookup)
                if token is None:
                    locked = await self._register_failed_attempt(phone)
                    if locked:
                        return False, "Too many attempts. Request a new code"
                    return False, "Invalid verification code"

                if token.used:
                    return False, "Verification code already used"

                if utcnow() > token.expires_at:
                    return False, "Verification code expired"

                if token.user_id != user_id or token.phone != phone:
                    return False, "Invalid verification code"

                if token.attempts >= self._settings.phone_max_attempts:
                    return False, "Too many attempts. Request a new code"

                if not secrets.compare_digest(token.code, code):
                    token.attempts += 1
                    try:
                        await self._repository.update(token)
                    except ConcurrentWriteError:
                        continue
                    return False, "Invalid verification code"

                user = await self.user_storage.get_user(user_id)
                if user is None:
                    return False, "User not found"

                token.used = True
                token.used_at = utcnow()
                try:
                    await self._repository.update(token)
                except ConcurrentWriteError:
                    continue

                user.phone = phone
                user.phone_verified = True
                user.phone_verified_at = utcnow()
                user.updated_at = utcnow()
                await self.user_storage.update_user(user)

                return True, None

            return False, "Verification failed. Request a new code"

    async def _register_failed_attempt(self, phone: str) -> bool:
        """Count a wrong guess against the newest active token.

        Returns True when the number just hit the attempt limit
        (locked until a fresh code is requested).
        """
        now = utcnow()
        candidates = [
            t
            for t in await self._repository.list_for_phone(phone)
            if not t.used and now <= t.expires_at
        ]
        if not candidates:
            return False
        token = max(candidates, key=lambda t: t.created_at)
        token.attempts += 1
        try:
            await self._repository.update(token)
        except ConcurrentWriteError:
            pass
        return token.attempts >= self._settings.phone_max_attempts

    async def cleanup_expired_tokens(self) -> int:
        """Delete all expired tokens. Returns the deletion count."""
        return await self._repository.cleanup_expired()


def _default_repository(settings: Settings) -> PhoneVerificationRepository:
    from authglow.repositories.file.phone_verification import (
        FilePhoneVerificationRepository,
    )

    return FilePhoneVerificationRepository(settings)


def _default_provider(settings: Settings) -> "PhoneVerificationProvider":
    from authglow.services.phone.factory import create_phone_provider

    return create_phone_provider(settings=settings)
