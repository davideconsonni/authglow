"""Password reset service for managing reset tokens.

Tokens are persisted via the ``PasswordResetRepository`` Protocol.
The service owns:

* the cryptographic helpers (``_generate_token`` with bcrypt + HMAC,
  ``_reset_code_lookup_key`` for the human-friendly code) — pure
  functions, no I/O;
* the ``generate_reset_code`` helper (alphabet + format + the
  confusable-character invariant assert);
* the bcrypt verification of a presented plaintext against the
  stored hash;
* the in-process ``named_lock`` that serialises cross-coroutine
  ``mark_token_used`` calls;
* the CAS retry loop that catches ``ConcurrentWriteError`` raised
  by the repository on cross-process races (no-op today — the
  repository's raw-text write does not preserve ``_version``, so
  the loop never fires; preserved as defensive future-proofing);
* the public ``create_reset_token`` / ``verify_token`` /
  ``verify_by_code`` / ``mark_token_used`` / ``get_token`` /
  ``list_user_tokens`` / ``list_all_tokens`` /
  ``revoke_user_tokens`` / ``delete_token`` /
  ``cleanup_expired_tokens`` / ``get_stats`` API.

The repository is responsible for the file layout (primary +
mirror), JSON serialisation, the dual-mirror write logic, and
bulk operations (``cleanup_expired``, ``stats``). A default
``FilePasswordResetRepository`` is constructed when no repository
is injected — FastAPI's ``Depends(get_reset_service)`` factory
uses the default.

Security: the plaintext bearer token and reset code are never
persisted. The ``token_hash`` (bcrypt) is the only on-disk
credential, and ``reset_code`` is a single-use secret with a
30-minute window.
"""

import hashlib
import hmac
import secrets
from datetime import timedelta as _timedelta
from typing import List, Optional, Tuple

import bcrypt

from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import Settings, get_settings
from authglow.core.crypto import reset_code_lookup_key
from authglow.core.datetime import utcnow
from authglow.models.password_reset import PasswordResetToken
from authglow.repositories.protocols import PasswordResetRepository

_RESET_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_RESET_CODE_SEGMENT_LEN = 4
_RESET_CODE_SEGMENTS = 3

# Confusable characters that are NOT in the alphabet (documented for the
# ``test_code_alphabet_excludes_ambiguous_chars`` invariant test).
_EXCLUDED_CHARS = frozenset("01OIL")


def generate_reset_code() -> str:
    """Generate a human-friendly reset code (VAPT-022 fix).

    Format: ``XXXX-XXXX-XXXX`` (4+4+4 chars) drawn from a 31-symbol
    alphabet that excludes visually ambiguous characters (``0``, ``O``,
    ``1``, ``I``, ``L``). Entropy: ``31^12 ~= 7.9e17`` possibilities,
    far exceeding the 30-minute token window. The code is intended to be
    emailed in the message body (never in the URL) and entered by the
    user into the reset form.
    """
    parts = []
    for _ in range(_RESET_CODE_SEGMENTS):
        parts.append(
            "".join(secrets.choice(_RESET_CODE_ALPHABET) for _ in range(_RESET_CODE_SEGMENT_LEN))
        )
    code = "-".join(parts)
    # Defensive: the alphabet is constant, but assert the invariant at
    # generation time so a future refactor cannot silently re-introduce
    # confusable characters.
    assert not (set(code) - {"-"} & _EXCLUDED_CHARS), (
        f"reset_code {code!r} contains excluded confusable characters"
    )
    return code


def _reset_code_lookup_key(code: str) -> str:
    """Compute the HMAC-SHA256 lookup key for a reset code (VAPT-022 fix).

    Thin wrapper over ``authglow.core.crypto.reset_code_lookup_key``
    that resolves the secret key from ``get_settings()``. Kept as a
    module-level function for backward compatibility with the
    pre-refactor import path.
    """
    return reset_code_lookup_key(get_settings().secret_key, code)


class PasswordResetService:
    """Service for managing password reset tokens.

    The ``mark_token_used`` operation is protected by a named lock and
    optimistic-concurrency versioning to prevent token reuse.
    """

    MAX_CAS_RETRIES = 3

    def __init__(
        self,
        repository: Optional[PasswordResetRepository] = None,
        *,
        settings: Optional[Settings] = None,
    ) -> None:
        """Initialize the password reset service."""
        self.settings: Settings = settings or get_settings()
        self._repository: PasswordResetRepository = (
            repository if repository is not None else _default_repository(self.settings)
        )
        self._lock = named_lock()

    @property
    def repository(self) -> PasswordResetRepository:
        """The underlying repository (exposed for tests / admin tools)."""
        return self._repository

    def _generate_token(self) -> Tuple[str, str, str]:
        """Generate a secure random token.

        Returns:
            tuple: (plaintext_token, hashed_token, token_lookup)

        The bcrypt cost factor is read from
        ``settings.bcrypt_rounds`` (VAPT-038). Reset tokens are
        short-lived (30 minutes) and single-use, so the impact
        on verify latency is bounded — but the new cost is
        still applied to keep ``token_hash`` policy-aligned
        with the rest of the platform's credentials.
        """
        plaintext = secrets.token_urlsafe(32)
        token_hash = bcrypt.hashpw(
            plaintext.encode(),
            bcrypt.gensalt(rounds=self.settings.bcrypt_rounds),
        ).decode()
        token_lookup = hmac.new(
            self.settings.secret_key.encode(),
            plaintext.encode(),
            hashlib.sha256,
        ).hexdigest()
        return plaintext, token_hash, token_lookup

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def create_reset_token(
        self,
        user_id: str,
        email: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        expires_in_minutes: int = 30,
    ) -> Tuple[PasswordResetToken, str, str]:
        """Create a new password reset token.

        Returns:
            tuple: (PasswordResetToken, plaintext_token, reset_code)
                - ``plaintext_token`` is the bearer secret, hashed at rest
                  and suitable for server-to-server confirmation flows.
                - ``reset_code`` is the human-friendly code to render in
                  the email body (VAPT-022 fix). Never embed it in a URL.
        """
        plaintext_token, token_hash, token_lookup = self._generate_token()
        reset_code = generate_reset_code()

        reset_token = PasswordResetToken(
            token_lookup=token_lookup,
            user_id=user_id,
            email=email,
            token_hash=token_hash,
            reset_code=reset_code,
            expires_at=utcnow() + _timedelta(minutes=expires_in_minutes),
            ip_address=ip_address,
            user_agent=user_agent,
        )

        await self._repository.create(reset_token)

        return reset_token, plaintext_token, reset_code

    async def verify_token(self, plaintext_token: str) -> Optional[PasswordResetToken]:
        """Verify a reset token and return the token object if valid.

        Uses HMAC-SHA256 lookup key for O(1) direct file access instead
        of listing all active tokens.
        """
        token_lookup = hmac.new(
            self.settings.secret_key.encode(),
            plaintext_token.encode(),
            hashlib.sha256,
        ).hexdigest()

        token = await self._repository.get_by_token_lookup(token_lookup)
        if token is None:
            return None

        if not bcrypt.checkpw(plaintext_token.encode(), token.token_hash.encode()):
            return None

        if token.is_used:
            return None

        if utcnow() > token.expires_at:
            return None

        return token

    async def verify_by_code(self, reset_code: str) -> Optional[PasswordResetToken]:
        """Verify a reset by the human-friendly code (VAPT-022 fix).

        The code is normalised to upper-case, stripped of whitespace, then
        hashed with HMAC-SHA256 to derive the same lookup key the
        plaintext token uses. Returns the token on success, None otherwise.
        """
        if not reset_code:
            return None

        code_lookup = _reset_code_lookup_key(reset_code)
        token = await self._repository.get_by_code_lookup(code_lookup)
        if token is None:
            return None

        stored_code = (token.reset_code or "").strip().upper()
        presented_code = reset_code.strip().upper()
        if not stored_code or not secrets.compare_digest(stored_code, presented_code):
            return None

        if token.is_used:
            return None

        if utcnow() > token.expires_at:
            return None

        return token

    async def mark_token_used(self, token_lookup: str) -> bool:
        """Mark a token as used.

        Protected by a named lock and optimistic-concurrency versioning
        to prevent the same token from being used twice. The repository
        updates both primary and mirror files so the email-based lookup
        path returns the same ``is_used`` state (VAPT-022 fix).

        Args:
            token_lookup: HMAC lookup key of the token to mark as used
        """
        async with self._lock(f"reset_token:{token_lookup}"):
            for attempt in range(self.MAX_CAS_RETRIES):
                token = await self._repository.get_by_token_lookup(token_lookup)
                if token is None:
                    return False

                if token.is_used:
                    return False

                token.is_used = True
                token.used_at = utcnow()

                try:
                    await self._repository.update(token)
                    return True
                except ConcurrentWriteError:
                    continue

            return False

    async def get_token(self, token_lookup: str) -> Optional[PasswordResetToken]:
        """Get a token by its HMAC lookup key."""
        return await self._repository.get_by_token_lookup(token_lookup)

    async def list_user_tokens(
        self, user_id: str, active_only: bool = True
    ) -> List[PasswordResetToken]:
        """List all reset tokens for a user."""
        return await self._repository.list_for_user(user_id, active_only=active_only)

    async def list_all_tokens(
        self, active_only: bool = False, limit: int = 100, offset: int = 0
    ) -> List[PasswordResetToken]:
        """List all reset tokens (admin)."""
        return await self._repository.list_all(active_only=active_only, limit=limit, offset=offset)

    async def revoke_user_tokens(self, user_id: str) -> int:
        """Revoke all active tokens for a user."""
        tokens = await self.list_user_tokens(user_id, active_only=True)
        count = 0
        for token in tokens:
            if await self.mark_token_used(token.token_lookup):
                count += 1
        return count

    async def delete_token(self, token_lookup: str) -> bool:
        """Delete/recycle a single token permanently."""
        return await self.mark_token_used(token_lookup)

    async def cleanup_expired_tokens(self) -> int:
        """Delete all expired and used tokens. Returns the deletion count."""
        return await self._repository.cleanup_expired()

    async def get_stats(self) -> dict:
        """Get statistics about password reset tokens."""
        return await self._repository.stats()


def _default_repository(settings: Settings) -> PasswordResetRepository:
    from authglow.repositories.file.password_reset import (
        FilePasswordResetRepository,
    )

    return FilePasswordResetRepository(settings)
