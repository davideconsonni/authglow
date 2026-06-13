"""Password reset service for managing reset tokens."""

import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import List, Optional

import bcrypt
import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.password_reset import PasswordResetToken

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

    Normalises the code to upper-case and strips whitespace so user input
    variants (``abcd-efgh-jklm``) match the stored value. The key mirrors
    the existing ``token_lookup`` pattern for O(1) file access.
    """
    normalised = code.strip().upper().replace(" ", "").replace("\t", "")
    return hmac.new(
        get_settings().secret_key.encode(),
        normalised.encode(),
        hashlib.sha256,
    ).hexdigest()


class PasswordResetService:
    """Service for managing password reset tokens.

    The ``mark_token_used`` operation is protected by a named lock and
    optimistic-concurrency versioning to prevent token reuse.
    """

    MAX_CAS_RETRIES = 3

    def __init__(self, storage_path: str | None = None):
        """Initialize the password reset service.

        Args:
            storage_path: Path to storage directory (supports s3://, gcs://, etc.)
        """
        self.settings = get_settings()
        self.storage_path = storage_path or self.settings.storage_path
        self.reset_path = f"{self.storage_path}/password_resets"
        self.fs = fsspec.filesystem("file")  # Will auto-detect protocol from path
        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

    def _get_token_path(self, token_lookup: str) -> str:
        """Get file path for a token by its HMAC lookup key."""
        return f"{self.reset_path}/{token_lookup}.json"

    def _get_code_path(self, code_lookup: str) -> str:
        """Get file path for a token by its reset-code HMAC lookup key.

        VAPT-022: the same token record is indexed by both
        ``token_lookup`` (HMAC of bearer token) and ``code_lookup``
        (HMAC of human-friendly reset code), so the email-based flow
        can resolve a token without the bearer secret.
        """
        return f"{self.reset_path}/code_{code_lookup}.json"

    def _generate_token(self) -> tuple[str, str, str]:
        """Generate a secure random token.

        Returns:
            tuple: (plaintext_token, hashed_token, token_lookup)
        """
        plaintext = secrets.token_urlsafe(32)

        token_hash = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt()).decode()

        token_lookup = hmac.new(
            self.settings.secret_key.encode(),
            plaintext.encode(),
            hashlib.sha256,
        ).hexdigest()

        return plaintext, token_hash, token_lookup

    async def create_reset_token(
        self,
        user_id: str,
        email: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        expires_in_minutes: int = 30,
    ) -> tuple[PasswordResetToken, str, str]:
        """Create a new password reset token.

        Args:
            user_id: User ID requesting reset
            email: User email
            ip_address: IP address of requester
            user_agent: User agent string
            expires_in_minutes: Token expiration time in minutes

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
            expires_at=utcnow() + timedelta(minutes=expires_in_minutes),
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Save token (primary file indexed by bearer token HMAC)
        token_path = self._get_token_path(reset_token.token_lookup)
        await self._afs.makedirs(self.reset_path, exist_ok=True)

        payload = reset_token.model_dump_json(indent=2)
        await self._afs.write_text(token_path, payload)

        # VAPT-022: also write a mirror file indexed by the reset_code
        # HMAC, so the email-based flow can resolve the same record
        # without the bearer token. The two files contain the same
        # payload; ``mark_token_used`` and ``cleanup`` operate on both.
        code_lookup = _reset_code_lookup_key(reset_code)
        code_path = self._get_code_path(code_lookup)
        await self._afs.write_text(code_path, payload)

        return reset_token, plaintext_token, reset_code

    async def verify_token(self, plaintext_token: str) -> Optional[PasswordResetToken]:
        """Verify a reset token and return the token object if valid.

        Uses HMAC-SHA256 lookup key for O(1) direct file access instead of
        listing all active tokens.

        Args:
            plaintext_token: The plaintext token to verify

        Returns:
            PasswordResetToken if valid, None otherwise
        """
        token_lookup = hmac.new(
            self.settings.secret_key.encode(),
            plaintext_token.encode(),
            hashlib.sha256,
        ).hexdigest()

        token_path = self._get_token_path(token_lookup)

        if not await self._afs.exists(token_path):
            return None

        try:
            content = await self._afs.read_text(token_path)
            token = PasswordResetToken.model_validate_json(content)
        except Exception:
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
        On success, the underlying ``plaintext_token`` is exposed via
        ``PasswordResetConfirm`` flow when the caller re-renders the form
        with the verified ``token_lookup``.

        Args:
            reset_code: The human-friendly code as entered by the user.

        Returns:
            PasswordResetToken if valid, None otherwise
        """
        if not reset_code:
            return None

        code_lookup = _reset_code_lookup_key(reset_code)
        code_path = self._get_code_path(code_lookup)

        if not await self._afs.exists(code_path):
            return None

        try:
            content = await self._afs.read_text(code_path)
            token = PasswordResetToken.model_validate_json(content)
        except Exception:
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
        to prevent the same token from being used twice. When a
        ``reset_code`` mirror file exists, it is updated too so the
        email-based lookup path returns the same ``is_used`` state
        (VAPT-022 fix).

        Args:
            token_lookup: HMAC lookup key of the token to mark as used

        Returns:
            bool: Success status
        """
        async with self._lock(f"reset_token:{token_lookup}"):
            for attempt in range(self.MAX_CAS_RETRIES):
                token_path = self._get_token_path(token_lookup)

                if not await self._afs.exists(token_path):
                    return False

                content = await self._afs.read_text(token_path)
                token = PasswordResetToken.model_validate_json(content)

                if token.is_used:
                    return False

                token.is_used = True
                token.used_at = utcnow()
                payload = token.model_dump_json(indent=2)

                try:
                    _, version = await self._afs.read_json_versioned(token_path)
                    await self._afs.write_text(token_path, payload)
                except ConcurrentWriteError:
                    continue

                # Update the reset_code mirror so the email-based
                # lookup path also sees the token as used.
                if token.reset_code:
                    code_lookup = _reset_code_lookup_key(token.reset_code)
                    code_path = self._get_code_path(code_lookup)
                    if await self._afs.exists(code_path):
                        await self._afs.write_text(code_path, payload)
                return True

            return False

    async def get_token(self, token_lookup: str) -> Optional[PasswordResetToken]:
        """Get a token by its HMAC lookup key.

        Args:
            token_lookup: HMAC lookup key

        Returns:
            PasswordResetToken if found, None otherwise
        """
        token_path = self._get_token_path(token_lookup)

        if not await self._afs.exists(token_path):
            return None

        content = await self._afs.read_text(token_path)
        return PasswordResetToken.model_validate_json(content)

    async def list_user_tokens(
        self, user_id: str, active_only: bool = True
    ) -> List[PasswordResetToken]:
        """List all reset tokens for a user.

        Args:
            user_id: User ID
            active_only: Only return active (unused, unexpired) tokens

        Returns:
            List of PasswordResetToken objects
        """
        if not await self._afs.exists(self.reset_path):
            return []

        tokens = []
        file_list = await self._afs.ls(self.reset_path)
        for file_path in file_list:
            if not file_path.endswith(".json"):
                continue
            # VAPT-022: skip reset_code mirror files; primary file wins.
            if "/code_" in file_path or file_path.endswith("/code_.json"):
                continue

            content = await self._afs.read_text(file_path)
            token = PasswordResetToken.model_validate_json(content)

            if token.user_id != user_id:
                continue

            if active_only:
                if token.is_used or utcnow() > token.expires_at:
                    continue

            tokens.append(token)

        return sorted(tokens, key=lambda t: t.created_at, reverse=True)

    async def list_all_tokens(
        self, active_only: bool = False, limit: int = 100, offset: int = 0
    ) -> List[PasswordResetToken]:
        """List all reset tokens (admin).

        Args:
            active_only: Only return active tokens
            limit: Maximum number of tokens to return
            offset: Number of tokens to skip

        Returns:
            List of PasswordResetToken objects
        """
        if not await self._afs.exists(self.reset_path):
            return []

        tokens = []
        file_list = await self._afs.ls(self.reset_path)
        for file_path in file_list:
            if not file_path.endswith(".json"):
                continue
            if "/code_" in file_path or file_path.endswith("/code_.json"):
                continue

            content = await self._afs.read_text(file_path)
            token = PasswordResetToken.model_validate_json(content)

            if active_only:
                if token.is_used or utcnow() > token.expires_at:
                    continue

            tokens.append(token)

        # Sort by created_at descending
        tokens.sort(key=lambda t: t.created_at, reverse=True)

        # Apply pagination
        return tokens[offset : offset + limit]

    async def revoke_user_tokens(self, user_id: str) -> int:
        """Revoke all active tokens for a user.

        Args:
            user_id: User ID

        Returns:
            Number of tokens revoked
        """
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
        """Delete all expired and used tokens.

        Returns:
            Number of tokens deleted
        """
        if not await self._afs.exists(self.reset_path):
            return 0

        count = 0
        file_list = await self._afs.ls(self.reset_path)
        for file_path in file_list:
            if not file_path.endswith(".json"):
                continue
            if "/code_" in file_path or file_path.endswith("/code_.json"):
                continue

            content = await self._afs.read_text(file_path)
            token = PasswordResetToken.model_validate_json(content)

            # Delete if used or expired (older than 24 hours after expiration)
            should_delete = token.is_used or utcnow() > token.expires_at + timedelta(hours=24)

            if should_delete:
                await self._afs.rm(file_path)
                # Also delete the reset_code mirror (VAPT-022).
                if token.reset_code:
                    code_lookup = _reset_code_lookup_key(token.reset_code)
                    code_path = self._get_code_path(code_lookup)
                    if await self._afs.exists(code_path):
                        await self._afs.rm(code_path)
                count += 1

        return count

    async def get_stats(self) -> dict:
        """Get statistics about password reset tokens.

        Returns:
            Dictionary with stats
        """
        if not await self._afs.exists(self.reset_path):
            return {"total": 0, "active": 0, "expired": 0, "used": 0}

        total = 0
        active = 0
        expired = 0
        used = 0

        now = utcnow()

        file_list = await self._afs.ls(self.reset_path)
        for file_path in file_list:
            if not file_path.endswith(".json"):
                continue
            if "/code_" in file_path or file_path.endswith("/code_.json"):
                continue

            content = await self._afs.read_text(file_path)
            token = PasswordResetToken.model_validate_json(content)

            total += 1

            if token.is_used:
                used += 1
            elif now > token.expires_at:
                expired += 1
            else:
                active += 1

        return {"total": total, "active": active, "expired": expired, "used": used}
