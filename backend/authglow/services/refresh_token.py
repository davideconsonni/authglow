"""Refresh token service with automatic rotation.

Persistence is delegated to a single :class:`RefreshTokenRepository`.
The pre-refactor service built its own fsspec/AsyncFileSystem
plumbing in ``__init__`` and would have crashed on any non-``file``
backend (``s3`` / ``gcs`` / ``abfs``) with a confusing ``ValueError``
from fsspec. The refactored service routes through the standard
``BaseFileRepository._init_filesystem`` via the factory, which
honours ``Settings.storage_backend``.

Pure-crypto helpers (``_generate_token`` for ``secrets + bcrypt + HMAC``
generation, ``_find_token_lookup`` for HMAC of the plaintext) stay
in the service because they have no I/O and because the HMAC secret
key is read from ``Settings``. The in-process ``named_lock`` wraps
read-modify-write critical sections (rotation, revoke, family
revocation) so concurrent updates from the same process are
serialised; cross-process safety is delegated to the repository's
optimistic-concurrency ``_version`` checks, which surface as
:class:`ConcurrentWriteError` and are retried inside the lock.
"""

import asyncio
import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import List, Optional, Tuple

from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.refresh_token import RefreshToken
from authglow.repositories.protocols import RefreshTokenRepository
from authglow.services.password import hash_password, verify_password_async


class RefreshTokenService:
    """Service for managing refresh tokens with rotation.

    Tokens are stored using the PasswordResetToken pattern:
    - ``token_lookup`` = HMAC-SHA256(secret_key, plaintext)  → filename (O(1) lookup)
    - ``token_hash`` = bcrypt(plaintext)                       → verification
    - The plaintext token is NEVER persisted to disk.

    Security-critical read-modify-write operations are protected by
    named locks (in-process) and optimistic-concurrency versioning
    (cross-process defense-in-depth).
    """

    MAX_CAS_RETRIES = 3

    def __init__(self, repository: Optional[RefreshTokenRepository] = None):
        """Initialize refresh token service with settings + repository.

        ``repository`` defaults to ``None`` and is resolved lazily via
        :func:`get_refresh_token_repository` (which returns a
        :class:`FileRefreshTokenRepository`). Tests can pass a stub or
        an in-memory implementation directly.

        The factory receives the already-resolved ``self.settings`` so
        the repository's filesystem binds to the same
        ``Settings.storage_path`` the service uses — otherwise
        :class:`BaseFileRepository` would hit the ``lru_cache``'d
        global ``get_settings`` singleton and bypass the per-test
        settings patch.
        """
        from authglow.repositories.dependencies import (
            get_refresh_token_repository,
        )

        self.settings = get_settings()
        self._secret_bytes = self.settings.secret_key.encode()
        self._repo = repository or get_refresh_token_repository(settings=self.settings)
        self._lock = named_lock()

    # ------------------------------------------------------------------
    # Pure crypto helpers — no I/O
    # ------------------------------------------------------------------

    def _generate_token(self) -> Tuple[str, str, str]:
        """Generate a secure refresh token.

        Returns:
            tuple: (plaintext_token, token_hash, token_lookup)
        """
        plaintext = secrets.token_urlsafe(32)
        token_hash = hash_password(plaintext)
        token_lookup = hmac.new(self._secret_bytes, plaintext.encode(), hashlib.sha256).hexdigest()
        return plaintext, token_hash, token_lookup

    def _find_token_lookup(self, plaintext_token: str) -> str:
        """Compute the HMAC lookup key for a plaintext token."""
        return hmac.new(self._secret_bytes, plaintext_token.encode(), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # CRUD + listing — persistence
    # ------------------------------------------------------------------

    async def create_refresh_token(
        self,
        user_id: str,
        client_id: str,
        scopes: List[str],
        issued_ip: Optional[str] = None,
        expires_in_days: int = 30,
        parent_token_id: Optional[str] = None,
    ) -> RefreshToken:
        """Create a new refresh token.

        Only the bcrypt hash and HMAC lookup key are persisted to disk.
        The plaintext token is returned to the caller for delivery to the client.
        """
        plaintext, token_hash, token_lookup = await asyncio.to_thread(self._generate_token)

        refresh_token = RefreshToken(
            token_hash=token_hash,
            token_lookup=token_lookup,
            token=plaintext,
            user_id=user_id,
            client_id=client_id,
            scopes=scopes,
            expires_at=utcnow() + timedelta(days=expires_in_days),
            issued_ip=issued_ip,
            parent_token_id=parent_token_id,
        )

        await self._repo.create(refresh_token)
        await self._repo.add_to_id_index(refresh_token.token_id, refresh_token.token_lookup)
        await self._repo.add_to_active_index(refresh_token.token_id)

        return refresh_token

    async def get_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """Get refresh token by plaintext token string using O(1) HMAC lookup."""
        token_lookup = self._find_token_lookup(token)
        rt = await self._repo.get_by_lookup(token_lookup)
        if rt is None:
            return None
        if not await verify_password_async(token, rt.token_hash):
            return None
        rt.token = token  # restore the plaintext for callers
        return rt

    async def get_refresh_token_by_id(self, token_id: str) -> Optional[RefreshToken]:
        """Get refresh token by token_id using the id_index for O(1) lookup."""
        return await self._repo.get_by_id(token_id)

    # ------------------------------------------------------------------
    # Rotation — guarded by named_lock + CAS retry
    # ------------------------------------------------------------------

    async def validate_and_rotate(
        self, token: str, client_id: str, ip_address: Optional[str] = None
    ) -> Tuple[Optional[RefreshToken], Optional[str]]:
        """Validate a refresh token and automatically rotate it.

        Protected by a named lock on the token_lookup to prevent
        concurrent rotations, and by optimistic-concurrency versioning.

        Returns:
            Tuple of (new_refresh_token, error_message)
        """
        rt = await self.get_refresh_token(token)

        if not rt:
            return None, "Invalid refresh token"

        if rt.revoked:
            return None, "Token has been revoked"

        if rt.client_id != client_id:
            return None, "Client mismatch"

        if utcnow() > rt.expires_at:
            return None, "Token expired"

        if rt.used:
            await self._revoke_token_family(rt)
            return None, "Token reuse detected - all tokens in family revoked"

        async with self._lock(f"refresh_token:{rt.token_lookup}"):
            for _ in range(self.MAX_CAS_RETRIES):
                rt = await self.get_refresh_token_by_id(rt.token_id)
                if rt is None:
                    return None, "Invalid refresh token"

                if rt.revoked:
                    return None, "Token has been revoked"
                if rt.used:
                    await self._revoke_token_family(rt)
                    return None, "Token reuse detected - all tokens in family revoked"

                rt.used = True
                rt.used_at = utcnow()
                rt.last_used_ip = ip_address

                new_token = await self.create_refresh_token(
                    user_id=rt.user_id,
                    client_id=rt.client_id,
                    scopes=rt.scopes,
                    issued_ip=ip_address,
                    parent_token_id=rt.token_id,
                )

                rt.replaced_by = new_token.token_id

                try:
                    await self._repo.update(rt)
                except ConcurrentWriteError:
                    continue

                await self._repo.remove_from_active_index(rt.token_id)
                return new_token, None

            return None, "Concurrent modification - please retry"

    # ------------------------------------------------------------------
    # Revocation — guarded by named_lock
    # ------------------------------------------------------------------

    async def revoke_token(self, token: str, reason: Optional[str] = None) -> bool:
        """Revoke a specific refresh token."""
        rt = await self.get_refresh_token(token)
        if not rt:
            return False

        async with self._lock(f"refresh_token:{rt.token_lookup}"):
            rt.revoked = True
            rt.revoked_at = utcnow()
            rt.revoked_reason = reason

            try:
                await self._repo.update(rt)
                await self._repo.remove_from_active_index(rt.token_id)
                return True
            except Exception:
                return False

    async def revoke_token_by_id(self, token_id: str, reason: Optional[str] = None) -> bool:
        """Revoke a refresh token by its database ID.

        Unlike ``revoke_token``, this does not require the plaintext token
        (which is never persisted to disk). It looks up the token by
        ``token_id`` via the id_index.
        """
        rt = await self.get_refresh_token_by_id(token_id)
        if not rt:
            return False

        async with self._lock(f"refresh_token:{rt.token_lookup}"):
            rt.revoked = True
            rt.revoked_at = utcnow()
            rt.revoked_reason = reason

            try:
                await self._repo.update(rt)
                await self._repo.remove_from_active_index(rt.token_id)
                return True
            except Exception:
                return False

    async def _revoke_token_family(self, token: RefreshToken) -> int:
        """Revoke all tokens in a family (security measure).

        Walks the parent chain to the root, then recursively
        revokes every descendant via ``_revoke_descendants``.
        """
        current = token
        while current.parent_token_id:
            parent = await self.get_refresh_token_by_id(current.parent_token_id)
            if not parent:
                break
            current = parent

        return await self._revoke_descendants(current.token_id)

    async def _revoke_descendants(self, token_id: str) -> int:
        """Recursively revoke a token and all its descendants."""
        revoked_count = 0

        rt = await self.get_refresh_token_by_id(token_id)
        if not rt:
            return revoked_count

        async with self._lock(f"refresh_token:{rt.token_lookup}"):
            rt_recheck = await self.get_refresh_token_by_id(token_id)
            if rt_recheck and not rt_recheck.revoked:
                rt_recheck.revoked = True
                rt_recheck.revoked_at = utcnow()
                rt_recheck.revoked_reason = "Token family revoked due to security violation"

                await self._repo.update(rt_recheck)
                await self._repo.remove_from_active_index(token_id)
                revoked_count += 1

                if rt_recheck.replaced_by:
                    revoked_count += await self._revoke_descendants(rt_recheck.replaced_by)

        return revoked_count

    async def revoke_user_tokens(self, user_id: str, client_id: Optional[str] = None) -> int:
        """Revoke all refresh tokens for a user."""
        return await self._repo.revoke_user_tokens(user_id=user_id, client_id=client_id)

    # ------------------------------------------------------------------
    # Listing + cleanup
    # ------------------------------------------------------------------

    async def list_all_tokens(
        self,
        active_only: bool = False,
        limit: int = 100,
        offset: int = 0,
        user_id: Optional[str] = None,
    ) -> Tuple[List[RefreshToken], int]:
        """List tokens with optional active-only filter and pagination."""
        return await self._repo.list_all(
            limit=limit, offset=offset, user_id=user_id, active_only=active_only
        )

    async def cleanup_expired_tokens(self) -> int:
        """Delete all expired refresh tokens."""
        return await self._repo.cleanup_expired()
