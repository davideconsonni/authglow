"""Refresh token service with automatic rotation."""

import json
import os
from datetime import datetime, timedelta
from typing import Optional, List
import fsspec

from authglow.core.config import get_settings
from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import named_lock, ConcurrentWriteError
from authglow.core.datetime import utcnow
from authglow.models.refresh_token import RefreshToken


class RefreshTokenService:
    """Service for managing refresh tokens with rotation.

    Security-critical read-modify-write operations are protected by
    named locks (in-process) and optimistic-concurrency versioning
    (cross-process defense-in-depth).
    """

    MAX_CAS_RETRIES = 3

    def __init__(self):
        """Initialize refresh token service."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/refresh_tokens"
        self.storage_options = self.settings.get_storage_options()

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

    def _get_token_path(self, token_id: str) -> str:
        """Get path for refresh token file."""
        return f"{self.storage_path}/{token_id}.json"

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

        Args:
            user_id: User ID
            client_id: OAuth2 client ID
            scopes: List of scopes
            issued_ip: IP address where token was issued
            expires_in_days: Days until expiration
            parent_token_id: ID of parent token (for rotation)

        Returns:
            RefreshToken object
        """
        refresh_token = RefreshToken(
            user_id=user_id,
            client_id=client_id,
            scopes=scopes,
            expires_at=utcnow() + timedelta(days=expires_in_days),
            issued_ip=issued_ip,
            parent_token_id=parent_token_id,
        )

        # Save token
        token_path = self._get_token_path(refresh_token.token_id)
        await self._afs.write_json(token_path, refresh_token.model_dump())

        return refresh_token

    async def get_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """Get refresh token by token string.

        Args:
            token: Refresh token string

        Returns:
            RefreshToken if found, None otherwise
        """
        try:
            # Search through all tokens to find matching token string
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    rt = RefreshToken(**data)

                    if rt.token == token:
                        return rt

                except Exception:
                    continue

            return None

        except Exception:
            return None

    async def get_refresh_token_by_id(self, token_id: str) -> Optional[RefreshToken]:
        """Get refresh token by token_id.

        Args:
            token_id: Token ID

        Returns:
            RefreshToken if found, None otherwise
        """
        try:
            token_path = self._get_token_path(token_id)
            data = await self._afs.read_json(token_path)
            return RefreshToken(**data)
        except Exception:
            return None

    async def validate_and_rotate(
        self, token: str, client_id: str, ip_address: Optional[str] = None
    ) -> tuple[Optional[RefreshToken], Optional[str]]:
        """Validate a refresh token and automatically rotate it.

        This implements refresh token rotation for enhanced security.
        If the token is valid, it's marked as used and a new one is issued.
        If a token is reused (already marked as used), the entire token family is revoked.

        Protected by a named lock on the token_id to prevent concurrent rotations,
        and by optimistic-concurrency versioning as a cross-process safeguard.

        Args:
            token: Refresh token string
            client_id: OAuth2 client ID
            ip_address: IP address making the request

        Returns:
            Tuple of (new_refresh_token, error_message)
            If error_message is not None, new_refresh_token will be None
        """
        # Get the refresh token (read outside lock — idempotent)
        rt = await self.get_refresh_token(token)

        if not rt:
            return None, "Invalid refresh token"

        # Check if revoked
        if rt.revoked:
            return None, "Token has been revoked"

        # Check client_id
        if rt.client_id != client_id:
            return None, "Client mismatch"

        # Check if expired
        if utcnow() > rt.expires_at:
            return None, "Token expired"

        # SECURITY: Check if token was already used (replay attack detection)
        if rt.used:
            # Token reuse detected! Revoke entire token family
            await self._revoke_token_family(rt)
            return None, "Token reuse detected - all tokens in family revoked"

        # Acquire per-token lock for the RMW
        async with self._lock(f"refresh_token:{rt.token_id}"):
            for attempt in range(self.MAX_CAS_RETRIES):
                # Re-read inside lock to get latest version
                rt = await self.get_refresh_token_by_id(rt.token_id)
                if rt is None:
                    return None, "Invalid refresh token"

                if rt.revoked:
                    return None, "Token has been revoked"
                if rt.used:
                    await self._revoke_token_family(rt)
                    return None, "Token reuse detected - all tokens in family revoked"

                # Mark current token as used
                rt.used = True
                rt.used_at = utcnow()
                rt.last_used_ip = ip_address

                # Create new refresh token (rotation)
                new_token = await self.create_refresh_token(
                    user_id=rt.user_id,
                    client_id=rt.client_id,
                    scopes=rt.scopes,
                    issued_ip=ip_address,
                    parent_token_id=rt.token_id,
                )

                # Update old token with replacement info
                rt.replaced_by = new_token.token_id

                # CAS write — fail if another process already modified this token
                token_path = self._get_token_path(rt.token_id)
                try:
                    token_data = rt.model_dump()
                    data, version = await self._afs.read_json_versioned(token_path)
                    await self._afs.write_json_versioned(
                        token_path, token_data, version
                    )
                except ConcurrentWriteError:
                    continue

                return new_token, None

            return None, "Concurrent modification - please retry"

    async def revoke_token(self, token: str, reason: Optional[str] = None) -> bool:
        """Revoke a specific refresh token.

        Args:
            token: Refresh token string
            reason: Reason for revocation

        Returns:
            True if revoked successfully, False otherwise
        """
        rt = await self.get_refresh_token(token)
        if not rt:
            return False

        async with self._lock(f"refresh_token:{rt.token_id}"):
            rt.revoked = True
            rt.revoked_at = utcnow()
            rt.revoked_reason = reason

            # Save updated token
            token_path = self._get_token_path(rt.token_id)
            try:
                await self._afs.write_json(token_path, rt.model_dump())
                return True
            except Exception:
                return False

    async def _revoke_token_family(self, token: RefreshToken) -> int:
        """Revoke all tokens in a family (security measure).

        This is called when token reuse is detected.

        Args:
            token: Any token in the family

        Returns:
            Number of tokens revoked
        """
        # Find the root token (no parent)
        current = token
        while current.parent_token_id:
            parent = await self.get_refresh_token_by_id(current.parent_token_id)
            if not parent:
                break
            current = parent

        root_token_id = current.token_id

        # Revoke all tokens starting from root
        return await self._revoke_descendants(root_token_id)

    async def _revoke_descendants(self, token_id: str) -> int:
        """Recursively revoke a token and all its descendants.

        Args:
            token_id: Token ID to start from

        Returns:
            Number of tokens revoked
        """
        revoked_count = 0

        # Revoke this token
        async with self._lock(f"refresh_token:{token_id}"):
            rt = await self.get_refresh_token_by_id(token_id)
            if rt and not rt.revoked:
                rt.revoked = True
                rt.revoked_at = utcnow()
                rt.revoked_reason = "Token family revoked due to security violation"

                token_path = self._get_token_path(token_id)
                await self._afs.write_json(token_path, rt.model_dump())

                revoked_count += 1

                # If this token has a replacement, revoke that too
                if rt.replaced_by:
                    pass

        # Revoke children outside the lock to avoid nesting
        if rt and rt.replaced_by:
            revoked_count += await self._revoke_descendants(rt.replaced_by)

        return revoked_count

    async def revoke_user_tokens(
        self, user_id: str, client_id: Optional[str] = None
    ) -> int:
        """Revoke all refresh tokens for a user.

        Args:
            user_id: User ID
            client_id: Optional client ID to filter by

        Returns:
            Number of tokens revoked
        """
        revoked_count = 0
        try:
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    rt = RefreshToken(**data)

                    # Check if matches user
                    if rt.user_id != user_id:
                        continue

                    # Check if matches client (if specified)
                    if client_id and rt.client_id != client_id:
                        continue

                    # Skip if already revoked
                    if rt.revoked:
                        continue

                    async with self._lock(f"refresh_token:{rt.token_id}"):
                        # Re-read inside lock
                        rt = await self.get_refresh_token_by_id(rt.token_id)
                        if rt and not rt.revoked:
                            rt.revoked = True
                            rt.revoked_at = utcnow()
                            rt.revoked_reason = "Revoked by user or admin"

                            await self._afs.write_json(file_path, rt.model_dump())

                            revoked_count += 1

                except Exception:
                    continue

        except Exception:
            pass

        return revoked_count

    async def list_all_tokens(
        self, active_only: bool = False, limit: int = 100, offset: int = 0
    ) -> tuple[list[RefreshToken], int]:
        """List tokens with optional active-only filter and pagination.

        Returns a tuple of (token_page, total_matching_count).
        """
        tokens = []
        try:
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    rt = RefreshToken(**data)

                    if active_only:
                        if rt.revoked or utcnow() > rt.expires_at:
                            continue

                    tokens.append(rt)

                except Exception:
                    continue

            tokens.sort(key=lambda t: t.created_at, reverse=True)
            total = len(tokens)
            page = tokens[offset : offset + limit]
            return page, total

        except Exception:
            return [], 0

    async def cleanup_expired_tokens(self) -> int:
        """Delete all expired refresh tokens.

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
                    rt = RefreshToken(**data)

                    # Delete if expired
                    if utcnow() > rt.expires_at:
                        await self._afs.rm(file_path)
                        deleted += 1

                except Exception:
                    continue

        except Exception:
            pass

        return deleted
