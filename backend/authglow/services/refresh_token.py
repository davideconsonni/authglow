"""Refresh token service with automatic rotation."""

import hashlib
import hmac
import os
import secrets
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.refresh_token import RefreshToken


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

    def __init__(self):
        """Initialize refresh token service."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/refresh_tokens"
        self.storage_options = self.settings.get_storage_options()
        self._secret_bytes = self.settings.secret_key.encode()

        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(self.settings.storage_backend, **self.storage_options)

        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

    def _get_token_path(self, token_lookup: str) -> str:
        """Get path for refresh token file by its HMAC lookup key."""
        return f"{self.storage_path}/{token_lookup}.json"

    @property
    def _active_index_path(self) -> str:
        return f"{self.storage_path}/active_index.json"

    @property
    def _id_index_path(self) -> str:
        return f"{self.storage_path}/id_index.json"

    def _generate_token(self) -> Tuple[str, str, str]:
        """Generate a secure refresh token.

        Returns:
            tuple: (plaintext_token, token_hash, token_lookup)
        """
        plaintext = secrets.token_urlsafe(32)
        token_hash = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt()).decode()
        token_lookup = hmac.new(self._secret_bytes, plaintext.encode(), hashlib.sha256).hexdigest()
        return plaintext, token_hash, token_lookup

    async def _load_id_index(self) -> Dict[str, str]:
        """Load token_id → token_lookup mapping."""
        try:
            data = await self._afs.read_json(self._id_index_path)
            return dict(data)
        except Exception:
            return {}

    async def _save_id_index(self, token_id: str, token_lookup: str) -> None:
        """Add a token_id → token_lookup entry to the index."""
        async with self._lock("id_index"):
            idx = await self._load_id_index()
            idx[token_id] = token_lookup
            await self._afs.write_json(self._id_index_path, idx)

    async def _remove_from_id_index(self, token_id: str) -> None:
        """Remove a token_id from the id_index."""
        async with self._lock("id_index"):
            idx = await self._load_id_index()
            idx.pop(token_id, None)
            if idx:
                await self._afs.write_json(self._id_index_path, idx)
            else:
                try:
                    await self._afs.rm(self._id_index_path)
                except Exception:
                    pass

    async def _find_token_lookup(self, plaintext_token: str) -> str:
        """Compute the HMAC lookup key for a plaintext token."""
        return hmac.new(self._secret_bytes, plaintext_token.encode(), hashlib.sha256).hexdigest()

    async def _load_active_index(self) -> List[str]:
        try:
            data: Dict[str, Any] = await self._afs.read_json(self._active_index_path)
            result: List[str] = data.get("token_ids", [])
            return result
        except Exception:
            return []

    async def _save_active_index(self, token_ids: List[str]) -> None:
        if not token_ids:
            try:
                await self._afs.rm(self._active_index_path)
            except Exception:
                pass
        else:
            await self._afs.write_json(self._active_index_path, {"token_ids": token_ids})

    async def _add_to_active_index(self, token_id: str) -> None:
        async with self._lock("active_index"):
            existing = await self._load_active_index()
            if token_id not in existing:
                existing.append(token_id)
            await self._save_active_index(existing)

    async def _remove_from_active_index(self, token_id: str) -> None:
        async with self._lock("active_index"):
            existing = await self._load_active_index()
            if token_id in existing:
                existing.remove(token_id)
            await self._save_active_index(existing)

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
        plaintext, token_hash, token_lookup = self._generate_token()

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

        token_path = self._get_token_path(refresh_token.token_lookup)
        await self._afs.write_json(token_path, refresh_token.model_dump())

        await self._save_id_index(refresh_token.token_id, refresh_token.token_lookup)
        await self._add_to_active_index(refresh_token.token_id)

        return refresh_token

    async def get_refresh_token(self, token: str) -> Optional[RefreshToken]:
        """Get refresh token by plaintext token string using O(1) HMAC lookup.

        Args:
            token: Plaintext refresh token string

        Returns:
            RefreshToken if found and valid, None otherwise
        """
        token_lookup = await self._find_token_lookup(token)
        token_path = self._get_token_path(token_lookup)

        try:
            data = await self._afs.read_json(token_path)
            rt = RefreshToken(**data)
        except Exception:
            return None

        if not bcrypt.checkpw(token.encode(), rt.token_hash.encode()):
            return None

        rt.token = token  # restore the plaintext for callers
        return rt

    async def get_refresh_token_by_id(self, token_id: str) -> Optional[RefreshToken]:
        """Get refresh token by token_id using the id_index for O(1) lookup.

        Args:
            token_id: Token ID

        Returns:
            RefreshToken if found, None otherwise
        """
        idx = await self._load_id_index()
        token_lookup = idx.get(token_id)
        if not token_lookup:
            return None

        try:
            token_path = self._get_token_path(token_lookup)
            data = await self._afs.read_json(token_path)
            return RefreshToken(**data)
        except Exception:
            return None

    async def validate_and_rotate(
        self, token: str, client_id: str, ip_address: Optional[str] = None
    ) -> Tuple[Optional[RefreshToken], Optional[str]]:
        """Validate a refresh token and automatically rotate it.

        Protected by a named lock on the token_lookup to prevent concurrent
        rotations, and by optimistic-concurrency versioning.

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
            for attempt in range(self.MAX_CAS_RETRIES):
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

                token_path = self._get_token_path(rt.token_lookup)
                try:
                    token_data = rt.model_dump()
                    data, version = await self._afs.read_json_versioned(token_path)
                    await self._afs.write_json_versioned(token_path, token_data, version)
                except ConcurrentWriteError:
                    continue

                await self._remove_from_active_index(rt.token_id)

                return new_token, None

            return None, "Concurrent modification - please retry"

    async def revoke_token(self, token: str, reason: Optional[str] = None) -> bool:
        """Revoke a specific refresh token."""
        rt = await self.get_refresh_token(token)
        if not rt:
            return False

        async with self._lock(f"refresh_token:{rt.token_lookup}"):
            rt.revoked = True
            rt.revoked_at = utcnow()
            rt.revoked_reason = reason

            token_path = self._get_token_path(rt.token_lookup)
            try:
                await self._afs.write_json(token_path, rt.model_dump())
                await self._remove_from_active_index(rt.token_id)
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

            token_path = self._get_token_path(rt.token_lookup)
            try:
                await self._afs.write_json(token_path, rt.model_dump())
                await self._remove_from_active_index(rt.token_id)
                return True
            except Exception:
                return False

    async def _revoke_token_family(self, token: RefreshToken) -> int:
        """Revoke all tokens in a family (security measure)."""
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

                token_path = self._get_token_path(rt_recheck.token_lookup)
                await self._afs.write_json(token_path, rt_recheck.model_dump())
                await self._remove_from_active_index(token_id)
                revoked_count += 1

                if rt_recheck.replaced_by:
                    revoked_count += await self._revoke_descendants(rt_recheck.replaced_by)

        return revoked_count

    async def revoke_user_tokens(self, user_id: str, client_id: Optional[str] = None) -> int:
        """Revoke all refresh tokens for a user."""
        revoked_count = 0
        try:
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    rt = RefreshToken(**data)

                    if rt.user_id != user_id:
                        continue
                    if client_id and rt.client_id != client_id:
                        continue
                    if rt.revoked:
                        continue

                    async with self._lock(f"refresh_token:{rt.token_lookup}"):
                        rt_locked = await self.get_refresh_token_by_id(rt.token_id)
                        if rt_locked and not rt_locked.revoked:
                            rt_locked.revoked = True
                            rt_locked.revoked_at = utcnow()
                            rt_locked.revoked_reason = "Revoked by user or admin"

                            await self._afs.write_json(file_path, rt_locked.model_dump())
                            await self._remove_from_active_index(rt_locked.token_id)
                            revoked_count += 1

                except Exception:
                    continue

        except Exception:
            pass

        return revoked_count

    async def list_all_tokens(
        self,
        active_only: bool = False,
        limit: int = 100,
        offset: int = 0,
        user_id: Optional[str] = None,
    ) -> Tuple[List[RefreshToken], int]:
        """List tokens with optional active-only filter and pagination."""
        tokens: List[RefreshToken] = []
        try:
            if active_only:
                active_ids = await self._load_active_index()
                idx = await self._load_id_index()

                for tid in active_ids:
                    try:
                        lookup = idx.get(tid)
                        if not lookup:
                            continue
                        data = await self._afs.read_json(self._get_token_path(lookup))
                        rt = RefreshToken(**data)

                        if rt.revoked or utcnow() > rt.expires_at:
                            continue
                        if user_id and rt.user_id != user_id:
                            continue

                        tokens.append(rt)
                    except Exception:
                        continue
            else:
                pattern = f"{self.storage_path}/*.json"
                files = await self._afs.glob(pattern)

                for file_path in files:
                    try:
                        data = await self._afs.read_json(file_path)
                        rt = RefreshToken(**data)

                        if user_id and rt.user_id != user_id:
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
        """Delete all expired refresh tokens."""
        deleted = 0
        try:
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    rt = RefreshToken(**data)

                    if utcnow() > rt.expires_at:
                        await self._afs.rm(file_path)
                        await self._remove_from_id_index(rt.token_id)
                        await self._remove_from_active_index(rt.token_id)
                        deleted += 1

                except Exception:
                    continue

        except Exception:
            pass

        return deleted
