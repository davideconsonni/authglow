"""API Key storage and management service."""

import os
import secrets
from datetime import datetime, timedelta
from typing import Any, List, Optional

import bcrypt
import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.api_key import APIKey, APIKeyCreate

PREFIX_LENGTH = 12


class APIKeyLockedException(Exception):
    """Raised when an API key is temporarily locked due to brute-force attempts."""

    def __init__(self, key_id: str, locked_until: datetime):
        self.key_id = key_id
        self.locked_until = locked_until
        super().__init__(f"API key {key_id} is locked until {locked_until.isoformat()}")


class APIKeyService:
    """Service for managing API keys."""

    def __init__(self):
        """Initialize API key service."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/api_keys"
        self.index_path = f"{self.storage_path}/index"
        self.storage_options = self.settings.get_storage_options()

        # Initialize filesystem
        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            os.makedirs(self.index_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(self.settings.storage_backend, **self.storage_options)

        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

    async def _load_prefix_index(self, prefix: str) -> List[str]:
        """Load key_ids for a given prefix from the index."""
        index_file = f"{self.index_path}/{prefix}.json"
        try:
            data: dict[str, Any] = await self._afs.read_json(index_file)
            result: list[str] = data.get("key_ids", [])
            return result
        except Exception:
            return []

    async def _save_prefix_index(self, api_key: APIKey) -> None:
        """Add key_id to the prefix index for O(1) lookups."""
        async with self._lock(f"prefix_index:{api_key.key_prefix}"):
            existing_ids = await self._load_prefix_index(api_key.key_prefix)
            if api_key.key_id not in existing_ids:
                existing_ids.append(api_key.key_id)
            index_file = f"{self.index_path}/{api_key.key_prefix}.json"
            await self._afs.write_json(index_file, {"key_ids": existing_ids})

    async def _remove_from_prefix_index(self, prefix: str, key_id: str) -> None:
        """Remove a key_id from the prefix index."""
        async with self._lock(f"prefix_index:{prefix}"):
            existing_ids = await self._load_prefix_index(prefix)
            if key_id in existing_ids:
                existing_ids.remove(key_id)
            index_file = f"{self.index_path}/{prefix}.json"
            if not existing_ids:
                try:
                    await self._afs.rm(index_file)
                except Exception:
                    pass
            else:
                await self._afs.write_json(index_file, {"key_ids": existing_ids})

    def _generate_api_key(self) -> tuple[str, str, str]:
        """Generate a new API key.

        Returns:
            tuple: (full_key, prefix, hash)
        """
        random_part = secrets.token_urlsafe(32)
        full_key = f"ak_{random_part}"

        prefix = full_key[:PREFIX_LENGTH]

        key_hash = bcrypt.hashpw(full_key.encode(), bcrypt.gensalt()).decode()

        return full_key, prefix, key_hash

    def _verify_api_key(self, key_hash: str, provided_key: str) -> bool:
        """Verify an API key against its hash."""
        try:
            return bcrypt.checkpw(provided_key.encode(), key_hash.encode())
        except Exception:
            return False

    async def create_key(
        self, user_id: str, key_data: APIKeyCreate, created_by: str
    ) -> tuple[APIKey, str]:
        """Create a new API key.

        Returns:
            tuple: (APIKey, plaintext_key)
        """
        full_key, prefix, key_hash = self._generate_api_key()

        # Calculate expiration
        expires_at = None
        if not key_data.never_expires and key_data.expires_in_days:
            expires_at = utcnow() + timedelta(days=key_data.expires_in_days)

        api_key = APIKey(
            user_id=user_id,
            name=key_data.name,
            description=key_data.description,
            key_prefix=prefix,
            key_hash=key_hash,
            scopes=key_data.scopes,
            expires_at=expires_at,
            never_expires=key_data.never_expires,
            created_by=created_by,
            allowed_ips=key_data.allowed_ips,
        )

        # Save to storage
        file_path = f"{self.storage_path}/{api_key.key_id}.json"
        await self._afs.write_json(file_path, api_key.model_dump(), default=str)

        # Update prefix index
        await self._save_prefix_index(api_key)

        return api_key, full_key

    async def get_key(self, key_id: str) -> Optional[APIKey]:
        """Get an API key by ID."""
        try:
            file_path = f"{self.storage_path}/{key_id}.json"
            data = await self._afs.read_json(file_path)
            return APIKey(**data)
        except Exception:
            return None

    async def get_user_keys(self, user_id: str) -> List[APIKey]:
        """Get all API keys for a user."""
        keys = []
        try:
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    api_key = APIKey(**data)
                    if api_key.user_id == user_id:
                        keys.append(api_key)
                except Exception:
                    continue
        except Exception:
            pass

        return sorted(keys, key=lambda k: k.created_at, reverse=True)

    async def list_all_keys(
        self, limit: int = 100, offset: int = 0, active_only: bool = False
    ) -> List[APIKey]:
        """List all API keys (admin)."""
        keys = []
        try:
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    api_key = APIKey(**data)

                    if active_only and not api_key.is_active:
                        continue

                    keys.append(api_key)
                except Exception:
                    continue
        except Exception:
            pass

        # Sort by created_at desc
        keys.sort(key=lambda k: k.created_at, reverse=True)

        return keys[offset : offset + limit]

    async def validate_key(self, provided_key: str) -> Optional[APIKey]:
        """Validate an API key using prefix index for O(1) lookup.

        Raises APIKeyLockedException if any candidate key is locked.
        Records failed attempts on all candidates on mismatch.
        Resets failed attempts on successful match.
        """
        if not provided_key or not provided_key.startswith("ak_"):
            return None

        prefix = provided_key[:PREFIX_LENGTH]
        candidate_ids = await self._load_prefix_index(prefix)

        if not candidate_ids:
            return None

        for key_id in candidate_ids:
            if await self.is_key_locked(key_id):
                api_key = await self.get_key(key_id)
                if api_key and api_key.locked_until:
                    raise APIKeyLockedException(key_id, api_key.locked_until)

        for key_id in candidate_ids:
            api_key = await self.get_key(key_id)
            if api_key is None:
                continue

            if self._verify_api_key(api_key.key_hash, provided_key):
                if not api_key.is_active:
                    return None

                if api_key.expires_at and api_key.expires_at < utcnow():
                    return None

                await self.reset_failed_validations(key_id)
                return api_key

        for key_id in candidate_ids:
            await self.record_failed_validation(key_id)

        return None

    async def record_failed_validation(self, key_id: str) -> None:
        """Record a failed API key validation attempt. Locks the key if threshold reached."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self.get_key(key_id)
            if not api_key or not api_key.is_active:
                return

            api_key.failed_validation_attempts += 1

            if api_key.failed_validation_attempts >= self.settings.api_key_max_failed_attempts:
                api_key.locked_until = utcnow() + timedelta(
                    minutes=self.settings.api_key_lockout_minutes
                )

            file_path = f"{self.storage_path}/{key_id}.json"
            await self._afs.write_json(file_path, api_key.model_dump(), default=str)

    async def is_key_locked(self, key_id: str) -> bool:
        """Check if an API key is currently locked. Auto-unlocks on expiry."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self.get_key(key_id)
            if not api_key or not api_key.locked_until:
                return False

            if utcnow() >= api_key.locked_until:
                api_key.locked_until = None
                api_key.failed_validation_attempts = 0
                file_path = f"{self.storage_path}/{key_id}.json"
                await self._afs.write_json(file_path, api_key.model_dump(), default=str)
                return False

            return True

    async def reset_failed_validations(self, key_id: str) -> None:
        """Reset failed validation attempts and clear lockout."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self.get_key(key_id)
            if not api_key:
                return

            api_key.failed_validation_attempts = 0
            api_key.locked_until = None

            file_path = f"{self.storage_path}/{key_id}.json"
            await self._afs.write_json(file_path, api_key.model_dump(), default=str)

    async def record_usage(
        self,
        key_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Optional[APIKey]:
        """Update an API key's usage statistics."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self.get_key(key_id)
            if not api_key:
                return None

            # Update usage stats
            api_key.last_used_at = utcnow()
            api_key.total_requests += 1
            if ip_address:
                api_key.last_used_ip = ip_address
            if user_agent:
                api_key.last_used_ua = user_agent

            # Save
            file_path = f"{self.storage_path}/{key_id}.json"
            await self._afs.write_json(file_path, api_key.model_dump(), default=str)

            return api_key

    async def update_key(self, key_id: str, updates: dict) -> Optional[APIKey]:
        """Update an API key's metadata."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self.get_key(key_id)
            if not api_key:
                return None

            for field, value in updates.items():
                if hasattr(api_key, field):
                    setattr(api_key, field, value)

            file_path = f"{self.storage_path}/{key_id}.json"
            await self._afs.write_json(file_path, api_key.model_dump(), default=str)
            return api_key

    async def revoke_key(self, key_id: str, revoked_by: str) -> bool:
        """Revoke an API key."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self.get_key(key_id)
            if not api_key:
                return False

            api_key.is_active = False
            api_key.revoked_at = utcnow()
            api_key.revoked_by = revoked_by

            file_path = f"{self.storage_path}/{key_id}.json"
            await self._afs.write_json(file_path, api_key.model_dump(), default=str)

            return True

    async def delete_key(self, key_id: str) -> bool:
        """Permanently delete an API key."""
        api_key = await self.get_key(key_id)
        if not api_key:
            return False

        try:
            await self._remove_from_prefix_index(api_key.key_prefix, key_id)
            file_path = f"{self.storage_path}/{key_id}.json"
            await self._afs.rm(file_path)
            return True
        except Exception:
            return False

    async def track_usage(self, key_id: str, ip_address: Optional[str] = None) -> bool:
        """Track API key usage."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self.get_key(key_id)
            if not api_key:
                return False

            # Check IP restrictions
            if api_key.allowed_ips and ip_address:
                if ip_address not in api_key.allowed_ips:
                    return False

            # Update usage stats
            api_key.last_used_at = utcnow()
            api_key.total_requests += 1

            # Save
            file_path = f"{self.storage_path}/{key_id}.json"
            await self._afs.write_json(file_path, api_key.model_dump(), default=str)

            return True

    async def cleanup_expired_keys(self) -> int:
        """Delete expired API keys. Returns count of deleted keys."""
        deleted = 0
        try:
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    api_key = APIKey(**data)

                    # Check if expired
                    if (
                        api_key.expires_at
                        and api_key.expires_at < utcnow()
                        and not api_key.is_active
                    ):
                        await self._remove_from_prefix_index(api_key.key_prefix, api_key.key_id)
                        await self._afs.rm(file_path)
                        deleted += 1

                except Exception:
                    continue
        except Exception:
            pass

        return deleted
