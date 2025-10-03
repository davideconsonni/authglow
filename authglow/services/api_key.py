"""API Key storage and management service."""

import json
import os
import secrets
from datetime import datetime, timedelta
from typing import List, Optional
import bcrypt
import fsspec

from authglow.core.config import get_settings
from authglow.models.api_key import APIKey, APIKeyCreate


class APIKeyService:
    """Service for managing API keys."""

    def __init__(self):
        """Initialize API key service."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/api_keys"
        self.storage_options = self.settings.get_storage_options()

        # Initialize filesystem
        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend,
                **self.storage_options
            )

    def _generate_api_key(self) -> tuple[str, str, str]:
        """Generate a new API key.

        Returns:
            tuple: (full_key, prefix, hash)
        """
        # Generate random key: ak_<32 random chars>
        random_part = secrets.token_urlsafe(32)
        full_key = f"ak_{random_part}"

        # Prefix is first 12 chars for display
        prefix = full_key[:12]

        # Hash the full key
        key_hash = bcrypt.hashpw(full_key.encode(), bcrypt.gensalt()).decode()

        return full_key, prefix, key_hash

    def _verify_api_key(self, key_hash: str, provided_key: str) -> bool:
        """Verify an API key against its hash."""
        try:
            return bcrypt.checkpw(provided_key.encode(), key_hash.encode())
        except Exception:
            return False

    async def create_key(
        self,
        user_id: str,
        key_data: APIKeyCreate,
        created_by: str
    ) -> tuple[APIKey, str]:
        """Create a new API key.

        Returns:
            tuple: (APIKey, plaintext_key)
        """
        full_key, prefix, key_hash = self._generate_api_key()

        # Calculate expiration
        expires_at = None
        if not key_data.never_expires and key_data.expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=key_data.expires_in_days)

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
            allowed_ips=key_data.allowed_ips
        )

        # Save to storage
        file_path = f"{self.storage_path}/{api_key.key_id}.json"
        with self.fs.open(file_path, "w") as f:
            json.dump(api_key.model_dump(), f, default=str)

        return api_key, full_key

    async def get_key(self, key_id: str) -> Optional[APIKey]:
        """Get an API key by ID."""
        try:
            file_path = f"{self.storage_path}/{key_id}.json"
            with self.fs.open(file_path, "r") as f:
                data = json.load(f)
                return APIKey(**data)
        except Exception:
            return None

    async def get_user_keys(self, user_id: str) -> List[APIKey]:
        """Get all API keys for a user."""
        keys = []
        try:
            pattern = f"{self.storage_path}/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        api_key = APIKey(**data)
                        if api_key.user_id == user_id:
                            keys.append(api_key)
                except Exception:
                    continue
        except Exception:
            pass

        return sorted(keys, key=lambda k: k.created_at, reverse=True)

    async def list_all_keys(
        self,
        limit: int = 100,
        offset: int = 0,
        active_only: bool = False
    ) -> List[APIKey]:
        """List all API keys (admin)."""
        keys = []
        try:
            pattern = f"{self.storage_path}/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
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

        return keys[offset:offset + limit]

    async def verify_key(self, provided_key: str) -> Optional[APIKey]:
        """Verify an API key and return the key object if valid."""
        try:
            # Extract prefix from provided key
            if not provided_key.startswith("ak_"):
                return None

            prefix = provided_key[:12]

            # Find keys with matching prefix
            pattern = f"{self.storage_path}/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        api_key = APIKey(**data)

                        # Check prefix match first (fast)
                        if api_key.key_prefix != prefix:
                            continue

                        # Check if active
                        if not api_key.is_active:
                            continue

                        # Check expiration
                        if api_key.expires_at and api_key.expires_at < datetime.utcnow():
                            continue

                        # Verify full key (slow)
                        if self._verify_api_key(api_key.key_hash, provided_key):
                            return api_key

                except Exception:
                    continue

        except Exception:
            pass

        return None

    async def update_key(self, key_id: str, updates: dict) -> Optional[APIKey]:
        """Update an API key."""
        api_key = await self.get_key(key_id)
        if not api_key:
            return None

        # Update fields
        for field, value in updates.items():
            if hasattr(api_key, field) and value is not None:
                setattr(api_key, field, value)

        # Save
        file_path = f"{self.storage_path}/{key_id}.json"
        with self.fs.open(file_path, "w") as f:
            json.dump(api_key.model_dump(), f, default=str)

        return api_key

    async def revoke_key(self, key_id: str, revoked_by: str) -> bool:
        """Revoke an API key."""
        api_key = await self.get_key(key_id)
        if not api_key:
            return False

        api_key.is_active = False
        api_key.revoked_at = datetime.utcnow()
        api_key.revoked_by = revoked_by

        file_path = f"{self.storage_path}/{key_id}.json"
        with self.fs.open(file_path, "w") as f:
            json.dump(api_key.model_dump(), f, default=str)

        return True

    async def delete_key(self, key_id: str) -> bool:
        """Permanently delete an API key."""
        try:
            file_path = f"{self.storage_path}/{key_id}.json"
            self.fs.rm(file_path)
            return True
        except Exception:
            return False

    async def track_usage(
        self,
        key_id: str,
        ip_address: Optional[str] = None
    ) -> bool:
        """Track API key usage."""
        api_key = await self.get_key(key_id)
        if not api_key:
            return False

        # Check IP restrictions
        if api_key.allowed_ips and ip_address:
            if ip_address not in api_key.allowed_ips:
                return False

        # Update usage stats
        api_key.last_used_at = datetime.utcnow()
        api_key.total_requests += 1

        # Save
        file_path = f"{self.storage_path}/{key_id}.json"
        with self.fs.open(file_path, "w") as f:
            json.dump(api_key.model_dump(), f, default=str)

        return True

    async def cleanup_expired_keys(self) -> int:
        """Delete expired API keys. Returns count of deleted keys."""
        deleted = 0
        try:
            pattern = f"{self.storage_path}/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        api_key = APIKey(**data)

                        # Check if expired
                        if (
                            api_key.expires_at
                            and api_key.expires_at < datetime.utcnow()
                            and not api_key.is_active
                        ):
                            self.fs.rm(file_path)
                            deleted += 1

                except Exception:
                    continue
        except Exception:
            pass

        return deleted
