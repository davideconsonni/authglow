"""External Identity Provider federation storage."""

import json
import os
from typing import List, Optional

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.federation import ExternalIdpConfig


class FederationStorage:
    """Storage for external IdP configurations."""

    def __init__(self):
        settings = get_settings()
        self.settings = settings
        self.storage_path = f"{self.settings.storage_path}/federation"

        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend, **self.settings.get_storage_options()
            )

        self._afs = AsyncFileSystem(self.fs)

    def _get_provider_path(self, provider_id: str) -> str:
        return f"{self.storage_path}/{provider_id}.json"

    async def _list_files(self) -> List[str]:
        """List all provider JSON files. Uses glob + manual fallback for s3/cloud."""
        try:
            return await self._afs.glob(f"{self.storage_path}/*.json")
        except Exception:
            try:
                all_files = await self._afs.ls(self.storage_path)
                return [f for f in all_files if isinstance(f, str) and f.endswith(".json")]
            except Exception:
                return []

    async def create_provider(self, provider: ExternalIdpConfig) -> ExternalIdpConfig:
        """Create a new external IdP configuration."""
        async with named_lock("federation:create"):
            provider.created_at = utcnow()
            provider.updated_at = utcnow()
            filepath = self._get_provider_path(provider.id)
            await self._afs.write_json(filepath, provider.model_dump(mode="json"))
        return provider

    async def get_provider(self, provider_id: str) -> Optional[ExternalIdpConfig]:
        """Get a provider by ID."""
        filepath = self._get_provider_path(provider_id)
        try:
            data = await self._afs.read_json(filepath)
            return ExternalIdpConfig(**data)
        except Exception:
            return None

    async def list_providers(self, enabled_only: bool = False) -> List[ExternalIdpConfig]:
        """List all providers, optionally filtering by enabled status."""
        providers: List[ExternalIdpConfig] = []
        try:
            files = await self._list_files()
            for filepath in files:
                try:
                    data = await self._afs.read_json(filepath)
                    if data:
                        provider = ExternalIdpConfig(**data)
                        if not enabled_only or provider.enabled:
                            providers.append(provider)
                except Exception:
                    continue
        except Exception:
            pass
        return providers

    async def update_provider(self, provider_id: str, updates: dict) -> Optional[ExternalIdpConfig]:
        """Update a provider configuration."""
        async with named_lock(f"federation:{provider_id}"):
            provider = await self.get_provider(provider_id)
            if not provider:
                return None

            for key, value in updates.items():
                if value is not None:
                    setattr(provider, key, value)
            provider.updated_at = utcnow()

            filepath = self._get_provider_path(provider_id)
            await self._afs.write_json(filepath, provider.model_dump(mode="json"))
            return provider

    async def delete_provider(self, provider_id: str) -> bool:
        """Delete a provider configuration."""
        async with named_lock(f"federation:{provider_id}"):
            filepath = self._get_provider_path(provider_id)
            exists = await self._afs.exists(filepath)
            if exists:
                await self._afs.rm(filepath)
                return True
        return False
