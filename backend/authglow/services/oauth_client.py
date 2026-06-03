"""OAuth2 Client storage and management service."""

import os
import secrets
from typing import List, Optional

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.oauth_client import OAuth2Client
from authglow.services.password import hash_password, verify_password


class OAuth2ClientStorage:
    """Storage for OAuth2 clients."""

    MAX_CAS_RETRIES = 3

    def __init__(self):
        """Initialize client storage."""
        settings = get_settings()
        self.settings = settings
        self.storage_path = f"{self.settings.storage_path}/oauth_clients"
        self.storage_options = self.settings.get_storage_options()

        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(self.settings.storage_backend, **self.storage_options)

        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

    def _get_client_path(self, client_id: str) -> str:
        """Get path for a client file."""
        return f"{self.storage_path}/{client_id}.json"

    async def create_client(self, client: OAuth2Client, plaintext_secret: str) -> OAuth2Client:
        """
        Create a new OAuth2 client.

        Args:
            client: OAuth2Client instance with plaintext secret
            plaintext_secret: The plaintext secret to hash and store

        Returns:
            Created client with hashed secret
        """
        client.client_secret = hash_password(plaintext_secret)

        client_path = self._get_client_path(client.client_id)
        await self._afs.write_json(client_path, client.model_dump(mode="json"))

        return client

    async def get_client(self, client_id: str) -> Optional[OAuth2Client]:
        """Get a client by client_id."""
        client_path = self._get_client_path(client_id)

        exists = await self._afs.exists(client_path)
        if not exists:
            return None

        data = await self._afs.read_json(client_path)
        return OAuth2Client(**data)

    async def update_client(self, client: OAuth2Client) -> OAuth2Client:
        """Update an existing client."""
        client_path = self._get_client_path(client.client_id)
        await self._afs.write_json(client_path, client.model_dump(mode="json"))
        return client

    async def delete_client(self, client_id: str) -> bool:
        """Delete a client."""
        client_path = self._get_client_path(client_id)

        exists = await self._afs.exists(client_path)
        if not exists:
            return False

        await self._afs.rm(client_path)
        return True

    async def list_clients(
        self, limit: int = 100, offset: int = 0, active_only: bool = False
    ) -> List[OAuth2Client]:
        """List all OAuth2 clients with pagination."""
        clients = []

        try:
            pattern = f"{self.storage_path}/*.json"
            files = sorted(await self._afs.glob(pattern))

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    client = OAuth2Client(**data)

                    if active_only and not client.is_active:
                        continue

                    clients.append(client)
                except Exception:
                    continue
        except Exception:
            pass

        return clients[offset : offset + limit]

    async def verify_client_secret(self, client: OAuth2Client, client_secret: str) -> bool:
        """Verify client credentials."""
        if not client or not client.is_active:
            return False

        return verify_password(client_secret, client.client_secret)

    async def verify_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Verify if redirect_uri is allowed for the client."""
        client = await self.get_client(client_id)

        if not client or not client.is_active:
            return False

        return redirect_uri in client.redirect_uris

    async def update_last_used(self, client_id: str):
        """Update last used timestamp with CAS protection."""
        async with self._lock(f"oauth_client:{client_id}"):
            client_path = self._get_client_path(client_id)

            exists = await self._afs.exists(client_path)
            if not exists:
                return

            for attempt in range(self.MAX_CAS_RETRIES):
                data, version = await self._afs.read_json_versioned(client_path)
                client = OAuth2Client(**data)
                client.last_used_at = utcnow()

                try:
                    await self._afs.write_json_versioned(
                        client_path,
                        client.model_dump(mode="json"),
                        version,
                    )
                    return
                except ConcurrentWriteError:
                    if attempt == self.MAX_CAS_RETRIES - 1:
                        raise
                    continue

    async def rotate_secret(self, client_id: str) -> str:
        """
        Rotate client secret with CAS protection against concurrent rotations.

        Returns:
            New plaintext secret

        Raises:
            ValueError: If the client is not found
        """
        client_path = self._get_client_path(client_id)
        exists = await self._afs.exists(client_path)
        if not exists:
            raise ValueError("Client not found")

        async with self._lock(f"oauth_client:{client_id}"):
            for attempt in range(self.MAX_CAS_RETRIES):
                data, version = await self._afs.read_json_versioned(client_path)
                client = OAuth2Client(**data)

                new_secret = secrets.token_urlsafe(32)
                client.client_secret = hash_password(new_secret)

                try:
                    await self._afs.write_json_versioned(
                        client_path,
                        client.model_dump(mode="json"),
                        version,
                    )
                    return new_secret
                except ConcurrentWriteError:
                    if attempt == self.MAX_CAS_RETRIES - 1:
                        raise
                    continue

        raise ConcurrentWriteError(
            f"Failed to rotate secret for {client_id} after {self.MAX_CAS_RETRIES} attempts"
        )

    def generate_client_secret(self) -> str:
        """Generate a secure random client secret."""
        return secrets.token_urlsafe(32)

    async def is_scope_allowed(self, client_id: str, requested_scopes: List[str]) -> bool:
        """Check if client is allowed to request these scopes."""
        client = await self.get_client(client_id)

        if not client or not client.is_active:
            return False

        return all(scope in client.allowed_scopes for scope in requested_scopes)

    async def is_grant_type_allowed(self, client_id: str, grant_type: str) -> bool:
        """Check if client is allowed to use this grant type."""
        client = await self.get_client(client_id)

        if not client or not client.is_active:
            return False

        return grant_type in client.grant_types
