"""OAuth2 Client storage and management service."""

import json
import secrets
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from authglow.models.oauth_client import OAuth2Client
from authglow.services.password import hash_password, verify_password
from authglow.core.config import get_settings


class OAuth2ClientStorage:
    """Storage for OAuth2 clients."""

    def __init__(self):
        """Initialize client storage."""
        settings = get_settings()
        self.storage_path = Path(settings.storage_path) / "oauth_clients"
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def _get_client_path(self, client_id: str) -> Path:
        """Get path for a client file."""
        return self.storage_path / f"{client_id}.json"

    async def create_client(self, client: OAuth2Client, plaintext_secret: str) -> OAuth2Client:
        """
        Create a new OAuth2 client.

        Args:
            client: OAuth2Client instance with plaintext secret
            plaintext_secret: The plaintext secret to hash and store

        Returns:
            Created client with hashed secret
        """
        # Hash the client secret
        client.client_secret = hash_password(plaintext_secret)

        # Save to file
        client_path = self._get_client_path(client.client_id)
        with open(client_path, "w") as f:
            json.dump(client.model_dump(mode="json"), f, indent=2, default=str)

        return client

    async def get_client(self, client_id: str) -> Optional[OAuth2Client]:
        """Get a client by client_id."""
        client_path = self._get_client_path(client_id)

        if not client_path.exists():
            return None

        with open(client_path, "r") as f:
            data = json.load(f)
            return OAuth2Client(**data)

    async def update_client(self, client: OAuth2Client) -> OAuth2Client:
        """Update an existing client."""
        client_path = self._get_client_path(client.client_id)

        with open(client_path, "w") as f:
            json.dump(client.model_dump(mode="json"), f, indent=2, default=str)

        return client

    async def delete_client(self, client_id: str) -> bool:
        """Delete a client."""
        client_path = self._get_client_path(client_id)

        if not client_path.exists():
            return False

        client_path.unlink()
        return True

    async def list_clients(
        self,
        limit: int = 100,
        offset: int = 0,
        active_only: bool = False
    ) -> List[OAuth2Client]:
        """List all OAuth2 clients with pagination."""
        clients = []

        for client_path in sorted(self.storage_path.glob("*.json")):
            with open(client_path, "r") as f:
                data = json.load(f)
                client = OAuth2Client(**data)

                if active_only and not client.is_active:
                    continue

                clients.append(client)

        # Apply pagination
        return clients[offset:offset + limit]

    async def verify_client_secret(
        self,
        client_id: str,
        client_secret: str
    ) -> bool:
        """Verify client credentials."""
        client = await self.get_client(client_id)

        if not client or not client.is_active:
            return False

        return verify_password(client_secret, client.client_secret)

    async def verify_redirect_uri(
        self,
        client_id: str,
        redirect_uri: str
    ) -> bool:
        """Verify if redirect_uri is allowed for the client."""
        client = await self.get_client(client_id)

        if not client or not client.is_active:
            return False

        return redirect_uri in client.redirect_uris

    async def update_last_used(self, client_id: str):
        """Update last used timestamp."""
        client = await self.get_client(client_id)
        if client:
            client.last_used_at = datetime.utcnow()
            await self.update_client(client)

    async def rotate_secret(self, client_id: str) -> str:
        """
        Rotate client secret.

        Returns:
            New plaintext secret
        """
        client = await self.get_client(client_id)
        if not client:
            raise ValueError("Client not found")

        # Generate new secret
        new_secret = secrets.token_urlsafe(32)

        # Hash and update
        client.client_secret = hash_password(new_secret)
        await self.update_client(client)

        return new_secret

    def generate_client_secret(self) -> str:
        """Generate a secure random client secret."""
        return secrets.token_urlsafe(32)

    async def is_scope_allowed(
        self,
        client_id: str,
        requested_scopes: List[str]
    ) -> bool:
        """Check if client is allowed to request these scopes."""
        client = await self.get_client(client_id)

        if not client or not client.is_active:
            return False

        # Check if all requested scopes are in allowed scopes
        return all(scope in client.allowed_scopes for scope in requested_scopes)

    async def is_grant_type_allowed(
        self,
        client_id: str,
        grant_type: str
    ) -> bool:
        """Check if client is allowed to use this grant type."""
        client = await self.get_client(client_id)

        if not client or not client.is_active:
            return False

        return grant_type in client.grant_types
