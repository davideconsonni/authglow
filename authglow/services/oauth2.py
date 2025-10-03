"""OAuth2 authorization service."""

import json
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4
import fsspec
from authglow.core.config import get_settings
from authglow.models.token import AuthorizationCode
from authglow.services.oauth_client import OAuth2ClientStorage


class OAuth2Service:
    """Service for OAuth2 authorization codes (stateless)."""

    def __init__(self):
        """Initialize OAuth2 service with settings."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/auth_codes"
        self.storage_options = self.settings.get_storage_options()
        self.client_storage = OAuth2ClientStorage()

        # Initialize filesystem
        if self.settings.storage_backend == "file":
            import os
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend,
                **self.storage_options
            )

    def _get_code_path(self, code: str) -> str:
        """Get full path for an authorization code."""
        return f"{self.storage_path}/{code}.json"

    async def create_authorization_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: str
    ) -> AuthorizationCode:
        """Create a new authorization code."""
        expires_at = datetime.utcnow() + timedelta(
            minutes=self.settings.oauth2_authorization_code_expire_minutes
        )

        auth_code = AuthorizationCode(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            expires_at=expires_at
        )

        # Save authorization code
        code_path = self._get_code_path(auth_code.code)
        code_data = auth_code.model_dump(mode="json")

        with self.fs.open(code_path, "w") as f:
            json.dump(code_data, f, indent=2, default=str)

        return auth_code

    async def get_authorization_code(self, code: str) -> Optional[AuthorizationCode]:
        """Get and validate an authorization code."""
        code_path = self._get_code_path(code)

        try:
            with self.fs.open(code_path, "r") as f:
                code_data = json.load(f)
                auth_code = AuthorizationCode(**code_data)

                # Check if expired
                if datetime.utcnow() > auth_code.expires_at:
                    # Delete expired code
                    self.fs.rm(code_path)
                    return None

                # Check if already used
                if auth_code.used:
                    return None

                return auth_code

        except FileNotFoundError:
            return None

    async def mark_code_as_used(self, code: str) -> bool:
        """Mark an authorization code as used."""
        auth_code = await self.get_authorization_code(code)
        if not auth_code:
            return False

        auth_code.used = True
        code_path = self._get_code_path(code)
        code_data = auth_code.model_dump(mode="json")

        with self.fs.open(code_path, "w") as f:
            json.dump(code_data, f, indent=2, default=str)

        return True

    async def delete_authorization_code(self, code: str):
        """Delete an authorization code."""
        code_path = self._get_code_path(code)
        try:
            self.fs.rm(code_path)
        except FileNotFoundError:
            pass

    async def verify_client(self, client_id: str, client_secret: Optional[str] = None) -> bool:
        """
        Verify client credentials using dynamic client storage.

        Falls back to settings-based client for backwards compatibility.
        """
        # Try dynamic client storage first
        client = await self.client_storage.get_client(client_id)

        if client:
            # Check if client is active
            if not client.is_active:
                return False

            # Update last used timestamp
            await self.client_storage.update_last_used(client_id)

            # If secret provided, verify it
            if client_secret:
                return await self.client_storage.verify_client_secret(client_id, client_secret)

            return True

        # Fallback to settings-based client (backwards compatibility)
        if client_id != self.settings.oauth2_client_id:
            return False

        if client_secret and client_secret != self.settings.oauth2_client_secret:
            return False

        return True

    async def verify_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Verify if redirect_uri is allowed for the client."""
        # Try dynamic client storage first
        client = await self.client_storage.get_client(client_id)

        if client:
            return await self.client_storage.verify_redirect_uri(client_id, redirect_uri)

        # Fallback: allow any redirect_uri for settings-based client
        # (not recommended for production)
        return client_id == self.settings.oauth2_client_id

    async def verify_scopes(self, client_id: str, requested_scopes: list[str]) -> bool:
        """Verify if client is allowed to request these scopes."""
        # Try dynamic client storage first
        client = await self.client_storage.get_client(client_id)

        if client:
            return await self.client_storage.is_scope_allowed(client_id, requested_scopes)

        # Fallback: allow all scopes for settings-based client
        return client_id == self.settings.oauth2_client_id

    async def verify_grant_type(self, client_id: str, grant_type: str) -> bool:
        """Verify if client is allowed to use this grant type."""
        # Try dynamic client storage first
        client = await self.client_storage.get_client(client_id)

        if client:
            return await self.client_storage.is_grant_type_allowed(client_id, grant_type)

        # Fallback: allow all grant types for settings-based client
        return client_id == self.settings.oauth2_client_id
