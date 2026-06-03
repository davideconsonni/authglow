"""OAuth2 authorization service."""

from datetime import timedelta
from typing import List, Optional

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.token import AuthorizationCode
from authglow.services.oauth_client import OAuth2ClientStorage


class OAuth2Service:
    """Service for OAuth2 authorization codes (stateless).

    The ``mark_code_as_used`` operation is protected by a named lock
    (in-process) and optimistic-concurrency versioning (cross-process)
    to prevent authorization code reuse.
    """

    MAX_CAS_RETRIES = 3

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
            self.fs = fsspec.filesystem(self.settings.storage_backend, **self.storage_options)

        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

    def _get_code_path(self, code: str) -> str:
        """Get full path for an authorization code."""
        return f"{self.storage_path}/{code}.json"

    async def create_authorization_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> AuthorizationCode:
        """Create a new authorization code."""
        expires_at = utcnow() + timedelta(
            minutes=self.settings.oauth2_authorization_code_expire_minutes
        )

        auth_code = AuthorizationCode(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            expires_at=expires_at,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
        )

        # Save authorization code
        code_path = self._get_code_path(auth_code.code)
        code_data = auth_code.model_dump(mode="json")

        await self._afs.write_json(code_path, code_data)

        return auth_code

    async def get_authorization_code(self, code: str) -> Optional[AuthorizationCode]:
        """Get and validate an authorization code."""
        code_path = self._get_code_path(code)

        try:
            code_data = await self._afs.read_json(code_path)
            auth_code = AuthorizationCode(**code_data)

            # Check if expired
            if utcnow() > auth_code.expires_at:
                # Delete expired code
                await self._afs.rm(code_path)
                return None

            # Check if already used
            if auth_code.used:
                return None

            return auth_code

        except FileNotFoundError:
            return None

    async def mark_code_as_used(self, code: str) -> bool:
        """Mark an authorization code as used.

        Protected by a named lock on the code and optimistic-concurrency
        versioning to prevent the same code from being redeemed twice.
        """
        async with self._lock(f"auth_code:{code}"):
            for attempt in range(self.MAX_CAS_RETRIES):
                auth_code = await self.get_authorization_code(code)
                if not auth_code:
                    return False

                auth_code.used = True
                code_path = self._get_code_path(code)
                code_data = auth_code.model_dump(mode="json")

                try:
                    _, version = await self._afs.read_json_versioned(code_path)
                    await self._afs.write_json_versioned(code_path, code_data, version)
                    return True
                except ConcurrentWriteError:
                    continue

            return False

    async def delete_authorization_code(self, code: str):
        """Delete an authorization code."""
        code_path = self._get_code_path(code)
        try:
            await self._afs.rm(code_path)
        except FileNotFoundError:
            pass

    async def verify_client(self, client_id: str, client_secret: Optional[str] = None) -> bool:
        """
        Verify client credentials using dynamic client storage.

        Falls back to the settings-based client for backwards compatibility.
        """
        # Try dynamic client storage first
        client = await self.client_storage.get_client(client_id)

        if client:
            # Check if the client is active
            if not client.is_active:
                return False

            # Update last used timestamp
            await self.client_storage.update_last_used(client_id)

            # If secret provided, verify it
            if client_secret:
                return await self.client_storage.verify_client_secret(client, client_secret)

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

        # Fallback: only allow specific callback for settings-based client
        if client_id == self.settings.oauth2_client_id:
            return redirect_uri == "http://localhost:8000/callback"

        return False

    async def verify_scopes(self, client_id: str, requested_scopes: list[str]) -> bool:
        """Verify if client is allowed to request these scopes."""
        # Try dynamic client storage first
        client = await self.client_storage.get_client(client_id)

        if client:
            return await self.client_storage.is_scope_allowed(client_id, requested_scopes)

        # Fallback: allow all scopes for settings-based client
        return client_id == self.settings.oauth2_client_id

    async def process_scopes(self, client_id: str, requested_scopes: List[str]) -> List[str]:
        """
        Process and validate scopes based on client configuration and application settings.

        Security: Always validates that requested scopes are authorized for the client.
        OIDC standard scopes (openid, profile, email, phone, address, offline_access)
        are always allowed as per OIDC spec.
        """
        # OIDC standard scopes that are always allowed
        OIDC_STANDARD_SCOPES = {
            "openid",
            "profile",
            "email",
            "phone",
            "address",
            "offline_access",
        }

        client = await self.client_storage.get_client(client_id)
        allowed_scopes = list(client.allowed_scopes) if client else []

        # Fallback for settings-based client
        if not client and client_id == self.settings.oauth2_client_id:
            # In permissive mode, allow any scope for the default client
            if not self.settings.oauth2_reject_unknown_scopes:
                return requested_scopes
            # In strict mode, default client has no defined scopes
            allowed_scopes = []

        # Always include OIDC standard scopes in allowed list
        allowed_scopes_set = set(allowed_scopes) | OIDC_STANDARD_SCOPES

        # Check for unauthorized scopes
        unknown_scopes = set(requested_scopes) - allowed_scopes_set

        if unknown_scopes:
            if self.settings.oauth2_reject_unknown_scopes:
                # Strict mode: reject immediately with error
                raise ValueError(
                    f"Unauthorized scopes: {', '.join(sorted(unknown_scopes))}. "
                    f"Allowed: {', '.join(sorted(allowed_scopes_set))}"
                )
            else:
                # Permissive mode: filter out unauthorized scopes and allow request to proceed
                filtered_scopes = [s for s in requested_scopes if s in allowed_scopes_set]
                return filtered_scopes

        return requested_scopes

    async def verify_grant_type(self, client_id: str, grant_type: str) -> bool:
        """Verify if client is allowed to use this grant type."""
        # Try dynamic client storage first
        client = await self.client_storage.get_client(client_id)

        if client:
            return await self.client_storage.is_grant_type_allowed(client_id, grant_type)

        # Fallback: allow all grant types for settings-based client
        return client_id == self.settings.oauth2_client_id
