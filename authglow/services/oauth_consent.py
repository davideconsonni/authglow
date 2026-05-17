"""OAuth2 consent management service."""

import json
import os
from datetime import datetime
from typing import Optional, List
import fsspec

from authglow.core.config import get_settings
from authglow.core.async_io import AsyncFileSystem
from authglow.core.datetime import utcnow
from authglow.models.oauth_consent import OAuth2Consent


class OAuth2ConsentService:
    """Service for managing OAuth2 user consents."""

    def __init__(self):
        """Initialize consent service."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/oauth_consents"
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

    def _get_consent_path(self, consent_id: str) -> str:
        """Get path for consent file."""
        return f"{self.storage_path}/{consent_id}.json"

    def _get_user_consent_pattern(self, user_id: str) -> str:
        """Get glob pattern for user's consents."""
        return f"{self.storage_path}/*.json"

    async def create_consent(
        self,
        user_id: str,
        client_id: str,
        scopes: List[str],
        expires_at: Optional[datetime] = None,
    ) -> OAuth2Consent:
        """Create a new consent record.

        Args:
            user_id: User ID
            client_id: OAuth2 client ID
            scopes: List of granted scopes
            expires_at: Optional expiration datetime

        Returns:
            OAuth2Consent object
        """
        consent = OAuth2Consent(
            user_id=user_id, client_id=client_id, scopes=scopes, expires_at=expires_at
        )

        # Save consent
        consent_path = self._get_consent_path(consent.consent_id)
        await self._afs.write_json(consent_path, consent.model_dump())

        return consent

    async def get_consent(self, consent_id: str) -> Optional[OAuth2Consent]:
        """Get a consent by ID.

        Args:
            consent_id: Consent ID

        Returns:
            OAuth2Consent if found, None otherwise
        """
        try:
            consent_path = self._get_consent_path(consent_id)
            data = await self._afs.read_json(consent_path)
            return OAuth2Consent(**data)
        except Exception:
            return None

    async def get_user_consent(
        self, user_id: str, client_id: str
    ) -> Optional[OAuth2Consent]:
        """Get existing consent for user and client.

        Args:
            user_id: User ID
            client_id: OAuth2 client ID

        Returns:
            OAuth2Consent if found and valid, None otherwise
        """
        try:
            pattern = self._get_user_consent_pattern(user_id)
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    consent = OAuth2Consent(**data)

                    # Check if matches user and client
                    if consent.user_id != user_id or consent.client_id != client_id:
                        continue

                    # Check if revoked
                    if consent.revoked:
                        continue

                    # Check if expired
                    if consent.expires_at and utcnow() > consent.expires_at:
                        # Auto-delete expired consent
                        await self._afs.rm(file_path)
                        continue

                    return consent

                except Exception:
                    continue

            return None

        except Exception:
            return None

    async def check_consent(
        self, user_id: str, client_id: str, required_scopes: List[str]
    ) -> tuple[bool, Optional[OAuth2Consent]]:
        """Check if user has granted consent for the requested scopes.

        Args:
            user_id: User ID
            client_id: OAuth2 client ID
            required_scopes: List of required scopes

        Returns:
            Tuple of (has_consent: bool, consent: Optional[OAuth2Consent])
        """
        consent = await self.get_user_consent(user_id, client_id)

        if not consent:
            return False, None

        # Check if all required scopes are granted
        has_all_scopes = all(scope in consent.scopes for scope in required_scopes)

        return has_all_scopes, consent

    async def revoke_consent(self, consent_id: str) -> bool:
        """Revoke a consent.

        Args:
            consent_id: Consent ID

        Returns:
            True if revoked successfully, False otherwise
        """
        consent = await self.get_consent(consent_id)
        if not consent:
            return False

        consent.revoked = True
        consent.revoked_at = utcnow()

        # Save updated consent
        consent_path = self._get_consent_path(consent_id)
        try:
            await self._afs.write_json(consent_path, consent.model_dump())
            return True
        except Exception:
            return False

    async def revoke_user_client_consent(self, user_id: str, client_id: str) -> bool:
        """Revoke all consents for a user and client.

        Args:
            user_id: User ID
            client_id: OAuth2 client ID

        Returns:
            True if at least one consent was revoked
        """
        consent = await self.get_user_consent(user_id, client_id)
        if consent:
            return await self.revoke_consent(consent.consent_id)
        return False

    async def list_user_consents(self, user_id: str) -> List[OAuth2Consent]:
        """List all consents for a user.

        Args:
            user_id: User ID

        Returns:
            List of OAuth2Consent objects
        """
        consents = []
        try:
            pattern = self._get_user_consent_pattern(user_id)
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    consent = OAuth2Consent(**data)

                    if consent.user_id == user_id:
                        consents.append(consent)

                except Exception:
                    continue

        except Exception:
            pass

        # Sort by granted_at descending
        consents.sort(key=lambda c: c.granted_at, reverse=True)
        return consents

    async def cleanup_expired_consents(self) -> int:
        """Delete all expired consents.

        Returns:
            Number of consents deleted
        """
        deleted = 0
        try:
            pattern = f"{self.storage_path}/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    consent = OAuth2Consent(**data)

                    # Delete if expired
                    if consent.expires_at and utcnow() > consent.expires_at:
                        await self._afs.rm(file_path)
                        deleted += 1

                except Exception:
                    continue

        except Exception:
            pass

        return deleted
