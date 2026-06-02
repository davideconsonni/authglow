"""OAuth2 consent management service — deterministic storage layout.

Consents are stored at {storage_path}/{user_id}/{client_id}.json
for O(1) direct lookup without glob.
"""

import os
from datetime import datetime
from typing import List, Optional

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.oauth_consent import OAuth2Consent


class OAuth2ConsentService:
    """Service for managing OAuth2 user consents."""

    def __init__(self):
        """Initialize consent service."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/oauth_consents"
        self.storage_options = self.settings.get_storage_options()

        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend, **self.storage_options
            )

        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

    def _get_consent_path(self, user_id: str, client_id: str) -> str:
        """Get deterministic path for a user+client consent."""
        return f"{self.storage_path}/{user_id}/{client_id}.json"

    async def _find_consent_by_id(
        self, consent_id: str
    ) -> Optional[tuple[OAuth2Consent, str, str]]:
        """Scan all consents to find one by consent_id.

        Returns (consent, user_id, client_id) or None.
        Admin-only operation, not on the hot path.
        """
        try:
            files = await self._afs.glob(f"{self.storage_path}/**/*.json")
            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    if data.get("consent_id") == consent_id:
                        consent = OAuth2Consent(**data)
                        return consent, data["user_id"], data["client_id"]
                except Exception:
                    continue
        except Exception:
            pass
        return None

    async def create_consent(
        self,
        user_id: str,
        client_id: str,
        scopes: List[str],
        expires_at: Optional[datetime] = None,
    ) -> OAuth2Consent:
        """Create or overwrite a consent record for a user+client pair.

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

        consent_path = self._get_consent_path(user_id, client_id)
        await self._afs.makedirs(f"{self.storage_path}/{user_id}", exist_ok=True)
        await self._afs.write_json(consent_path, consent.model_dump())

        return consent

    async def get_consent(self, consent_id: str) -> Optional[OAuth2Consent]:
        """Get a consent by ID (admin operation, scans all consents).

        Args:
            consent_id: Consent ID

        Returns:
            OAuth2Consent if found, None otherwise
        """
        result = await self._find_consent_by_id(consent_id)
        if result:
            return result[0]
        return None

    async def get_user_consent(
        self, user_id: str, client_id: str
    ) -> Optional[OAuth2Consent]:
        """Get existing consent for user and client — O(1) direct path lookup.

        Args:
            user_id: User ID
            client_id: OAuth2 client ID

        Returns:
            OAuth2Consent if found and valid, None otherwise
        """
        try:
            consent_path = self._get_consent_path(user_id, client_id)
            data = await self._afs.read_json(consent_path)
            consent = OAuth2Consent(**data)

            if consent.revoked:
                return None

            if consent.expires_at and utcnow() > consent.expires_at:
                await self._afs.rm(consent_path)
                return None

            return consent

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

        has_all_scopes = all(scope in consent.scopes for scope in required_scopes)

        return has_all_scopes, consent

    async def revoke_consent(self, consent_id: str) -> bool:
        """Revoke a consent by ID (admin operation, scans all consents).

        Protected by a named lock to prevent concurrent revocation races.

        Args:
            consent_id: Consent ID

        Returns:
            True if revoked successfully, False otherwise
        """
        result = await self._find_consent_by_id(consent_id)
        if not result:
            return False

        consent, user_id, client_id = result
        lock_key = f"consent:{user_id}:{client_id}"

        async with self._lock(lock_key):
            consent.revoked = True
            consent.revoked_at = utcnow()

            consent_path = self._get_consent_path(user_id, client_id)
            try:
                await self._afs.write_json(consent_path, consent.model_dump())
                return True
            except Exception:
                return False

    async def revoke_user_client_consent(self, user_id: str, client_id: str) -> bool:
        """Revoke consent for a specific user+client pair — O(1) direct path.

        Args:
            user_id: User ID
            client_id: OAuth2 client ID

        Returns:
            True if consent was revoked
        """
        consent = await self.get_user_consent(user_id, client_id)
        if not consent:
            return False

        async with self._lock(f"consent:{user_id}:{client_id}"):
            consent.revoked = True
            consent.revoked_at = utcnow()

            consent_path = self._get_consent_path(user_id, client_id)
            try:
                await self._afs.write_json(consent_path, consent.model_dump())
                return True
            except Exception:
                return False

    async def list_user_consents(self, user_id: str) -> List[OAuth2Consent]:
        """List all consents for a user (bounded glob under user directory).

        Args:
            user_id: User ID

        Returns:
            List of OAuth2Consent objects
        """
        consents = []
        try:
            pattern = f"{self.storage_path}/{user_id}/*.json"
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

        consents.sort(key=lambda c: c.granted_at, reverse=True)
        return consents

    async def cleanup_expired_consents(self) -> int:
        """Delete all expired consents.

        Returns:
            Number of consents deleted
        """
        deleted = 0
        try:
            pattern = f"{self.storage_path}/**/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    consent = OAuth2Consent(**data)

                    if consent.expires_at and utcnow() > consent.expires_at:
                        await self._afs.rm(file_path)
                        deleted += 1

                except Exception:
                    continue

        except Exception:
            pass

        return deleted
