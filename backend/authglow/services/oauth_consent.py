"""OAuth2 consent management service.

Consents are persisted via the ``OAuth2ConsentRepository``
Protocol. The service owns:

* the in-process ``named_lock`` that serialises cross-coroutine
  revocation races;
* the user / client lookups (peer services) needed to build the
  admin DTOs in ``list_all_for_admin``;
* the email filter and the public ``list_all_for_admin`` API
  consumed by ``api/admin.py``;
* the public ``create_consent`` / ``get_consent`` /
  ``get_user_consent`` / ``check_consent`` / ``revoke_consent`` /
  ``revoke_user_client_consent`` / ``list_user_consents`` /
  ``cleanup_expired_consents`` API.

The repository is responsible for the file layout, JSON
serialisation, O(1) direct lookup, and bulk cleanup / list
operations. A default ``FileOAuth2ConsentRepository`` is
constructed when no repository is injected — FastAPI's
``Depends(lambda: OAuth2ConsentService())`` factory uses the
default.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from authglow.core.concurrency import named_lock
from authglow.core.config import Settings, get_settings
from authglow.core.datetime import utcnow
from authglow.models.oauth_consent import OAuth2Consent
from authglow.repositories.protocols import OAuth2ConsentRepository
from authglow.services.oauth_client import OAuth2ClientStorage
from authglow.services.user import UserService as UserStorage


class OAuth2ConsentService:
    """Service for managing OAuth2 user consents."""

    def __init__(
        self,
        repository: Optional[OAuth2ConsentRepository] = None,
        *,
        settings: Optional[Settings] = None,
    ) -> None:
        """Initialize consent service."""
        self.settings: Settings = settings or get_settings()
        self._repository: OAuth2ConsentRepository = (
            repository if repository is not None else _default_repository(self.settings)
        )
        self._lock = named_lock()

        # Peer services — used by list_all_for_admin. Kept as
        # attributes so they can be replaced in tests.
        self.user_storage = UserStorage()
        self.client_storage = OAuth2ClientStorage()

    @property
    def repository(self) -> OAuth2ConsentRepository:
        """The underlying repository (exposed for tests / admin tools)."""
        return self._repository

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create_consent(
        self,
        user_id: str,
        client_id: str,
        scopes: List[str],
        expires_at: Optional[datetime] = None,
    ) -> OAuth2Consent:
        """Create or overwrite a consent record for a user+client pair."""
        consent = OAuth2Consent(
            user_id=user_id, client_id=client_id, scopes=scopes, expires_at=expires_at
        )
        await self._repository.create(consent)
        return consent

    async def get_consent(self, consent_id: str) -> Optional[OAuth2Consent]:
        """Get a consent by ID (admin operation, scans all consents)."""
        return await self._repository.get_by_id(consent_id)

    async def get_user_consent(self, user_id: str, client_id: str) -> Optional[OAuth2Consent]:
        """Get existing consent for user and client — O(1) direct path lookup."""
        return await self._repository.get_for_user_client(user_id, client_id)

    async def check_consent(
        self, user_id: str, client_id: str, required_scopes: List[str]
    ) -> Tuple[bool, Optional[OAuth2Consent]]:
        """Check if user has granted consent for the requested scopes."""
        consent = await self.get_user_consent(user_id, client_id)
        if not consent:
            return False, None
        has_all_scopes = all(scope in consent.scopes for scope in required_scopes)
        return has_all_scopes, consent

    # ------------------------------------------------------------------
    # Revocation (CAS-equivalent: in-process lock per user+client)
    # ------------------------------------------------------------------

    async def revoke_consent(self, consent_id: str) -> bool:
        """Revoke a consent by ID (admin operation).

        Protected by a named lock to prevent concurrent revocation
        races for the same ``(user_id, client_id)`` pair.
        """
        consent = await self._repository.get_by_id(consent_id)
        if consent is None:
            return False

        async with self._lock(f"consent:{consent.user_id}:{consent.client_id}"):
            consent.revoked = True
            consent.revoked_at = utcnow()
            try:
                await self._repository.update(consent)
                return True
            except Exception:
                return False

    async def revoke_user_client_consent(self, user_id: str, client_id: str) -> bool:
        """Revoke consent for a specific user+client pair — O(1) direct path."""
        consent = await self.get_user_consent(user_id, client_id)
        if not consent:
            return False

        async with self._lock(f"consent:{user_id}:{client_id}"):
            consent.revoked = True
            consent.revoked_at = utcnow()
            try:
                await self._repository.update(consent)
                return True
            except Exception:
                return False

    # ------------------------------------------------------------------
    # Listing / cleanup
    # ------------------------------------------------------------------

    async def list_user_consents(self, user_id: str) -> List[OAuth2Consent]:
        """List all consents for a user (sorted by ``granted_at`` desc)."""
        return await self._repository.list_for_user(user_id)

    async def cleanup_expired_consents(self) -> int:
        """Delete all expired consents. Returns the deletion count."""
        return await self._repository.cleanup_expired()

    async def list_all_for_admin(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        email: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List all consents with user + client details for the admin
        view. Filters by *email* substring (case-insensitive) if
        provided. Returns ``(paginated_items, total_count)``.

        The DTO shape matches the original inline-I/O contract in
        ``api/admin.py:1163-1225`` (the admin route used to do its
        own fsspec enumeration — that has now been moved here).
        """
        # Read everything (no on-disk pagination) so the email
        # filter applies to the full set, matching the original
        # behaviour. ``limit`` for the disk read is generous; the
        # File backend has no on-disk index to leverage for
        # pre-filter pagination.
        all_consents = await self._repository.list_all(limit=10_000, offset=0)

        items: List[Dict[str, Any]] = []
        for consent in all_consents:
            user = await self.user_storage.get_user(consent.user_id)
            if not user:
                continue
            if email and email.lower() not in user.email.lower():
                continue
            client = await self.client_storage.get_client(consent.client_id)
            client_name = client.client_name if client else consent.client_id
            items.append(
                {
                    "consent_id": consent.consent_id,
                    "user_email": user.email,
                    "client_id": consent.client_id,
                    "client_name": client_name,
                    "scopes": consent.scopes,
                    "granted_at": consent.granted_at.isoformat(),
                    "expires_at": consent.expires_at.isoformat() if consent.expires_at else None,
                    "revoked": consent.revoked,
                    "revoked_at": consent.revoked_at.isoformat() if consent.revoked_at else None,
                }
            )

        items.sort(key=lambda x: str(x.get("granted_at", "")), reverse=True)
        total = len(items)
        return items[offset : offset + limit], total


def _default_repository(settings: Settings) -> OAuth2ConsentRepository:
    from authglow.repositories.file.oauth_consent import (
        FileOAuth2ConsentRepository,
    )

    return FileOAuth2ConsentRepository(settings)
