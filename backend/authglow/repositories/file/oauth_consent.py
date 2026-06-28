"""File-backed persistence for OAuth2 consent records.

Consents are stored at a deterministic two-level path layout
(``{user_id}/{client_id}.json``) for O(1) direct lookup on the
hot path (``get_for_user_client``). The admin operations
(``get_by_id``, ``list_for_user``, ``list_all``) scan the
directory tree — these are cold paths, acceptable cost.

The repository owns:

* the path layout and JSON serialisation;
* the Pydantic round-trip (with transparent ``_version`` strip);
* the bulk expired-consent cleanup that returns a deletion count;
* the O(1) direct lookup by ``(user_id, client_id)``.

The service layer in ``services/oauth_consent.py`` owns:

* the in-process ``named_lock`` for revocation races;
* the user + client lookups (peer services) when building the
  admin DTOs;
* the email filter and the public ``list_all_for_admin`` API
  consumed by ``api/admin.py``.
"""

from typing import List, Optional

from authglow.core.config import Settings
from authglow.core.datetime import utcnow
from authglow.models.oauth_consent import OAuth2Consent
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import OAuth2ConsentRepository


class FileOAuth2ConsentRepository(BaseFileRepository, OAuth2ConsentRepository):
    """Persists OAuth2 consent records.

    File layout::

        <storage_path>/oauth_consents/<user_id>/<client_id>.json
    """

    _subdir = "oauth_consents"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _path_for(self, user_id: str, client_id: str) -> str:
        return self._path(f"{user_id}/{client_id}.json")

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create(self, consent: OAuth2Consent) -> None:
        """Persist a new consent (upsert by user_id + client_id)."""
        path = self._path_for(consent.user_id, consent.client_id)
        await self._ensure_parent(path)
        await self._write_json(path, consent.model_dump())

    async def get_by_id(self, consent_id: str) -> Optional[OAuth2Consent]:
        """Admin: scan all consents to find one by consent_id.

        Returns the consent + its ``(user_id, client_id)`` location
        so the caller can construct the deterministic path. The
        service layer wraps this and discards the location.
        """
        paths = await self._glob(f"{self._storage_path}/**/*.json")
        for path in paths:
            data = await self._read_json(path)
            if data is None:
                continue
            if data.get("consent_id") == consent_id:
                try:
                    return OAuth2Consent(**data)
                except Exception:
                    return None
        return None

    async def get_for_user_client(self, user_id: str, client_id: str) -> Optional[OAuth2Consent]:
        """O(1) direct lookup. Auto-deletes expired consents."""
        path = self._path_for(user_id, client_id)
        if not await self._exists(path):
            return None
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            consent = OAuth2Consent(**data)
        except Exception:
            return None
        if consent.revoked:
            return None
        if consent.expires_at and utcnow() > consent.expires_at:
            await self._delete(path)
            return None
        return consent

    async def update(self, consent: OAuth2Consent) -> None:
        """Persist changes (e.g. revocation)."""
        path = self._path_for(consent.user_id, consent.client_id)
        await self._ensure_parent(path)
        await self._write_json(path, consent.model_dump())

    async def delete_for_user_client(self, user_id: str, client_id: str) -> bool:
        """Delete the consent for the ``(user_id, client_id)`` pair."""
        return await self._delete(self._path_for(user_id, client_id))

    async def delete_for_user(self, user_id: str) -> int:
        """Delete every consent belonging to ``user_id``.

        VAPT-082: GDPR right-to-erasure. Drops the
        ``{user_id}/`` subdirectory and every ``*.json`` file in
        it. Best-effort: if the directory removal fails, the
        file deletions still happened.
        """
        paths = await self._glob(f"{self._storage_path}/{user_id}/*.json")
        deleted = 0
        for path in paths:
            if await self._delete(path):
                deleted += 1
        try:
            remaining = await self._glob(f"{self._storage_path}/{user_id}/*.json")
            if not remaining:
                await self._afs.rm(f"{self._storage_path}/{user_id}", recursive=False)
        except Exception:
            pass
        return deleted

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    async def list_for_user(self, user_id: str) -> List[OAuth2Consent]:
        """Return every consent granted by *user_id* (sorted by
        ``granted_at`` desc)."""
        paths = await self._glob(f"{self._storage_path}/{user_id}/*.json")
        consents: List[OAuth2Consent] = []
        for path in paths:
            data = await self._read_json(path)
            if data is None:
                continue
            try:
                consent = OAuth2Consent(**data)
            except Exception:
                continue
            consents.append(consent)
        consents.sort(key=lambda c: c.granted_at, reverse=True)
        return consents

    async def list_all(self, *, limit: int = 100, offset: int = 0) -> List[OAuth2Consent]:
        """Admin: return a paginated slice of every consent."""
        paths = await self._glob(f"{self._storage_path}/**/*.json")
        consents: List[OAuth2Consent] = []
        for path in paths:
            data = await self._read_json(path)
            if data is None:
                continue
            try:
                consent = OAuth2Consent(**data)
            except Exception:
                continue
            consents.append(consent)
        consents.sort(key=lambda c: c.granted_at, reverse=True)
        return consents[offset : offset + limit]

    async def cleanup_expired(self, *, cutoff: Optional[str] = None) -> int:
        """Delete every consent whose ``expires_at`` is in the
        past, or whose ``revoked_at`` is older than ``cutoff``.

        VAPT-086: ``cutoff`` is an ISO-8601 string; if supplied,
        revoked consents older than ``cutoff`` are also
        dropped (drives the retention sweep). ``expires_at``
        dropping is independent of the cutoff and runs on the
        natural expiry.
        """
        from datetime import datetime as dt

        paths = await self._glob(f"{self._storage_path}/**/*.json")
        deleted = 0
        now = utcnow()
        cutoff_dt = dt.fromisoformat(cutoff) if cutoff else None
        for path in paths:
            data = await self._read_json(path)
            if data is None:
                continue
            try:
                consent = OAuth2Consent(**data)
            except Exception:
                continue
            should_drop = False
            if consent.expires_at and now > consent.expires_at:
                should_drop = True
            elif (
                cutoff_dt
                and consent.revoked
                and consent.revoked_at
                and consent.revoked_at < cutoff_dt
            ):
                should_drop = True
            if should_drop:
                await self._delete(path)
                deleted += 1
        return deleted
