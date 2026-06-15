"""File-backed persistence for MFA and consent sessions.

Both flavours share an on-disk directory but are distinguished by the
filename prefix:

* ``<lookup>.json`` — MFA session (Pydantic model on disk)
* ``consent_<lookup>.json`` — consent session (dict on disk; the
  plaintext ``session_token`` is included for historical reasons)

The repository exposes them as two separate method families so the
service layer never has to know the on-disk naming convention.

The service layer is responsible for HMAC lookup computation, expiry
checks, and the deletion of expired entries. The repository is a
dumb JSON store: ``get`` returns the raw payload or ``None`` on
absent / corrupt file; ``save`` writes a single file; ``delete``
removes it.
"""

from typing import Any, Dict, Optional

from authglow.core.config import Settings
from authglow.models.session import MFASession
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import SessionRepository


class FileSessionRepository(BaseFileRepository, SessionRepository):
    """Persists MFA + consent sessions under one storage directory.

    File layout::

        <storage_path>/sessions/<token_lookup>.json          (MFA)
        <storage_path>/sessions/consent_<token_lookup>.json  (consent)
    """

    _subdir = "sessions"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    @staticmethod
    def _mfa_filename(token_lookup: str) -> str:
        return f"{token_lookup}.json"

    @staticmethod
    def _consent_filename(token_lookup: str) -> str:
        return f"consent_{token_lookup}.json"

    # ------------------------------------------------------------------
    # MFA sessions
    # ------------------------------------------------------------------

    async def save_mfa_session(self, session: MFASession) -> None:
        """Persist an MFA session. Overwrites any prior entry for the
        same lookup."""
        path = self._path(self._mfa_filename(session.token_lookup))
        await self._write_json(path, session.model_dump(mode="json"))

    async def get_mfa_session(self, token_lookup: str) -> Optional[MFASession]:
        """Return the MFA session, or ``None``.

        The repository does **not** auto-delete expired entries: the
        service layer is responsible for that policy.
        """
        path = self._path(self._mfa_filename(token_lookup))
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return MFASession(**data)
        except Exception:
            return None

    async def delete_mfa_session(self, token_lookup: str) -> None:
        """Remove the MFA session. No-op if absent."""
        path = self._path(self._mfa_filename(token_lookup))
        await self._delete(path)

    # ------------------------------------------------------------------
    # Consent sessions
    # ------------------------------------------------------------------

    async def save_consent_session(self, data: Dict[str, Any]) -> None:
        """Persist a consent-session dict. Overwrites any prior entry
        for the same lookup.

        ``data`` MUST contain a ``token_lookup`` key.
        """
        lookup = data.get("token_lookup")
        if not lookup:
            raise ValueError("consent session data must include 'token_lookup'")
        path = self._path(self._consent_filename(lookup))
        await self._write_json(path, data)

    async def get_consent_session(self, token_lookup: str) -> Optional[Dict[str, Any]]:
        """Return the consent-session dict, or ``None``."""
        path = self._path(self._consent_filename(token_lookup))
        data = await self._read_json(path)
        if data is None:
            return None
        return dict(data)

    async def delete_consent_session(self, token_lookup: str) -> None:
        """Remove the consent session. No-op if absent."""
        path = self._path(self._consent_filename(token_lookup))
        await self._delete(path)
