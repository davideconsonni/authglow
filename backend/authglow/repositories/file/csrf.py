"""File-backed persistence for CSRF tokens.

Tokens are stored one-per-session, identified by the HMAC of the
session id (not the session id itself, to make directory listings
non-enumerable). The token is persisted as a SHA-256 hash; the
plaintext never lands on disk.

The repository is responsible for the file layout, JSON serialisation,
and bulk-cleanup glob logic. The service layer is responsible for the
throttling of the periodic sweep (in-process state), for generating
the session id and token, and for the HMAC lookup / SHA-256 hash
helpers.
"""

from typing import Any, Dict, Optional

from authglow.core.config import Settings
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import CSRFTokenRepository


class FileCSRFTokenRepository(BaseFileRepository, CSRFTokenRepository):
    """Persists CSRF tokens as one JSON file per session.

    File layout::

        <storage_path>/csrf_tokens/<hmac(session_id)>.json

    Payload shape::

        {"token_hash": "<sha256>",
         "expires_at": <epoch_float>,
         "created_at": <epoch_float>}

    The on-disk name is the HMAC lookup key — never the session id
    itself — so that directory listings cannot enumerate sessions.
    """

    _subdir = "csrf_tokens"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    @staticmethod
    def _filename(session_lookup: str) -> str:
        return f"{session_lookup}.json"

    async def save(
        self,
        session_lookup: str,
        token_hash: str,
        expires_at: float,
        created_at: float,
    ) -> None:
        """Persist the CSRF state for a session. Overwrites any
        prior entry for the same session."""
        path = self._path(self._filename(session_lookup))
        await self._write_json(
            path,
            {
                "token_hash": token_hash,
                "expires_at": expires_at,
                "created_at": created_at,
            },
        )

    async def get(self, session_lookup: str) -> Optional[Dict[str, Any]]:
        """Return ``{token_hash, expires_at, created_at}`` or ``None``.

        The repository does not auto-delete expired entries on read:
        the service layer decides whether to delete (e.g. inside
        ``validate_token``) based on its own expiry policy.
        """
        path = self._path(self._filename(session_lookup))
        return await self._read_json(path)

    async def delete(self, session_lookup: str) -> None:
        """Remove the entry. No-op if absent."""
        path = self._path(self._filename(session_lookup))
        await self._delete(path)

    async def cleanup_expired(self) -> None:
        """Delete every entry whose ``expires_at`` is in the past."""
        glob_pattern = f"{self._storage_path}/*.json"
        paths = await self._glob(glob_pattern)
        now = _now_epoch()
        for path in paths:
            try:
                data = await self._read_json(path)
            except Exception:
                continue
            if data is None:
                continue
            if now > float(data.get("expires_at", 0)):
                await self._delete(path)


def _now_epoch() -> float:
    """``time.time()`` shim so the function is mockable in tests."""
    import time

    return time.time()
