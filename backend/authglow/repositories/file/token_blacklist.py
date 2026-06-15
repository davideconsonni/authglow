"""File-backed persistence for the JWT revocation blacklist.

The repository is intentionally minimal: it knows nothing about the
in-memory cache, the singleton lifecycle, or the lock used by the
service. It only persists and retrieves the ``{jti: expires_at}`` map.

The crash-safe ``tmp + rename`` write is provided by
``BaseFileRepository._write_json_atomic`` (shared with the future
keyring repository, see Fase 20).
"""

from typing import Dict, Optional

from authglow.core.config import Settings
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import TokenBlacklistRepository


class FileTokenBlacklistRepository(BaseFileRepository, TokenBlacklistRepository):
    """Persists the revoked-JTI map as a single JSON file.

    File layout::

        <storage_path>/token_blacklist/entries.json

    Payload shape::

        {"entries": {"<jti>": <expires_at_epoch>, ...}}

    Expired entries are not removed on save — the service layer
    prunes them lazily on read and on every ``revoke`` call that
    triggers the MAX_ENTRIES sweep.
    """

    _subdir = "token_blacklist"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)
        self._entries_path = self._path("entries.json")

    async def load_all(self) -> Dict[str, float]:
        """Return every persisted jti -> expires_at mapping.

        Returns an empty dict when the entries file is missing
        (first boot) or corrupt. Expired entries are not filtered
        here — the service layer is responsible for that.
        """
        data = await self._read_json(self._entries_path)
        if data is None:
            return {}
        return dict(data.get("entries", {}))

    async def save_all(self, entries: Dict[str, float]) -> None:
        """Atomically replace the persisted mapping with *entries*."""
        await self._write_json_atomic(self._entries_path, {"entries": entries})
