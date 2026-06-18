"""File-backed persistence for the JWT revocation blacklist.

One JSON file per revoked JTI so that multiple instances sharing a
single filesystem can detect each other's revocations without restart.
The service layer handles the in-memory cache and sync ``os.path``
checks on the hot path; the repository is responsible for async
hydration, writes, and periodic cleanup.
"""

import os
from typing import Dict, Optional

from authglow.core.config import Settings
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import TokenBlacklistRepository


class FileTokenBlacklistRepository(BaseFileRepository, TokenBlacklistRepository):
    """Persists each revoked JTI as a separate JSON file.

    File layout::

        <storage_path>/token_blacklist/<jti>.json

    Payload shape::

        {"expires_at": <epoch_float>}

    Expired files are NOT auto-deleted on read — the service or a
    periodic cleanup job is responsible for pruning them.
    """

    _subdir = "token_blacklist"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    @staticmethod
    def _filename(jti: str) -> str:
        return f"{jti}.json"

    # ------------------------------------------------------------------
    # Protocol: TokenBlacklistRepository
    # ------------------------------------------------------------------

    async def save(self, jti: str, expires_at: float) -> None:
        """Persist or overwrite the entry for *jti*."""
        path = self._path(self._filename(jti))
        await self._write_json(path, {"expires_at": expires_at})

    async def load_all(self) -> Dict[str, float]:
        """Scan the directory and return every jti -> expires_at."""
        entries: Dict[str, float] = {}
        paths = await self._glob(f"{self._storage_path}/*.json")
        for path in paths:
            data = await self._read_json(path)
            if data is None:
                continue
            expires = data.get("expires_at")
            if not isinstance(expires, (int, float)):
                continue
            jti = os.path.splitext(os.path.basename(path))[0]
            entries[jti] = float(expires)
        return entries

    async def cleanup_expired(self) -> int:
        """Delete every entry whose ``expires_at`` is in the past."""
        import time

        now = time.time()
        removed = 0
        paths = await self._glob(f"{self._storage_path}/*.json")
        for path in paths:
            data = await self._read_json(path)
            if data is None:
                continue
            expires = data.get("expires_at")
            if isinstance(expires, (int, float)) and float(expires) <= now:
                await self._delete(path)
                removed += 1
        return removed
