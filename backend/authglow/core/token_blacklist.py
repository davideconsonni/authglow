"""Token blacklist for JWT access token revocation with disk persistence.

Dual-layer architecture for serverless resilience:

* **In-memory dict** — fast sync path for ``is_revoked()``, called on every
  auth request.  Zero I/O in the hot path.
* **Disk persistence** — ``{storage_path}/token_blacklist/entries.json``,
  written atomically on every revocation.  On process restart the in-memory
  cache is hydrated from disk via ``startup_hydrate()``.

RFC 7009 compliant: revoking an already-revoked token is idempotent,
revoking a non-existent token is silently accepted.
"""

import os
import time
from typing import Dict, Optional

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings


class TokenBlacklist:
    """Persistent revocation store for access-token JTIs.

    Usage::

        # At app startup (async)
        await token_blacklist().startup_hydrate()

        # Revoke (async — writes to disk + in-memory)
        await token_blacklist().revoke("jti-123", expires_at)

        # Check (sync — in-memory only, no I/O)
        if token_blacklist().is_revoked("jti-123"):
            raise HTTPException(401)
    """

    MAX_ENTRIES = 10_000

    def __init__(self) -> None:
        self._store: Dict[str, float] = {}
        self._initialized: bool = False
        self._afs: Optional[AsyncFileSystem] = None
        self._storage_path: str = ""
        self._entries_path: str = ""
        self._lock = named_lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def startup_hydrate(self) -> None:
        """Load persisted entries from disk into the in-memory cache.

        Must be called once at application startup (e.g. in a lifespan
        handler).  Expired entries are pruned during hydration.
        """
        await self._ensure_initialized()
        await self._hydrate()

    async def revoke(self, jti: str, expires_at: float) -> None:
        """Add a token JTI to the blacklist and persist to disk.

        *expires_at* is a POSIX timestamp (``time.time()``).  The entry
        is kept until the token would have expired anyway.
        """
        await self._ensure_initialized()

        if expires_at <= time.time():
            return

        async with self._lock("token_blacklist"):
            # Prune when the dict gets large
            if len(self._store) >= self.MAX_ENTRIES:
                self._sweep()

            self._store[jti] = expires_at
            await self._persist()

    def is_revoked(self, jti: str) -> bool:
        """Check if a token JTI has been revoked (in-memory only, no I/O)."""
        if not self._initialized:
            return False
        if jti not in self._store:
            return False
        expires_at = self._store[jti]
        if expires_at <= time.time():
            del self._store[jti]
            return False
        return True

    # ------------------------------------------------------------------
    # Internal — disk persistence
    # ------------------------------------------------------------------

    async def _ensure_initialized(self) -> None:
        """Lazy-init fsspec and paths from Settings."""
        if self._initialized:
            return

        settings = get_settings()
        self._storage_path = settings.storage_path

        os.makedirs(os.path.join(self._storage_path, "token_blacklist"), exist_ok=True)
        self._entries_path = os.path.join(self._storage_path, "token_blacklist", "entries.json")

        if settings.storage_backend == "file":
            self._fs = fsspec.filesystem("file")
        else:
            self._fs = fsspec.filesystem(settings.storage_backend, **settings.get_storage_options())

        self._afs = AsyncFileSystem(self._fs)
        self._initialized = True

    async def _hydrate(self) -> None:
        """Load all non-expired entries from disk."""
        assert self._afs is not None  # narrowed after _ensure_initialized
        try:
            data = await self._afs.read_json(self._entries_path)
            entries: Dict[str, float] = data.get("entries", {})
        except Exception:
            return

        now = time.time()
        self._store = {jti: exp for jti, exp in entries.items() if exp > now}

        # If we pruned any expired entries, write back a clean file
        if len(self._store) < len(entries):
            await self._persist()

    async def _persist(self) -> None:
        """Atomically write the in-memory store to disk.

        Uses the tmp+rename pattern (same as jwt._save_keyring) for
        crash-safe writes.
        """
        assert self._afs is not None  # narrowed after _ensure_initialized
        tmp_path = self._entries_path + ".tmp"
        await self._afs.write_json(tmp_path, {"entries": self._store})
        os.replace(tmp_path, self._entries_path)

    def _sweep(self) -> None:
        """Remove every entry whose expiry has passed."""
        now = time.time()
        self._store = {jti: exp for jti, exp in self._store.items() if exp > now}


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_token_blacklist: Optional[TokenBlacklist] = None


def token_blacklist() -> TokenBlacklist:
    """Return the process-global ``TokenBlacklist`` singleton."""
    global _token_blacklist
    if _token_blacklist is None:
        _token_blacklist = TokenBlacklist()
    return _token_blacklist


def _reset_token_blacklist() -> None:
    """Reset the blacklist singleton (for testing only)."""
    global _token_blacklist
    _token_blacklist = None
