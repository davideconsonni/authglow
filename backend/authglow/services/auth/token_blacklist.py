"""JWT access-token revocation blacklist with per-JTI disk persistence.

One file per JTI so multi-instance deployments sharing a filesystem
see each other's revocations without a restart.  The hot path
(``is_revoked``) is sync and falls back to ``os.path`` when a JTI is
not in the in-memory cache.

RFC 7009 compliant: revoking an already-revoked token is idempotent,
revoking a non-existent token is silently accepted.
"""

import json
import os
import time
from typing import Dict, Optional

from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.repositories.dependencies import get_token_blacklist_repository
from authglow.repositories.protocols import TokenBlacklistRepository


class TokenBlacklist:
    """Persistent revocation store for access-token JTIs.

    Usage::

        # At app startup (async)
        await token_blacklist().startup_hydrate()

        # Revoke (async — writes to disk + in-memory)
        await token_blacklist().revoke("jti-123", expires_at)

        # Check (sync — in-memory + os.path fallback)
        if token_blacklist().is_revoked("jti-123"):
            raise HTTPException(401)
    """

    MAX_ENTRIES = 10_000

    def __init__(self, repository: Optional[TokenBlacklistRepository] = None) -> None:
        self._repository: TokenBlacklistRepository = (
            repository if repository is not None else get_token_blacklist_repository()
        )
        self._store: Dict[str, float] = {}
        self._initialized: bool = False
        self._lock = named_lock()

        if hasattr(self._repository, "_storage_path"):
            self._blacklist_dir: str = self._repository._storage_path
        else:
            settings = get_settings()
            self._blacklist_dir = os.path.join(settings.storage_path, "token_blacklist")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def startup_hydrate(self) -> None:
        """Load persisted entries from disk into the in-memory cache."""
        entries = await self._repository.load_all()
        now = time.time()
        self._store = {jti: exp for jti, exp in entries.items() if exp > now}
        self._initialized = True

    async def revoke(self, jti: str, expires_at: float) -> None:
        """Add a token JTI to the blacklist and persist to disk."""
        if expires_at <= time.time():
            return

        async with self._lock("token_blacklist"):
            if len(self._store) >= self.MAX_ENTRIES:
                self._sweep()

            self._store[jti] = expires_at
            await self._repository.save(jti, expires_at)

    def is_revoked(self, jti: str) -> bool:
        """Check if a token JTI has been revoked.

        Checks the in-memory cache first; on a miss, falls back to
        a sync ``os.path`` existence check so that revocations made
        by other instances are visible immediately.
        """
        now = time.time()

        if jti in self._store:
            if self._store[jti] <= now:
                del self._store[jti]
                return False
            return True

        if self._check_disk(jti, now):
            return True

        return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check_disk(self, jti: str, now: float) -> bool:
        """Sync check for a JTI file on disk. Caches and cleans up."""
        path = os.path.join(self._blacklist_dir, f"{jti}.json")
        try:
            if not os.path.isfile(path):
                return False
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                expires_at = float(data.get("expires_at", 0))
        except Exception:
            return False

        if expires_at <= now:
            try:
                os.remove(path)
            except Exception:
                pass
            return False

        self._store[jti] = expires_at
        return True

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
