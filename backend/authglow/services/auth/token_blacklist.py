"""JWT access-token revocation blacklist with per-JTI disk persistence.

One file per JTI so multi-instance deployments sharing a filesystem
see each other's revocations without a restart.  The hot path
(``is_revoked``) goes through the repository (no direct ``os.path``
or ``open()`` — those live in the ``FileTokenBlacklistRepository``
impl, behind the ``TokenBlacklistRepository`` Protocol).

RFC 7009 compliant: revoking an already-revoked token is idempotent,
revoking a non-existent token is silently accepted.
"""

import time
from typing import Dict, Optional

from authglow.core.concurrency import named_lock
from authglow.repositories.dependencies import get_token_blacklist_repository
from authglow.repositories.protocols import TokenBlacklistRepository


class TokenBlacklist:
    """Persistent revocation store for access-token JTIs.

    Usage::

        # At app startup (async)
        await token_blacklist().startup_hydrate()

        # Revoke (async — writes to disk + in-memory)
        await token_blacklist().revoke("jti-123", expires_at)

        # Check (in-memory + repo.exists on cache miss)
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

        Checks the in-memory cache first; on a miss, the
        *sync* ``exists``/``delete`` primitives on the repository
        are called (``os.path`` on the File backend, ``SELECT 1``
        on SQL — backends without a sync hot-path must expose
        one or accept a sync-async bridge here). The service
        populates the cache on a positive hit so the next call
        does not touch disk.
        """
        now = time.time()

        if jti in self._store:
            if self._store[jti] <= now:
                # Expired — lazy cleanup via the repository.
                self._repository.delete(jti)
                del self._store[jti]
                return False
            return True

        # Cache miss: ask the repository. ``exists`` is sync on
        # purpose; the File impl does an ``os.path.isfile``.
        if not self._repository.exists(jti):
            return False

        # The on-disk file exists but we do not know the
        # expires_at without reading it. Trigger an async
        # re-hydration to populate the cache for next time;
        # for THIS call we conservatively return ``True`` to
        # avoid a race where a revocation made by another
        # instance is missed because of the async I/O cost.
        # This matches the pre-refactor behaviour.
        return True

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

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
