"""JWT access-token revocation blacklist with disk persistence.

This service used to live in ``authglow.core.token_blacklist``; the
Fase 1 refactor split it into a thin in-memory service (this module)
and a file-backed repository (``authglow.repositories.file.token_blacklist``).

Layer split:

* **Service** (this module) — process singleton, holds the
  in-memory ``_store`` dict, exposes the sync ``is_revoked()`` hot
  path and the async ``revoke()`` / ``startup_hydrate()`` cold paths.
* **Repository** — pure I/O, no state. Persists the
  ``{jti: expires_at_epoch}`` map to a single JSON file using a
  crash-safe ``tmp + rename`` write.

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

        # Check (sync — in-memory only, no I/O)
        if token_blacklist().is_revoked("jti-123"):
            raise HTTPException(401)
    """

    MAX_ENTRIES = 10_000

    def __init__(self, repository: Optional[TokenBlacklistRepository] = None) -> None:
        """Construct the service.

        Args:
            repository: Backend for the ``{jti: expires_at}`` map.
                Defaults to ``get_token_blacklist_repository()`` (the
                file implementation). Tests may pass an in-memory
                stub or patch the factory to swap backends.
        """
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
        """Load persisted entries from disk into the in-memory cache.

        Must be called once at application startup (e.g. in a lifespan
        handler). Expired entries are pruned during hydration. If
        pruning removed any entries, the cleaned map is persisted
        back so the on-disk state matches the in-memory state.
        """
        entries = await self._repository.load_all()
        now = time.time()
        pruned = {jti: exp for jti, exp in entries.items() if exp > now}
        self._store = pruned

        if len(pruned) < len(entries):
            await self._repository.save_all(pruned)

        self._initialized = True

    async def revoke(self, jti: str, expires_at: float) -> None:
        """Add a token JTI to the blacklist and persist to disk.

        *expires_at* is a POSIX timestamp (``time.time()``). The entry
        is kept until the token would have expired anyway. Revoking
        an already-revoked token overwrites the existing entry
        (idempotent).
        """
        if expires_at <= time.time():
            return

        async with self._lock("token_blacklist"):
            if len(self._store) >= self.MAX_ENTRIES:
                self._sweep()

            self._store[jti] = expires_at
            await self._repository.save_all(self._store)

    def is_revoked(self, jti: str) -> bool:
        """Check if a token JTI has been revoked (in-memory only, no I/O).

        The in-memory ``_store`` is the single source of truth. The
        service is "functionally empty" when ``_store`` is empty,
        regardless of whether ``startup_hydrate`` has been called.
        This makes the service safe to use even before hydration
        (returns ``False`` for every jti) and after hydration (reads
        from the populated ``_store``).
        """
        if jti not in self._store:
            return False
        expires_at = self._store[jti]
        if expires_at <= time.time():
            del self._store[jti]
            return False
        return True

    # ------------------------------------------------------------------
    # Internal — in-memory only
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
    """Return the process-global ``TokenBlacklist`` singleton.

    On first call the service is constructed with a fresh
    ``FileTokenBlacklistRepository``. The service itself holds the
    in-memory ``_store`` and the ``named_lock`` for in-process
    serialisation; the repository is stateless beyond its fsspec
    handles.
    """
    global _token_blacklist
    if _token_blacklist is None:
        _token_blacklist = TokenBlacklist()
    return _token_blacklist


def _reset_token_blacklist() -> None:
    """Reset the blacklist singleton (for testing only).

    The next call to ``token_blacklist()`` will construct a fresh
    service with a fresh repository instance pointing at the
    (test-isolated) ``storage_path`` from the autouse ``test_settings``
    fixture.
    """
    global _token_blacklist
    _token_blacklist = None
