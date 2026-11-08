"""Base class for storage-root JSON index repositories with a
process-lifetime cache.

The root-level indexes (``email_index.json``,
``federated_identities.json``) are flat ``key -> user_id`` dicts read
on the login hot path. When each HTTP request constructed its own
repository instance, the in-memory copy died with the request, so
every upper-cache miss re-read and re-parsed the **whole** file —
a cost that grows with the user base.

This base owns the cache lifecycle:

* **Cached reads** — ``_ensure_index_loaded`` serves lookups from the
  in-memory dict; the first call loads from disk.
* **Staleness probe** — once ``storage_index_refresh_seconds``
  (``0`` disables it) has elapsed since the last load/probe, the next
  cached read re-reads the file and swaps the dict in when the content
  differs, so writes from *another replica* become visible within one
  interval. Same design as ``core/jwt_singleton.py`` — minus the
  ``asyncio.Lock``, which binds to the first event loop it awaits on
  and breaks multi-``asyncio.run`` test suites (PERF-001 lesson).
  The interval is consumed before the I/O with no interleaving await,
  so concurrent callers pile up at most one re-read per interval.
* **Fresh-merge writes** — mutation paths use ``_load_index_fresh``:
  the read-modify-write always starts from current on-disk content,
  so entries created by other processes are merged, not lost —
  exactly the pre-cache behaviour.

Instances are shared process-wide through
``authglow.repositories.file.index_registry`` (file backend only;
other backends keep per-call construction). Mutations remain guarded
by the service-layer ``named_lock("email_index")`` /
``named_lock("federated_identities")``.
"""

from datetime import datetime
from typing import Dict, Optional

import structlog

from authglow.core.config import Settings
from authglow.core.datetime import utcnow
from authglow.repositories.file.base import BaseFileRepository

_probe_log = structlog.get_logger("authglow.storage")


class CachedRootIndexRepository(BaseFileRepository):
    """Common scaffolding for single-file root indexes with a cache
    that outlives the request that loaded it.

    Subclasses set ``_filename`` and call the two access helpers:

    * read paths (``lookup`` / ``all``) → ``_ensure_index_loaded``
    * write paths (insert / remove / link / unlink) →
      ``_load_index_fresh``, mutate, ``_write_index``
    """

    _filename: str = ""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        """Initialise the repository with an empty lazy cache.

        No I/O happens here — the index is read on first access, so
        constructing (and sharing) the instance stays cheap and
        event-loop agnostic.
        """
        super().__init__(settings=settings, subdir=".")
        # The index file lives at the storage root, not in a
        # subdirectory — pre-refactor layout. Collapse the "." subdir
        # back to the root so paths never leak "./" segments.
        self._storage_path = self._storage_root
        self._index_cache: Optional[Dict[str, str]] = None
        self._index_loaded: bool = False
        self._last_probe: Optional[datetime] = None

    # ------------------------------------------------------------------
    # Path helper
    # ------------------------------------------------------------------

    def _index_path(self) -> str:
        """Return the on-disk path for this repository's index file."""
        return f"{self._storage_root}/{self._filename}"

    # ------------------------------------------------------------------
    # I/O primitives
    # ------------------------------------------------------------------

    async def _read_index(self) -> Dict[str, str]:
        """Read the index file. Returns ``{}`` on missing or corrupt
        JSON."""
        data = await self._read_json(self._index_path())
        if not isinstance(data, dict):
            return {}
        return data

    async def _write_index(self, index: Dict[str, str]) -> None:
        """Write the index file. Atomic-ish (``_write_json_atomic``:
        crash-safe on local filesystems, plain write on cloud
        backends)."""
        await self._write_json_atomic(self._index_path(), index)

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _probe_interval_seconds(self) -> int:
        """Probe interval from settings; anything that is not an int
        (e.g. auto-created attributes on a MagicMock settings in
        tests) means "probe disabled" — the same fail-tolerant
        convention as ``_resolve_backend_name``."""
        interval = getattr(self._settings, "storage_index_refresh_seconds", 0)
        return interval if isinstance(interval, int) else 0

    async def _ensure_index_loaded(self) -> Dict[str, str]:
        """Return the in-memory index, loading or probing disk as needed.

        Loads on first access; afterwards serves from memory and
        re-validates against the file only once the probe interval has
        elapsed. Probe I/O failures are logged and swallowed — reads
        keep being served from the (possibly stale) cache and the probe
        retries after one full new interval.
        """
        if not self._index_loaded:
            self._index_cache = await self._read_index()
            self._index_loaded = True
            self._last_probe = utcnow()
            return self._index_cache

        # ``_index_loaded`` implies a dict has been assigned; keep the
        # exact cached object (identity included) for the return type.
        cache = self._index_cache if self._index_cache is not None else {}

        interval = self._probe_interval_seconds()
        if interval <= 0:
            return cache
        assert self._last_probe is not None
        if (utcnow() - self._last_probe).total_seconds() < interval:
            return cache

        # Consume the interval *before* the I/O. There is no await
        # between the freshness check above and this assignment, so on
        # a single event-loop thread only one caller can ever pass the
        # check per interval.
        self._last_probe = utcnow()
        try:
            fresh = await self._read_index()
        except Exception:
            _probe_log.warning("index_probe_failed", index=self._filename, exc_info=True)
            return cache
        if fresh != self._index_cache:
            _probe_log.info("index_reloaded_after_foreign_change", index=self._filename)
            self._index_cache = fresh
            return fresh
        return cache

    async def _load_index_fresh(self) -> Dict[str, str]:
        """Re-read the index from disk for read-modify-write paths.

        Mutations must start from the current on-disk content so
        entries written by other processes survive the merge — the
        cache is then replaced with that same dict (write-through) and
        the probe timer restarts.
        """
        index = await self._read_index()
        self._index_cache = index
        self._index_loaded = True
        self._last_probe = utcnow()
        return index
