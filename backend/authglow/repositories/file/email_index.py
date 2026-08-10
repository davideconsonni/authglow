"""File-system-backed repository for the email -> user_id index.

On-disk layout (relative to ``settings.storage_path``):

* ``<storage>/email_index.json`` — a flat dict mapping
  ``hash_index_key(email)`` to ``user_id``.

The pre-refactor ``UserStorage`` owned this index inline (in
``services/storage.py``) with two helpers: ``_load_email_index`` and
``_save_email_index``. The ``hash_index_key`` helper is in
``authglow.core.crypto`` and HMAC-SHA256s the lower-cased email —
plaintext email is never written to disk.

This repository implements :class:`EmailIndexRepository` with
``lookup`` / ``insert`` / ``remove`` / ``all`` semantics. The
caller (``UserStorage``) is expected to lower-case the email
**before** calling the repository (the File implementation does
not duplicate the lower-casing, to avoid surprising the service
layer's invariant that ``email.lower()`` is the canonical form).

The underlying fsspec filesystem and ``AsyncFileSystem`` wrapper
are managed by :class:`BaseFileRepository`, which also provides
the atomic-write helper for the index file. Concurrency is
delegated to the service layer (``UserStorage`` already holds
a ``named_lock("email_index")`` around multi-step operations
like ``create_user`` and ``update_email``); the repository
methods are single-shot and do not acquire locks themselves.
"""

from typing import Dict, Optional

from authglow.core.config import Settings
from authglow.core.crypto import hash_index_key
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import EmailIndexRepository


class FileEmailIndexRepository(BaseFileRepository, EmailIndexRepository):
    """File-backed implementation of :class:`EmailIndexRepository`.

    Stores the index as a single JSON object at
    ``<storage>/email_index.json`` mapping
    ``hash_index_key(email)`` -> ``user_id``.

    The caller is responsible for lower-casing the email before
    calling ``lookup`` / ``insert`` / ``remove`` (the public API
    of the service layer enforces this).

    The entire index is loaded into an in-memory dict on first
    access and kept in sync via write-through: ``insert`` and
    ``remove`` mutate both the in-memory dict and the on-disk
    file under the caller's ``named_lock("email_index")``.
    ``lookup`` and ``all`` read from memory and never touch disk.
    """

    _filename = "email_index.json"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings=settings, subdir=".")
        self._storage_path = self._storage_root
        self._index_cache: Optional[Dict[str, str]] = None
        self._index_loaded: bool = False

    # ------------------------------------------------------------------
    # In-memory cache (write-through)
    # ------------------------------------------------------------------

    async def _ensure_index_loaded(self) -> Dict[str, str]:
        if not self._index_loaded:
            index = await self._read_index()
            self._index_cache = index
            self._index_loaded = True
        assert self._index_cache is not None
        return self._index_cache

    # ------------------------------------------------------------------
    # Path helper (overrides default BaseFileRepository._path semantics)
    # ------------------------------------------------------------------

    def _index_path(self) -> str:
        """Return the on-disk path for the email index file.

        The index lives at the storage root, not in a subdirectory
        — pre-refactor layout: ``<storage>/email_index.json``.
        """
        return f"{self._storage_root}/{self._filename}"

    # ------------------------------------------------------------------
    # Protocol: lookup
    # ------------------------------------------------------------------

    async def lookup(self, email: str) -> Optional[str]:
        """Return the user_id mapped to *email*, or ``None``.

        Reads from the in-memory index (loaded from disk on first
        access, kept in sync via write-through).
        """
        index = await self._ensure_index_loaded()
        return index.get(hash_index_key(email))

    # ------------------------------------------------------------------
    # Protocol: insert
    # ------------------------------------------------------------------

    async def insert(self, email: str, user_id: str) -> None:
        """Insert a new ``email -> user_id`` mapping. Write-through:
        both the in-memory dict and the on-disk file are updated.
        """
        index = await self._ensure_index_loaded()
        index[hash_index_key(email)] = user_id
        await self._write_index(index)

    # ------------------------------------------------------------------
    # Protocol: remove
    # ------------------------------------------------------------------

    async def remove(self, email: str) -> None:
        """Remove the mapping for *email*. No-op if absent.
        Write-through: both in-memory dict and on-disk file."""
        index = await self._ensure_index_loaded()
        if hash_index_key(email) not in index:
            return
        index.pop(hash_index_key(email), None)
        await self._write_index(index)

    # ------------------------------------------------------------------
    # Protocol: all
    # ------------------------------------------------------------------

    async def all(self) -> Dict[str, str]:
        """Return a snapshot of the entire in-memory index."""
        index = await self._ensure_index_loaded()
        return dict(index)

    # ------------------------------------------------------------------
    # I/O helpers
    # ------------------------------------------------------------------

    async def _read_index(self) -> Dict[str, str]:
        """Read the email index file. Returns ``{}`` on missing or
        corrupt JSON."""
        data = await self._read_json(self._index_path())
        if not isinstance(data, dict):
            return {}
        return data

    async def _write_index(self, index: Dict[str, str]) -> None:
        """Write the email index file. Atomic-ish (uses the
        ``_write_json_atomic`` helper for crash safety on local
        filesystems; cloud backends fall back to plain write)."""
        await self._write_json_atomic(self._index_path(), index)
