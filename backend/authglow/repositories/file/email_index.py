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

    Layout note: ``BaseFileRepository`` requires a non-empty
    ``_subdir``. The email index lives at the storage **root**,
    not in a subdirectory, so we pass ``subdir="."`` to the base
    constructor and override ``_storage_path`` to point back at
    the root (the ``.`` would otherwise show up in the path).
    """

    _filename = "email_index.json"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings=settings, subdir=".")
        # Collapse the "." subdir back to the root so the file
        # lives at <storage>/email_index.json (not <storage>/./...).
        self._storage_path = self._storage_root

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

        *email* is expected to be lower-cased by the caller (the
        service layer enforces this invariant). The repository
        HMAC-hashes the email before reading from the index.
        """
        index = await self._read_index()
        if not isinstance(index, dict):
            return None
        return index.get(hash_index_key(email))

    # ------------------------------------------------------------------
    # Protocol: insert
    # ------------------------------------------------------------------

    async def insert(self, email: str, user_id: str) -> None:
        """Insert a new ``email -> user_id`` mapping.

        If the email is already present, the mapping is overwritten
        — the service layer (``UserStorage.create_user``) is
        responsible for checking uniqueness before calling
        ``insert`` and for raising a domain-level error.

        The write is single-shot and lock-free at the repository
        level: cross-process safety is delegated to the
        ``named_lock("email_index")`` held by ``UserStorage``.
        """
        index = await self._read_index()
        if not isinstance(index, dict):
            index = {}
        index[hash_index_key(email)] = user_id
        await self._write_index(index)

    # ------------------------------------------------------------------
    # Protocol: remove
    # ------------------------------------------------------------------

    async def remove(self, email: str) -> None:
        """Remove the mapping for *email*. No-op if absent."""
        index = await self._read_index()
        if not isinstance(index, dict):
            return
        index.pop(hash_index_key(email), None)
        await self._write_index(index)

    # ------------------------------------------------------------------
    # Protocol: all
    # ------------------------------------------------------------------

    async def all(self) -> Dict[str, str]:
        """Return a snapshot of the entire index as a dict.

        Used by debug + ``count``/``list`` fallback only — the
        service layer prefers ``lookup`` for O(1) reads.
        """
        index = await self._read_index()
        if not isinstance(index, dict):
            return {}
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
