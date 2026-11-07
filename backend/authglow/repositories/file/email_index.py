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

The in-memory index cache lives for the lifetime of the process
(via ``authglow.repositories.file.index_registry``), not the
request: ``lookup`` and ``all`` are served from it and re-validate
against the file at most once per
``settings.storage_index_refresh_seconds`` (staleness probe, see
:class:`CachedRootIndexRepository`). ``insert`` and ``remove``
start from current on-disk content so entries written by another
replica are merged, never lost, then update the shared cache
(write-through). Concurrency is delegated to the service layer
(``UserStorage`` holds ``named_lock("email_index")`` around
multi-step operations like ``create_user`` and ``update_email``);
the repository methods are single-shot and do not acquire locks
themselves.
"""

from typing import Dict, Optional

from authglow.core.crypto import hash_index_key
from authglow.repositories.file.root_index import CachedRootIndexRepository
from authglow.repositories.protocols import EmailIndexRepository


class FileEmailIndexRepository(CachedRootIndexRepository, EmailIndexRepository):
    """File-backed implementation of :class:`EmailIndexRepository`.

    Stores the index as a single JSON object at
    ``<storage>/email_index.json`` mapping
    ``hash_index_key(email)`` -> ``user_id``.

    The caller is responsible for lower-casing the email before
    calling ``lookup`` / ``insert`` / ``remove`` (the public API
    of the service layer enforces this).

    ``lookup`` and ``all`` read from the process-wide in-memory
    index and never touch disk until the staleness probe interval
    elapses; ``insert`` and ``remove`` are write-through: they
    re-read the file first (read-modify-write merge), mutate both
    the on-disk file and the in-memory dict.
    """

    _filename = "email_index.json"

    # ------------------------------------------------------------------
    # Protocol: lookup
    # ------------------------------------------------------------------

    async def lookup(self, email: str) -> Optional[str]:
        """Return the user_id mapped to *email*, or ``None``.

        Reads from the in-memory index (loaded from disk on first
        access, refreshed by the staleness probe).
        """
        index = await self._ensure_index_loaded()
        return index.get(hash_index_key(email))

    # ------------------------------------------------------------------
    # Protocol: insert
    # ------------------------------------------------------------------

    async def insert(self, email: str, user_id: str) -> None:
        """Insert a new ``email -> user_id`` mapping.

        Read-modify-write starts from the current on-disk file (so
        foreign entries merge) and the shared cache is updated
        through the same dict (write-through). Overwrites an existing
        mapping for the same key — the service layer performs the
        duplicate check before calling.
        """
        index = await self._load_index_fresh()
        index[hash_index_key(email)] = user_id
        await self._write_index(index)

    # ------------------------------------------------------------------
    # Protocol: remove
    # ------------------------------------------------------------------

    async def remove(self, email: str) -> None:
        """Remove the mapping for *email*. No-op if absent.
        Write-through: re-reads the file first, then updates both
        the on-disk file and the shared cache."""
        index = await self._load_index_fresh()
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
