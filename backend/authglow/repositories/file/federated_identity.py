"""File-system-backed repository for the (provider_id, external_id) -> user_id index.

On-disk layout (relative to ``settings.storage_path``):

* ``<storage>/federated_identities.json`` — a flat dict mapping
  the composite key ``f"{provider_id}|{external_id}"`` to ``user_id``.

The pre-refactor ``UserStorage`` owned this index inline (in
``services/storage.py``) with two helpers: ``_load_federated_identities``
and ``_save_federated_identities``. The ``_make_identity_key`` helper
forms the composite key from ``(provider_id, external_id)``.

This repository implements :class:`FederatedIdentityRepository` with
``lookup`` / ``link`` / ``unlink`` semantics. ``link`` raises
``EntityAlreadyExistsError`` if the (provider, external) pair is
already linked to a different user — this matches the
``UserStorage.link_federated_identity`` contract (which used to
raise ``ValueError``; the repository uses a domain-level
exception for backend portability).

The in-memory index cache lives for the lifetime of the process
(via ``authglow.repositories.file.index_registry``), not the
request: before this, every ``lookup`` re-read and re-parsed the
whole file (the federated login path has no upper cache, so that
was an O(index) cost per login). ``lookup`` is served from the
cache and re-validated against the file at most once per
``settings.storage_index_refresh_seconds`` (staleness probe, see
:class:`CachedRootIndexRepository`); ``link`` and ``unlink``
re-read from disk first so entries written by another replica are
merged, never lost. Cross-process safety is delegated to the
``named_lock("federated_identities")`` held by ``UserStorage``
(``link`` / ``get_by_external_id`` paths).
"""

from typing import Optional

from authglow.repositories.exceptions import EntityAlreadyExistsError
from authglow.repositories.file.root_index import CachedRootIndexRepository
from authglow.repositories.protocols import FederatedIdentityRepository


class FileFederatedIdentityRepository(CachedRootIndexRepository, FederatedIdentityRepository):
    """File-backed implementation of :class:`FederatedIdentityRepository`.

    Stores the index as a single JSON object at
    ``<storage>/federated_identities.json`` mapping
    ``"{provider_id}|{external_id}"`` -> ``user_id``.

    Layout note: ``BaseFileRepository`` requires a non-empty
    ``_subdir``. The federated identities file lives at the
    storage **root**, not in a subdirectory, so
    :class:`CachedRootIndexRepository` passes ``subdir="."`` to the
    base constructor and collapses ``_storage_path`` back to the
    root.
    """

    _filename = "federated_identities.json"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_key(self, provider_id: str, external_id: str) -> str:
        """Build the composite key for a federated identity."""
        return f"{provider_id}|{external_id}"

    # ------------------------------------------------------------------
    # Protocol: lookup
    # ------------------------------------------------------------------

    async def lookup(self, provider_id: str, external_id: str) -> Optional[str]:
        """Return the user_id linked to the given (provider,
        external) pair, or ``None``.

        Reads from the in-memory index (loaded from disk on first
        access, refreshed by the staleness probe).
        """
        index = await self._ensure_index_loaded()
        return index.get(self._make_key(provider_id, external_id))

    # ------------------------------------------------------------------
    # Protocol: link
    # ------------------------------------------------------------------

    async def link(self, user_id: str, provider_id: str, external_id: str) -> None:
        """Insert or update the (provider, external) -> user_id
        mapping. Raises :class:`EntityAlreadyExistsError` if the
        pair is already linked to a different user.

        The duplicate check runs against the current on-disk content
        (read-modify-write merge), so a link created by another
        process since our last read is still detected. The shared
        cache is updated through the same dict (write-through).
        The write is single-shot and lock-free at the repository
        level: cross-process safety is delegated to the
        ``named_lock("federated_identities")`` held by
        ``UserStorage``.
        """
        index = await self._load_index_fresh()
        key = self._make_key(provider_id, external_id)
        existing = index.get(key)
        if existing is not None and existing != user_id:
            raise EntityAlreadyExistsError("federated_identity", key)
        index[key] = user_id
        await self._write_index(index)

    # ------------------------------------------------------------------
    # Protocol: unlink
    # ------------------------------------------------------------------

    async def unlink(self, provider_id: str, external_id: str) -> None:
        """Remove the mapping. No-op if the pair is absent (the
        write is still issued, matching the pre-refactor contract).
        Read-modify-write starts from disk; the shared cache is
        updated through the same dict."""
        index = await self._load_index_fresh()
        index.pop(self._make_key(provider_id, external_id), None)
        await self._write_index(index)
