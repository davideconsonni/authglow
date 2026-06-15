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

The underlying fsspec filesystem and ``AsyncFileSystem`` wrapper
are managed by :class:`BaseFileRepository`. Cross-process safety
is delegated to the ``named_lock("federated_identities")`` held
by ``UserStorage`` (``link`` / ``get_by_external_id`` paths).
"""

from typing import TYPE_CHECKING, Optional

from authglow.repositories.exceptions import EntityAlreadyExistsError
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import FederatedIdentityRepository

if TYPE_CHECKING:
    from authglow.core.config import Settings


class FileFederatedIdentityRepository(BaseFileRepository, FederatedIdentityRepository):
    """File-backed implementation of :class:`FederatedIdentityRepository`.

    Stores the index as a single JSON object at
    ``<storage>/federated_identities.json`` mapping
    ``"{provider_id}|{external_id}"`` -> ``user_id``.

    Layout note: ``BaseFileRepository`` requires a non-empty
    ``_subdir``. The federated identities file lives at the
    storage **root**, not in a subdirectory, so we pass
    ``subdir="."`` to the base constructor and override
    ``_storage_path`` to point back at the root.
    """

    _filename = "federated_identities.json"

    def __init__(self, settings: Optional["Settings"] = None) -> None:
        super().__init__(settings=settings, subdir=".")
        # Collapse the "." subdir back to the root so the file
        # lives at <storage>/federated_identities.json (not
        # <storage>/./...).
        self._storage_path = self._storage_root

    # ------------------------------------------------------------------
    # Path helper
    # ------------------------------------------------------------------

    def _index_path(self) -> str:
        """Return the on-disk path for the federated identities file.

        The index lives at the storage root, not in a subdirectory
        — pre-refactor layout: ``<storage>/federated_identities.json``.
        """
        return f"{self._storage_root}/{self._filename}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_key(self, provider_id: str, external_id: str) -> str:
        """Build the composite key for a federated identity."""
        return f"{provider_id}|{external_id}"

    async def _read_index(self) -> dict:
        """Read the federated identities file. Returns ``{}`` on
        missing or corrupt JSON."""
        data = await self._read_json(self._index_path())
        if not isinstance(data, dict):
            return {}
        return data

    async def _write_index(self, index: dict) -> None:
        """Write the federated identities file. Atomic-ish (uses
        ``_write_json_atomic`` for crash safety on local
        filesystems; cloud backends fall back to plain write)."""
        await self._write_json_atomic(self._index_path(), index)

    # ------------------------------------------------------------------
    # Protocol: lookup
    # ------------------------------------------------------------------

    async def lookup(self, provider_id: str, external_id: str) -> Optional[str]:
        """Return the user_id linked to the given (provider,
        external) pair, or ``None``."""
        index = await self._read_index()
        return index.get(self._make_key(provider_id, external_id))

    # ------------------------------------------------------------------
    # Protocol: link
    # ------------------------------------------------------------------

    async def link(self, user_id: str, provider_id: str, external_id: str) -> None:
        """Insert or update the (provider, external) -> user_id
        mapping. Raises :class:`EntityAlreadyExistsError` if the
        pair is already linked to a different user.

        The write is single-shot and lock-free at the repository
        level: cross-process safety is delegated to the
        ``named_lock("federated_identities")`` held by
        ``UserStorage``.
        """
        index = await self._read_index()
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
        """Remove the mapping. No-op if absent."""
        index = await self._read_index()
        index.pop(self._make_key(provider_id, external_id), None)
        await self._write_index(index)
