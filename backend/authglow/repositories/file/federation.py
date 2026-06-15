"""File-system-backed repository for external OIDC IdP configurations.

On-disk layout (relative to ``settings.storage_path``):

* ``<storage>/federation/<provider_id>.json`` — one document
  per external IdP. The repository uses the
  ``ExternalIdpConfig`` Pydantic model from
  ``authglow.models.federation`` for serialisation.

The pre-refactor ``FederationStorage`` (in
``services/federation_storage.py``) had two backend-bypass
bugs:

1. ``__init__`` constructed ``fsspec.filesystem("file")``
   directly, ignoring ``Settings.storage_backend``
   (``services/federation_storage.py:25``).
2. ``__init__`` used ``os.makedirs(self.storage_path, ...)``
   to create the federation directory
   (``services/federation_storage.py:24``), bypassing the
   fsspec abstraction. On any non-``file`` backend the
   ``os.makedirs`` would attempt to create a path on the
   local filesystem that the cloud backend never sees, and
   the subsequent ``_afs.write_json`` would write the file
   to the wrong location (or raise a missing-bucket error
   on first write).

Both bugs are fixed in this repository: ``BaseFileRepository``
builds the fsspec filesystem from ``Settings.storage_backend``,
and ``_ensure_parent`` is the single place that handles
directory creation in a backend-agnostic way.

Cross-process safety is delegated to the
``named_lock("federation:*")`` held by ``FederationService``
(the original ``FederationStorage`` class is now a
deprecation shim for ``FederationService``, see
``services/federation.py`` and the Fase 18 pattern).
"""

from typing import Any, Dict, List, Optional

from authglow.models.federation import ExternalIdpConfig
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import FederationProviderRepository


class FileFederationProviderRepository(BaseFileRepository, FederationProviderRepository):
    """File-backed implementation of :class:`FederationProviderRepository`.

    Stores each provider as a JSON file at
    ``<storage>/federation/<provider_id>.json``.
    """

    _subdir = "federation"

    # ------------------------------------------------------------------
    # Path helper
    # ------------------------------------------------------------------

    def _provider_path(self, provider_id: str) -> str:
        """Return the on-disk path for a provider file."""
        return self._path(f"{provider_id}.json")

    # ------------------------------------------------------------------
    # Protocol: create
    # ------------------------------------------------------------------

    async def create(self, provider: ExternalIdpConfig) -> None:
        """Persist a new IdP configuration.

        Sets ``created_at`` and ``updated_at`` to the current
        UTC time as a side effect (matches the pre-refactor
        service-side behaviour, where the timestamps were set
        before the write).
        """
        from authglow.core.datetime import utcnow

        provider.created_at = utcnow()
        provider.updated_at = utcnow()
        await self._write_json(self._provider_path(provider.id), provider.model_dump(mode="json"))

    # ------------------------------------------------------------------
    # Protocol: get_by_id
    # ------------------------------------------------------------------

    async def get_by_id(self, provider_id: str) -> Optional[ExternalIdpConfig]:
        """Return the provider, or ``None``.

        Corrupt-JSON tolerance: a missing or invalid file
        returns ``None`` rather than raising. The
        ``_read_json`` helper swallows ``FileNotFoundError``
        and ``(ValueError, TypeError)`` so the service layer
        can treat missing and corrupt providers uniformly.
        """
        data = await self._read_json(self._provider_path(provider_id))
        if not isinstance(data, dict):
            return None
        try:
            return ExternalIdpConfig(**data)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Protocol: update
    # ------------------------------------------------------------------

    async def update(
        self, provider_id: str, updates: Dict[str, Any]
    ) -> Optional[ExternalIdpConfig]:
        """Apply the given non-``None`` field updates and
        persist. Returns the updated provider, or ``None`` if
        it was missing.

        Fields with ``None`` values in ``updates`` are
        ignored (matches the pre-refactor service-side
        ``if value is not None: setattr(provider, key, value)``
        behaviour). ``updated_at`` is set to the current UTC
        time on a successful update.
        """
        from authglow.core.datetime import utcnow

        provider = await self.get_by_id(provider_id)
        if provider is None:
            return None

        for key, value in updates.items():
            if value is not None:
                setattr(provider, key, value)
        provider.updated_at = utcnow()

        await self._write_json(self._provider_path(provider_id), provider.model_dump(mode="json"))
        return provider

    # ------------------------------------------------------------------
    # Protocol: delete
    # ------------------------------------------------------------------

    async def delete(self, provider_id: str) -> bool:
        """Remove the provider. Returns ``True`` if it existed."""
        return await self._delete(self._provider_path(provider_id))

    # ------------------------------------------------------------------
    # Protocol: list
    # ------------------------------------------------------------------

    async def list(self, enabled_only: bool = False) -> List[ExternalIdpConfig]:
        """Return every provider, optionally filtered by ``enabled``.

        Corrupt-JSON files are silently skipped (matches the
        pre-refactor ``try / except Exception: continue``
        pattern in ``FederationStorage.list_providers``).
        """
        pattern = f"{self._storage_path}/*.json"
        try:
            files = await self._glob(pattern)
        except Exception:
            return []

        providers: List[ExternalIdpConfig] = []
        for file_path in files:
            data = await self._read_json(file_path)
            if not isinstance(data, dict):
                continue
            try:
                provider = ExternalIdpConfig(**data)
            except Exception:
                continue
            if enabled_only and not provider.enabled:
                continue
            providers.append(provider)
        return providers
