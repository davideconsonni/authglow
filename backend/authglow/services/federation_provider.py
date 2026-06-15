"""Federation provider service — thin facade over FederationProviderRepository.

Persistence for external OIDC IdP configurations is delegated to
:class:`FileFederationProviderRepository` (Fase 17). The service
keeps the in-process ``named_lock`` for cross-entity safety (the
provider CRUD is single-entity today, but the lock is held
consistently with the pre-refactor ``FederationStorage`` to
preserve behaviour and provide forward-compatibility for future
federation flows that span multiple providers or linked
external users).

Note on naming: this class is called ``FederationProviderService``
(not ``FederationService``) because ``FederationService`` is
already used in ``authglow.services.federation`` for the OIDC
Relying Party flow (callback handling, JWKS verification,
provider UI list, etc.). The two concerns are kept separate:
``FederationService`` is the flow, ``FederationProviderService``
is the CRUD.

The pre-refactor ``FederationStorage`` (in
``services/federation_storage.py``) had two backend-bypass bugs
(``fsspec.filesystem("file")`` hard-coded + ``os.makedirs``
bypassing the fsspec abstraction). Both are fixed by delegating
to the FileFederationProviderRepository, which inherits the
backend-agnostic fsspec handling from
:class:`BaseFileRepository`.
"""

from typing import TYPE_CHECKING, Optional

from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.models.federation import ExternalIdpConfig

if TYPE_CHECKING:
    from authglow.repositories.protocols import FederationProviderRepository


class FederationProviderService:
    """Thin facade for external OIDC IdP configuration persistence."""

    def __init__(
        self,
        provider_repository: Optional["FederationProviderRepository"] = None,
    ):
        """Initialise the service.

        ``provider_repository`` is optional; when ``None`` a
        fresh :class:`FileFederationProviderRepository` is
        created via the FastAPI factory. Tests can pass a
        stub or an in-memory implementation directly.
        """
        self.settings = get_settings()
        self._lock = named_lock()

        if provider_repository is None:
            from authglow.repositories.dependencies import (
                get_federation_provider_repository,
            )

            self._provider_repo: "FederationProviderRepository" = (
                get_federation_provider_repository(settings=self.settings)
            )
        else:
            self._provider_repo = provider_repository

    async def create_provider(self, provider: ExternalIdpConfig) -> ExternalIdpConfig:
        """Create a new external IdP configuration.

        The repository sets ``created_at`` and ``updated_at``
        to the current UTC time. The lock is held for
        consistency with the pre-refactor behaviour
        (``named_lock("federation:create")``) and to provide
        forward-compatibility for future cross-entity
        federation flows.
        """
        async with self._lock("federation:create"):
            await self._provider_repo.create(provider)
        return provider

    async def get_provider(self, provider_id: str) -> Optional[ExternalIdpConfig]:
        """Get a provider by ID. Delegates to the repository
        (no lock — single read)."""
        return await self._provider_repo.get_by_id(provider_id)

    async def list_providers(self, enabled_only: bool = False) -> list[ExternalIdpConfig]:
        """List all providers, optionally filtering by
        ``enabled`` status. Delegates to the repository (no
        lock — single read)."""
        return await self._provider_repo.list(enabled_only=enabled_only)

    async def update_provider(self, provider_id: str, updates: dict) -> Optional[ExternalIdpConfig]:
        """Update a provider configuration.

        The repository applies only non-``None`` fields from
        ``updates`` and sets ``updated_at`` to the current UTC
        time. The lock is held for the read-modify-write
        cycle to prevent concurrent updates from clobbering
        each other (matches the pre-refactor
        ``named_lock(f"federation:{provider_id}")`` pattern).
        """
        async with self._lock(f"federation:{provider_id}"):
            return await self._provider_repo.update(provider_id, updates)

    async def delete_provider(self, provider_id: str) -> bool:
        """Delete a provider configuration. The lock is held
        for consistency with the pre-refactor behaviour and
        to provide forward-compatibility for future
        cross-entity federation flows (e.g. cleaning up
        linked federated identities)."""
        async with self._lock(f"federation:{provider_id}"):
            return await self._provider_repo.delete(provider_id)
