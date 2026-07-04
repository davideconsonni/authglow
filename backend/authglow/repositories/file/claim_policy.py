"""File-backed persistence for the per-OAuth2-client claim policy.

File layout::

    <storage_path>/client_claim_policies/<client_id>.json

One file per OAuth2 client. The file is only present when a
policy has been explicitly saved — clients without a policy
return ``None`` from :meth:`get_by_client` and the service
falls back to the built-in default (namespaced RBAC roles +
permissions). The repository never fabricates a default file.

The repository owns the file layout, JSON serialisation, and
the Pydantic round-trip. No optimistic-concurrency ``_version``
field is required: claim policies are admin-controlled and
updated by a single admin UI at a time, so the simpler
write-overwrite semantics are sufficient (any cross-process
conflict resolves last-write-wins, which matches admin intent).
"""

from typing import Optional

from authglow.core.config import Settings
from authglow.models.claim_policy import ClientClaimPolicy
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import ClientClaimPolicyRepository


class FileClientClaimPolicyRepository(BaseFileRepository, ClientClaimPolicyRepository):
    """Persists claim policies as one JSON file per ``client_id``."""

    _subdir = "client_claim_policies"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    def _path_for(self, client_id: str) -> str:
        return self._path(f"{client_id}.json")

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def get_by_client(self, client_id: str) -> Optional[ClientClaimPolicy]:
        """Return the policy for *client_id*, or ``None``.

        Missing file, corrupt JSON, or invalid Pydantic payload
        all return ``None`` — the service layer treats "no
        policy" as "use the built-in default".
        """
        path = self._path_for(client_id)
        if not await self._exists(path):
            return None
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return ClientClaimPolicy(**data)
        except Exception:
            # Corrupt / incompatible payload — treat as missing.
            return None

    async def save(self, policy: ClientClaimPolicy) -> None:
        """Persist the policy. Overwrites any prior policy for the
        same ``client_id``.

        The ``ClientClaimPolicy.updated_at`` is refreshed by the
        service layer before this call; the repository just
        writes whatever Pydantic model it receives.
        """
        path = self._path_for(policy.client_id)
        await self._write_json(path, policy.model_dump(mode="json"))

    async def delete(self, client_id: str) -> bool:
        """Remove the policy for *client_id*. Returns ``True`` on
        success, ``False`` if no policy was configured."""
        return await self._delete(self._path_for(client_id))
