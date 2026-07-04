"""File-backed persistence for the per-API-key claim policy.

File layout::

    <storage_path>/api_key_claim_policies/<api_key_id>.json

One file per API key. The file is only present when a policy
has been explicitly saved — keys without a policy return
``None`` from :meth:`get_by_api_key` and the service falls
back to the built-in default (namespaced RBAC roles +
permissions). The repository never fabricates a default
file.

The repository owns the file layout, JSON serialisation, and
the Pydantic round-trip. No optimistic-concurrency ``_version``
field is required: claim policies are admin-controlled and
updated by a single admin UI at a time, so the simpler
write-overwrite semantics are sufficient (any cross-process
conflict resolves last-write-wins, which matches admin intent).
"""

from typing import Optional

from authglow.core.config import Settings
from authglow.models.api_key_claim_policy import APIKeyClaimPolicy
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import APIKeyClaimPolicyRepository


class FileAPIKeyClaimPolicyRepository(
    BaseFileRepository, APIKeyClaimPolicyRepository
):
    """Persists claim policies as one JSON file per ``api_key_id``."""

    _subdir = "api_key_claim_policies"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    def _path_for(self, api_key_id: str) -> str:
        return self._path(f"{api_key_id}.json")

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def get_by_api_key(self, api_key_id: str) -> Optional[APIKeyClaimPolicy]:
        """Return the policy for *api_key_id*, or ``None``.

        Missing file, corrupt JSON, or invalid Pydantic payload
        all return ``None`` — the service layer treats "no
        policy" as "use the built-in default".
        """
        path = self._path_for(api_key_id)
        if not await self._exists(path):
            return None
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return APIKeyClaimPolicy(**data)
        except Exception:
            return None

    async def save(self, policy: APIKeyClaimPolicy) -> None:
        """Persist the policy. Overwrites any prior policy for the
        same ``api_key_id``.

        The ``APIKeyClaimPolicy.updated_at`` is refreshed by the
        service layer before this call; the repository just
        writes whatever Pydantic model it receives.
        """
        path = self._path_for(policy.api_key_id)
        await self._write_json(path, policy.model_dump(mode="json"))

    async def delete(self, api_key_id: str) -> bool:
        """Remove the policy for *api_key_id*. Returns ``True`` on
        success, ``False`` if no policy was configured."""
        return await self._delete(self._path_for(api_key_id))
