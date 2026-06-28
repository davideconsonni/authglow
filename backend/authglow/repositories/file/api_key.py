"""File-system-backed repository for API keys.

Stores one ``APIKey`` document per ``key_id`` at
``<storage>/api_keys/<key_id>.json`` and a secondary prefix index at
``<storage>/api_keys/index/<prefix>.json`` for O(1) lookup on
``validate_key``.

The pre-refactor service did its own fsspec/AsyncFileSystem plumbing
in ``__init__``; the refactored repository inherits the standard
``BaseFileRepository._init_filesystem`` and therefore honours
``Settings.storage_backend`` (the historical code would have crashed
on any non-``file`` backend).

The prefix index is an implementation detail of the File backend:
alternative backends (SQL with a unique key on ``key_prefix``,
Firestore with a composite index, etc.) can implement ``get_by_prefix``
via a native query and ignore the JSON index file. The three
``_load/_add/_remove`` helpers are private to ``FileAPIKeyRepository``
on purpose.

VAPT-040: the prefix index file is **encrypted** with the
private-key envelope (``agk1:`` prefix) so a directory-read
attacker cannot enumerate the live ``key_id``s registered
under a given prefix. The plaintext filename (``<prefix>``)
remains visible because the prefix is the public part of
the API key (the first 12 chars shown to the user on
issuance) — only the mapping to ``key_id``s is encrypted.
"""

import json
from typing import List, Optional

from authglow.core.crypto import decrypt_index_value, encrypt_index_value
from authglow.models.api_key import APIKey
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import APIKeyRepository


class FileAPIKeyRepository(BaseFileRepository, APIKeyRepository):
    """File-backed implementation of :class:`APIKeyRepository`.

    On-disk layout (relative to ``settings.storage_path``):

    * ``<storage>/api_keys/<key_id>.json`` — one per API key
      (the Pydantic ``model_dump(mode="json")`` round-trip).
    * ``<storage>/api_keys/index/<prefix>.json`` — secondary index
      mapping ``prefix`` to a list of ``key_id``s (so
      ``validate_key`` is O(1) on the prefix scan).
    """

    _subdir = "api_keys"

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _path_for(self, key_id: str) -> str:
        """Return the on-disk path for the *key_id*'s document."""
        return self._path(f"{key_id}.json")

    def _index_path_for(self, prefix: str) -> str:
        """Return the on-disk path for the *prefix*'s index file."""
        return self._path(f"index/{prefix}.json")

    # ------------------------------------------------------------------
    # Prefix index helpers (private; implementation detail of File)
    # ------------------------------------------------------------------

    async def _load_prefix_index(self, prefix: str) -> List[str]:
        """Return the list of ``key_id``s registered for *prefix*.

        Returns an empty list if the index file is missing or corrupt.

        VAPT-040: the file content is encrypted with the
        private-key envelope (``agk1:``). Legacy plaintext
        payloads (pre-VAPT-040) are accepted transparently
        and re-encrypted on the next write.
        """
        index_file = self._index_path_for(prefix)
        raw: Optional[str] = await self._read_text(index_file)
        if raw is None:
            return []
        try:
            plaintext = decrypt_index_value(raw)
            data = json.loads(plaintext)
        except (ValueError, TypeError, json.JSONDecodeError):
            return []
        if not isinstance(data, dict):
            return []
        result = data.get("key_ids", [])
        return result if isinstance(result, list) else []

    async def _add_to_prefix_index(self, api_key: APIKey) -> None:
        """Add ``api_key.key_id`` to the prefix index (idempotent).

        VAPT-040: the file content is encrypted with the
        private-key envelope so a directory-read attacker
        cannot enumerate live key IDs.
        """
        index_file = self._index_path_for(api_key.key_prefix)
        existing_ids = await self._load_prefix_index(api_key.key_prefix)
        if api_key.key_id not in existing_ids:
            existing_ids.append(api_key.key_id)
        payload = json.dumps({"key_ids": existing_ids})
        await self._write_text(index_file, encrypt_index_value(payload))

    async def _remove_from_prefix_index(self, prefix: str, key_id: str) -> None:
        """Remove ``key_id`` from the prefix index. If the resulting
        list is empty, the index file is deleted entirely.

        VAPT-040: same encryption envelope as the add path.
        """
        index_file = self._index_path_for(prefix)
        existing_ids = await self._load_prefix_index(prefix)
        if key_id not in existing_ids:
            return
        existing_ids.remove(key_id)
        if not existing_ids:
            await self._delete(index_file)
        else:
            payload = json.dumps({"key_ids": existing_ids})
            await self._write_text(index_file, encrypt_index_value(payload))

    # Protocol-visible wrappers around the private helpers above.
    # Backends with a native index (SQL) override these directly.

    async def load_prefix_index(self, prefix: str) -> List[str]:
        return await self._load_prefix_index(prefix)

    async def add_to_prefix_index(self, key: APIKey) -> None:
        await self._add_to_prefix_index(key)

    async def remove_from_prefix_index(self, prefix: str, key_id: str) -> None:
        await self._remove_from_prefix_index(prefix, key_id)

    # ------------------------------------------------------------------
    # APIKeyRepository methods
    # ------------------------------------------------------------------

    async def create(self, key: APIKey) -> None:
        """Persist a new API key (no CAS — first creation only)."""
        path = self._path_for(key.key_id)
        await self._write_json(path, key.model_dump(mode="json"))

    async def get_by_id(self, key_id: str) -> Optional[APIKey]:
        """Return the API key, or ``None``."""
        path = self._path_for(key_id)
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return APIKey(**data)
        except (ValueError, TypeError):
            return None

    async def get_by_prefix(self, prefix: str) -> List[APIKey]:
        """Return every candidate key sharing *prefix*.

        Returns an empty list if the index file is missing or no
        candidate resolves to a readable document.
        """
        candidate_ids = await self._load_prefix_index(prefix)
        if not candidate_ids:
            return []
        keys: List[APIKey] = []
        for key_id in candidate_ids:
            api_key = await self.get_by_id(key_id)
            if api_key is not None:
                keys.append(api_key)
        return keys

    async def update(self, key: APIKey) -> None:
        """Persist changes to an existing key.

        Simple non-CAS write — the brute-force lockout / usage stats
        on API keys are service-level concerns wrapped in a
        ``named_lock`` and do not require cross-process CAS. If the
        file is missing, a new document is created (idempotent
        overwrite)."""
        path = self._path_for(key.key_id)
        await self._write_json(path, key.model_dump(mode="json"))

    async def delete(self, key_id: str) -> bool:
        """Hard-delete the key (without touching the prefix index —
        the service layer is responsible for that, because it owns
        the in-process lock that makes the index update + delete
        atomic). Returns ``True`` if it existed."""
        path = self._path_for(key_id)
        return await self._delete(path)

    async def list_for_user(self, user_id: str) -> List[APIKey]:
        """Return every key owned by *user_id*, sorted by
        ``created_at`` desc."""
        return await self._collect(user_id=user_id, active_only=False)

    async def list_all(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        active_only: bool = False,
    ) -> List[APIKey]:
        """Return a paginated slice of every key, sorted by
        ``created_at`` desc."""
        all_keys = await self._collect(active_only=active_only)
        return all_keys[offset : offset + limit]

    async def cleanup_expired(self) -> int:
        """Delete every expired **and inactive** key. Returns the count.

        The pre-refactor service required both ``expires_at < now``
        AND ``is_active is False`` (an expired-but-active key is
        still useful as a "force fail" target). The repository
        preserves that semantics.
        """
        from authglow.core.datetime import utcnow

        all_keys = await self._collect(active_only=False)
        deleted = 0
        for api_key in all_keys:
            if api_key.expires_at and api_key.expires_at < utcnow() and not api_key.is_active:
                await self._remove_from_prefix_index(api_key.key_prefix, api_key.key_id)
                if await self._delete(self._path_for(api_key.key_id)):
                    deleted += 1
        return deleted

    # ------------------------------------------------------------------
    # Internal collection helper
    # ------------------------------------------------------------------

    async def _collect(self, *, user_id: Optional[str] = None, active_only: bool) -> List[APIKey]:
        """Scan ``<storage>/api_keys/*.json`` and return a filtered,
        Pydantic-validated list of API keys.

        ``user_id`` filters by owner; ``active_only`` filters out
        revoked keys.
        """
        pattern = f"{self._storage_path}/*.json"
        files = await self._glob(pattern)
        keys: List[APIKey] = []
        for file_path in files:
            data = await self._read_json(file_path)
            if data is None:
                continue
            try:
                api_key = APIKey(**data)
            except (ValueError, TypeError):
                continue
            if user_id is not None and api_key.user_id != user_id:
                continue
            if active_only and not api_key.is_active:
                continue
            keys.append(api_key)
        keys.sort(key=lambda k: k.created_at, reverse=True)
        return keys
