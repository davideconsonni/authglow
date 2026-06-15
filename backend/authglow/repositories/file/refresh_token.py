"""File-system-backed repository for OAuth2 refresh tokens.

On-disk layout (relative to ``settings.storage_path``):

* ``<storage>/refresh_tokens/<token_lookup>.json`` — one per refresh
  token (the Pydantic ``model_dump(mode="json")`` round-trip;
  ``token_lookup`` is the HMAC-SHA256 of the plaintext, doubling
  as the filename for O(1) direct access).
* ``<storage>/refresh_tokens/id_index.json`` — secondary index
  mapping ``token_id`` to ``token_lookup`` so ``get_by_id`` is O(1).
* ``<storage>/refresh_tokens/active_index.json`` — list of
  currently-active ``token_id``s (not yet used, not revoked, not
  expired) so ``list_active`` is O(active) instead of O(all).

Security: the plaintext ``token`` is **never** persisted — the
service hands the repository a ``RefreshToken`` whose ``token_hash``
(bcrypt) and ``token_lookup`` (HMAC-SHA256) are already set. The
Pydantic ``token`` field is marked ``exclude=True`` in the model.

Concurrency: ``update`` uses optimistic concurrency (``_version``
field). The service layer is responsible for retrying on
``ConcurrentWriteError`` inside the in-process ``named_lock``.
SQL backends would replace the JSON index files with native
indexes and use row-level locking for ``update``.
"""

from typing import Any, Dict, List, Optional, Tuple

from authglow.core.datetime import utcnow
from authglow.models.refresh_token import RefreshToken
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import RefreshTokenRepository


class FileRefreshTokenRepository(BaseFileRepository, RefreshTokenRepository):
    """File-backed implementation of :class:`RefreshTokenRepository`."""

    _subdir = "refresh_tokens"

    # Reserved filenames for the two secondary indexes — they cannot
    # collide with a token_lookup because token_lookup is the
    # hex-encoded HMAC-SHA256 of a random 32-byte secret (256 bits).
    _ID_INDEX_FILENAME = "id_index.json"
    _ACTIVE_INDEX_FILENAME = "active_index.json"

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _path_for_lookup(self, token_lookup: str) -> str:
        """Return the on-disk path for the ``token_lookup``'s document."""
        return self._path(f"{token_lookup}.json")

    @property
    def _id_index_path(self) -> str:
        """Absolute path to the id_index JSON file."""
        return self._path(self._ID_INDEX_FILENAME)

    @property
    def _active_index_path(self) -> str:
        """Absolute path to the active_index JSON file."""
        return self._path(self._ACTIVE_INDEX_FILENAME)

    # ------------------------------------------------------------------
    # Idempotent guarded writes for the indexes (private helpers)
    # ------------------------------------------------------------------

    async def _load_id_index_dict(self) -> Dict[str, str]:
        """Return the id_index as a dict (empty if missing/corrupt)."""
        data: Optional[Any] = await self._read_json(self._id_index_path)
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items()}

    async def _save_id_index_dict(self, idx: Dict[str, str]) -> None:
        """Persist the id_index (deletes the file if ``idx`` is empty)."""
        if not idx:
            await self._delete(self._id_index_path)
        else:
            await self._write_json(self._id_index_path, dict(idx))

    async def _load_active_index_list(self) -> List[str]:
        """Return the active_index as a list (empty if missing/corrupt)."""
        data: Optional[Any] = await self._read_json(self._active_index_path)
        if not isinstance(data, dict):
            return []
        result = data.get("token_ids", [])
        return result if isinstance(result, list) else []

    async def _save_active_index_list(self, token_ids: List[str]) -> None:
        """Persist the active_index (deletes the file if empty)."""
        if not token_ids:
            await self._delete(self._active_index_path)
        else:
            await self._write_json(self._active_index_path, {"token_ids": list(token_ids)})

    # ------------------------------------------------------------------
    # Protocol: CRUD
    # ------------------------------------------------------------------

    async def create(self, token: RefreshToken) -> None:
        """Persist a freshly-generated refresh token."""
        path = self._path_for_lookup(token.token_lookup)
        await self._write_json(path, token.model_dump(mode="json"))

    async def get_by_id(self, token_id: str) -> Optional[RefreshToken]:
        """Return the token with the given ``token_id`` via the id_index."""
        idx = await self._load_id_index_dict()
        token_lookup = idx.get(token_id)
        if not token_lookup:
            return None
        return await self.get_by_lookup(token_lookup)

    async def get_by_lookup(self, token_lookup: str) -> Optional[RefreshToken]:
        """Return the token with the given ``token_lookup`` (O(1))."""
        path = self._path_for_lookup(token_lookup)
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return RefreshToken(**data)
        except (ValueError, TypeError):
            return None

    async def update(self, token: RefreshToken) -> None:
        """Persist changes to an existing token with optimistic
        concurrency. Raises ``ConcurrentWriteError`` on a version
        mismatch (cross-process race)."""
        path = self._path_for_lookup(token.token_lookup)
        current_data, version = await self._read_json_versioned(path)
        if current_data is None:
            raise FileNotFoundError(
                f"RefreshToken {token.token_id} (lookup {token.token_lookup}) "
                "not found; cannot update"
            )
        await self._write_json_versioned(path, token.model_dump(mode="json"), version)

    async def delete(self, token_id: str) -> bool:
        """Hard-delete the token (without touching the indexes — the
        service layer is responsible for that, because it owns the
        in-process lock that makes the index update + delete atomic).
        Returns ``True`` if it existed."""
        idx = await self._load_id_index_dict()
        token_lookup = idx.get(token_id)
        if not token_lookup:
            return False
        path = self._path_for_lookup(token_lookup)
        return await self._delete(path)

    # ------------------------------------------------------------------
    # Protocol: listing
    # ------------------------------------------------------------------

    async def list_active(self, *, user_id: Optional[str] = None) -> List[RefreshToken]:
        """Return all non-revoked, non-expired tokens via the active
        index, optionally filtered by ``user_id``."""
        token_ids = await self._load_active_index_list()
        idx = await self._load_id_index_dict()
        tokens: List[RefreshToken] = []
        for tid in token_ids:
            lookup = idx.get(tid)
            if not lookup:
                continue
            token = await self.get_by_lookup(lookup)
            if token is None:
                continue
            if user_id is not None and token.user_id != user_id:
                continue
            tokens.append(token)
        tokens.sort(key=lambda t: t.created_at, reverse=True)
        return tokens

    async def list_all(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        user_id: Optional[str] = None,
        active_only: bool = False,
    ) -> Tuple[List[RefreshToken], int]:
        """Return a paginated slice of tokens plus the total count.

        ``active_only=True`` routes through the active_index (O(active))
        instead of globbing the entire directory (O(all) — fine for
        small fleets, but a P4 perf bug for large ones).
        """
        if active_only:
            tokens = await self.list_active(user_id=user_id)
            total = len(tokens)
            return tokens[offset : offset + limit], total

        tokens = await self._collect(user_id=user_id)
        total = len(tokens)
        return tokens[offset : offset + limit], total

    async def cleanup_expired(self) -> int:
        """Delete every expired token and remove it from both indexes."""
        tokens = await self._collect()
        deleted = 0
        for token in tokens:
            if utcnow() > token.expires_at:
                # Recover the on-disk filename BEFORE removing the
                # id_index entry, otherwise we cannot locate the
                # JSON file to delete.
                idx = await self._load_id_index_dict()
                token_lookup = idx.get(token.token_id) or token.token_lookup
                await self.remove_from_id_index(token.token_id)
                await self.remove_from_active_index(token.token_id)
                if await self._delete(self._path_for_lookup(token_lookup)):
                    deleted += 1
        return deleted

    async def revoke_user_tokens(self, user_id: str, client_id: Optional[str] = None) -> int:
        """Revoke every non-revoked token for a user, optionally
        filtered by ``client_id``. Returns the count of newly-revoked
        tokens.

        Implementation note: the File backend scans the storage
        directory. SQL backends would use a single
        ``UPDATE ... WHERE user_id = ? AND (client_id = ? OR ? IS NULL)
        AND NOT revoked`` statement. The service layer is responsible
        for wrapping this in a ``named_lock`` if it needs
        cross-key atomicity.
        """
        tokens = await self._collect(user_id=user_id)
        revoked_count = 0
        for token in tokens:
            if token.revoked:
                continue
            if client_id is not None and token.client_id != client_id:
                continue
            token.revoked = True
            token.revoked_at = utcnow()
            token.revoked_reason = "Revoked by user or admin"
            await self.update(token)
            await self.remove_from_active_index(token.token_id)
            revoked_count += 1
        return revoked_count

    # ------------------------------------------------------------------
    # Protocol: id_index helpers
    # ------------------------------------------------------------------

    async def load_id_index(self) -> Dict[str, str]:
        return await self._load_id_index_dict()

    async def add_to_id_index(self, token_id: str, token_lookup: str) -> None:
        """Register a ``token_id -> token_lookup`` entry (idempotent)."""
        idx = await self._load_id_index_dict()
        idx[token_id] = token_lookup
        await self._save_id_index_dict(idx)

    async def remove_from_id_index(self, token_id: str) -> None:
        """Unregister a ``token_id``. No-op if absent. If the index
        becomes empty the file is deleted."""
        idx = await self._load_id_index_dict()
        if token_id not in idx:
            return
        del idx[token_id]
        await self._save_id_index_dict(idx)

    # ------------------------------------------------------------------
    # Protocol: active_index helpers
    # ------------------------------------------------------------------

    async def load_active_index(self) -> List[str]:
        return await self._load_active_index_list()

    async def add_to_active_index(self, token_id: str) -> None:
        """Add a ``token_id`` to the active_index. Idempotent."""
        existing = await self._load_active_index_list()
        if token_id not in existing:
            existing.append(token_id)
        await self._save_active_index_list(existing)

    async def remove_from_active_index(self, token_id: str) -> None:
        """Remove a ``token_id`` from the active_index. No-op if absent."""
        existing = await self._load_active_index_list()
        if token_id not in existing:
            return
        existing.remove(token_id)
        await self._save_active_index_list(existing)

    # ------------------------------------------------------------------
    # Internal collection helper
    # ------------------------------------------------------------------

    async def _collect(self, *, user_id: Optional[str] = None) -> List[RefreshToken]:
        """Scan ``<storage>/refresh_tokens/*.json`` (skipping the two
        index files) and return a filtered, Pydantic-validated list."""
        pattern = f"{self._storage_path}/*.json"
        files = await self._glob(pattern)
        tokens: List[RefreshToken] = []
        for file_path in files:
            if file_path.endswith(self._ID_INDEX_FILENAME) or file_path.endswith(
                self._ACTIVE_INDEX_FILENAME
            ):
                continue
            data = await self._read_json(file_path)
            if data is None:
                continue
            try:
                token = RefreshToken(**data)
            except (ValueError, TypeError):
                continue
            if user_id is not None and token.user_id != user_id:
                continue
            tokens.append(token)
        tokens.sort(key=lambda t: t.created_at, reverse=True)
        return tokens
