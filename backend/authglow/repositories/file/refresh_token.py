"""File-system-backed repository for OAuth2 refresh tokens.

On-disk layout (relative to ``settings.storage_path``):

* ``<storage>/refresh_tokens/<token_lookup>.json`` — one per refresh
  token (the Pydantic ``model_dump(mode="json")`` round-trip;
  ``token_lookup`` is the HMAC-SHA256 of the plaintext, doubling
  as the filename for O(1) direct access).
* ``<storage>/refresh_tokens/id_index.json`` — secondary index
  mapping ``token_id`` to ``token_lookup`` so ``get_by_id`` is O(1).
  **Encrypted with the private-key envelope** (``agk1:`` prefix,
  VAPT-040) so a directory-read attacker cannot enumerate live
  ``token_id``s.
* ``<storage>/refresh_tokens/active_index.json`` — list of
  currently-active ``token_id``s (not yet used, not revoked, not
  expired) so ``list_active`` is O(active) instead of O(all).
  Same envelope as the id_index.

Security: the plaintext ``token`` is **never** persisted — the
service hands the repository a ``RefreshToken`` whose ``token_hash``
(bcrypt) and ``token_lookup`` (HMAC-SHA256) are already set. The
Pydantic ``token`` field is marked ``exclude=True`` in the model.

Concurrency: ``update`` uses optimistic concurrency (``_version``
field). The service layer is responsible for retrying on
``ConcurrentWriteError`` inside the in-process ``named_lock``. The two
secondary indexes are read-modify-written as single locked sections
(per-path thread lock + atomic tmp/rename write in the storage worker),
so concurrent issuances for different users cannot overwrite each
other's entries or expose a half-written file to a reader.
SQL backends would replace the JSON index files with native
indexes and use row-level locking for ``update``.
"""

import json
from typing import Callable, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag

from authglow.core.crypto import decrypt_index_value, encrypt_index_value
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

    @staticmethod
    def _parse_id_index(raw: Optional[str]) -> Dict[str, str]:
        """Parse an id_index payload (empty when missing/corrupt).

        VAPT-040: the file content is encrypted with the private-key
        envelope (``agk1:``). Reads transparently migrate legacy
        plaintext (pre-VAPT-040) payloads — ``decrypt_index_value``
        returns the input unchanged when the prefix is missing. The
        next write re-encrypts so the legacy data is replaced on first
        mutation. ``InvalidTag`` (a tampered or damaged envelope) joins
        the corrupt set: with atomic index writes the only way to see
        it is genuinely corrupt content, and the documented tolerance
        is then "empty", not an exception.
        """
        if raw is None:
            return {}
        try:
            data = json.loads(decrypt_index_value(raw))
        except (ValueError, TypeError, json.JSONDecodeError, InvalidTag):
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items()}

    @staticmethod
    def _serialize_id_index(idx: Dict[str, str]) -> Optional[str]:
        """Serialize the id_index (``None`` when empty, so the guarded
        writer deletes the file instead of persisting an empty index)."""
        if not idx:
            return None
        return encrypt_index_value(json.dumps(dict(idx)))

    @staticmethod
    def _parse_active_index(raw: Optional[str]) -> List[str]:
        """Parse an active_index payload (empty when missing/corrupt).

        VAPT-040: same encryption envelope and tolerance as
        :meth:`_parse_id_index`.
        """
        if raw is None:
            return []
        try:
            data = json.loads(decrypt_index_value(raw))
        except (ValueError, TypeError, json.JSONDecodeError, InvalidTag):
            return []
        if not isinstance(data, dict):
            return []
        result = data.get("token_ids", [])
        return result if isinstance(result, list) else []

    @staticmethod
    def _serialize_active_index(token_ids: List[str]) -> Optional[str]:
        """Serialize the active_index (``None`` when empty, so the
        guarded writer deletes the file)."""
        if not token_ids:
            return None
        payload = json.dumps({"token_ids": list(token_ids)})
        return encrypt_index_value(payload)

    async def _load_id_index_dict(self) -> Dict[str, str]:
        """Return the id_index as a dict (empty if missing/corrupt)."""
        raw: Optional[str] = await self._read_text(self._id_index_path)
        return self._parse_id_index(raw)

    async def _load_active_index_list(self) -> List[str]:
        """Return the active_index as a list (empty if missing/corrupt)."""
        raw: Optional[str] = await self._read_text(self._active_index_path)
        return self._parse_active_index(raw)

    async def _rmw_id_index(self, mutate: Callable[[Dict[str, str]], Dict[str, str]]) -> None:
        """Read-modify-write the id_index as one locked atomic section.

        *mutate* must return the new index **without modifying the one
        it receives**: returning an equal mapping is detected as a
        no-op and skips the disk write entirely.
        """

        def _transform(raw: Optional[str]) -> Optional[str]:
            idx = self._parse_id_index(raw)
            new_idx = mutate(idx)
            if new_idx == idx:
                return raw
            return self._serialize_id_index(new_idx)

        await self._update_text(self._id_index_path, _transform)

    async def _rmw_active_index(self, mutate: Callable[[List[str]], List[str]]) -> None:
        """Read-modify-write the active_index as one locked atomic section.

        Same contract as :meth:`_rmw_id_index`: *mutate* returns a new
        list and leaves the input untouched, so a no-op mutation does
        not rewrite the file.
        """

        def _transform(raw: Optional[str]) -> Optional[str]:
            ids = self._parse_active_index(raw)
            new_ids = mutate(ids)
            if new_ids == ids:
                return raw
            return self._serialize_active_index(new_ids)

        await self._update_text(self._active_index_path, _transform)

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
        """Register a ``token_id -> token_lookup`` entry (idempotent).

        The read-modify-write runs as a single locked section, so two
        concurrent issuances can no longer overwrite each other's
        entries (lost update).
        """

        def _mutate(idx: Dict[str, str]) -> Dict[str, str]:
            if idx.get(token_id) == token_lookup:
                return idx
            return {**idx, token_id: token_lookup}

        await self._rmw_id_index(_mutate)

    async def remove_from_id_index(self, token_id: str) -> None:
        """Unregister a ``token_id``. No-op if absent. If the index
        becomes empty the file is deleted."""

        def _mutate(idx: Dict[str, str]) -> Dict[str, str]:
            if token_id not in idx:
                return idx
            return {k: v for k, v in idx.items() if k != token_id}

        await self._rmw_id_index(_mutate)

    # ------------------------------------------------------------------
    # Protocol: active_index helpers
    # ------------------------------------------------------------------

    async def load_active_index(self) -> List[str]:
        return await self._load_active_index_list()

    async def add_to_active_index(self, token_id: str) -> None:
        """Add a ``token_id`` to the active_index. Idempotent.

        Locked RMW, same guarantee as :meth:`add_to_id_index`.
        """

        def _mutate(ids: List[str]) -> List[str]:
            if token_id in ids:
                return ids
            return ids + [token_id]

        await self._rmw_active_index(_mutate)

    async def remove_from_active_index(self, token_id: str) -> None:
        """Remove a ``token_id`` from the active_index. No-op if absent."""

        def _mutate(ids: List[str]) -> List[str]:
            if token_id not in ids:
                return ids
            return [t for t in ids if t != token_id]

        await self._rmw_active_index(_mutate)

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
