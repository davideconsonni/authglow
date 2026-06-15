"""File-system-backed repository for the login-history audit log.

On-disk layout (relative to ``settings.storage_path``):

* ``<storage>/login_history/<user_id>/<entry_id>.json`` — one
  document per login attempt. The two-level directory structure
  keeps the per-user fan-out cheap on the admin listing routes
  (``list_for_user`` is a single ``<user_id>/*.json`` glob).

The pre-refactor ``LoginHistoryService`` had two backend-bypass bugs:

1. ``__init__`` constructed ``fsspec.filesystem("file")`` directly,
   ignoring ``Settings.storage_backend`` (``services/login_history.py:73``).
2. ``_cleanup_old_entries`` used ``os.remove(file_path)`` instead
   of the fsspec filesystem's ``rm`` (``services/login_history.py:141``),
   so the cleanup would crash on any non-``file`` backend with a
   ``FileNotFoundError`` / ``OSError`` from the OS-level ``unlink``.

Both bugs are fixed in this repository: ``BaseFileRepository`` builds
the fsspec filesystem from ``Settings.storage_backend``, and
``_delete`` uses the async-fsspec ``rm`` so the cleanup is
backend-agnostic.
"""

from typing import Any, Dict, List, Optional, Tuple

from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import LoginHistoryRepository


class FileLoginHistoryRepository(BaseFileRepository, LoginHistoryRepository):
    """File-backed implementation of :class:`LoginHistoryRepository`.

    Each entry is stored as a flat dict (the pre-refactor
    ``LoginHistoryEntry.to_dict()`` shape) so the repo can stay
    backend-agnostic without dragging the Pydantic/dataclass model
    into the Protocol (the Protocol exposes ``Record = Dict[str, Any]``
    for the same reason).
    """

    _subdir = "login_history"

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _user_dir(self, user_id: str) -> str:
        """Return the on-disk directory for a user's history."""
        return self._path(user_id)

    def _entry_path(self, user_id: str, entry_id: str) -> str:
        """Return the on-disk path for a single entry."""
        return self._path(f"{user_id}/{entry_id}.json")

    # ------------------------------------------------------------------
    # Protocol: record
    # ------------------------------------------------------------------

    async def record(
        self,
        *,
        user_id: str,
        email: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        failure_reason: Optional[str] = None,
        entry_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Append a new login-attempt record.

        The caller is the service layer, which owns the
        ``LoginHistoryEntry`` dataclass + ``id`` + ``timestamp``
        generation. The repository accepts them as keyword-only
        arguments so the service does not need to expose its
        internal model class to the Protocol.

        Returns the persisted record (a plain dict, matching the
        pre-refactor ``LoginHistoryEntry.to_dict()`` shape).
        """
        from uuid import uuid4

        from authglow.core.datetime import utcnow

        record: Dict[str, Any] = {
            "id": entry_id or str(uuid4()),
            "user_id": user_id,
            "email": email,
            "success": success,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "failure_reason": failure_reason,
            "timestamp": timestamp or utcnow().isoformat(),
        }
        path = self._entry_path(user_id, record["id"])
        await self._write_json(path, record)
        return record

    # ------------------------------------------------------------------
    # Protocol: list_for_user
    # ------------------------------------------------------------------

    async def list_for_user(
        self,
        user_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Return a paginated slice of history for a user, plus
        the total count. Newest first (sorted by ``timestamp`` desc
        with a stable tie-break on ``id``)."""
        pattern = f"{self._user_dir(user_id)}/*.json"
        files = await self._glob(pattern)
        records: List[Dict[str, Any]] = []
        for file_path in files:
            data = await self._read_json(file_path)
            if not isinstance(data, dict):
                continue
            records.append(data)
        records.sort(
            key=lambda r: (r.get("timestamp") or "", r.get("id") or ""),
            reverse=True,
        )
        total = len(records)
        return records[offset : offset + limit], total

    # ------------------------------------------------------------------
    # Protocol: cleanup_old
    # ------------------------------------------------------------------

    async def cleanup_old(self, user_id: str, cutoff: str) -> int:
        """Delete every record with ``timestamp < cutoff`` for a
        user. Returns the deletion count.

        Implementation note: uses the async-fsspec ``rm`` instead of
        the pre-refactor ``os.remove`` so the operation works on any
        backend (``s3`` / ``gcs`` / ``abfs``) without falling out of
        the fsspec abstraction.
        """
        from datetime import datetime as dt

        cutoff_dt = dt.fromisoformat(cutoff)
        pattern = f"{self._user_dir(user_id)}/*.json"
        files = await self._glob(pattern)
        deleted = 0
        for file_path in files:
            data = await self._read_json(file_path)
            if not isinstance(data, dict):
                continue
            ts_raw = data.get("timestamp")
            if not isinstance(ts_raw, str):
                continue
            try:
                ts = dt.fromisoformat(ts_raw)
            except (ValueError, TypeError):
                continue
            if ts < cutoff_dt:
                if await self._delete(file_path):
                    deleted += 1
        return deleted
