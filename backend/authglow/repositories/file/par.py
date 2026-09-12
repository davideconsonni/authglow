"""File-backed persistence for Pushed Authorization Requests (RFC 9126, OA-501).

Requests are short-lived (TTL, 90s default) single-use secrets. The
file is named after the opaque ``request_id`` (the tail of the
``request_uri`` URN — the full URN contains colons, which are not
valid filename characters on all platforms). The repository owns:

* the file layout (``<storage>/par_requests/{request_id}.json``);
* the JSON serialisation of the ``PushedAuthorizationRequest`` model;
* the ``get_by_request_id`` policy: absent / corrupt / expired (and
  auto-deleted) / already-used all return ``None``;
* the ``mark_used`` CAS-protected update with bounded retries.

The service layer in ``services/par.py`` keeps the in-process
``named_lock`` and the request construction (id default factory,
``expires_at`` calculation from settings TTL).
"""

from typing import Optional

from authglow.core.config import Settings
from authglow.core.datetime import utcnow
from authglow.models.par import PushedAuthorizationRequest
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import PushedAuthorizationRequestRepository


class FilePushedAuthorizationRequestRepository(
    BaseFileRepository, PushedAuthorizationRequestRepository
):
    """Persists pushed requests as one JSON file per ``request_id``.

    File layout::

        <storage_path>/par_requests/{request_id}.json
    """

    _subdir = "par_requests"
    MAX_CAS_RETRIES = 3

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    @staticmethod
    def _filename(request_id: str) -> str:
        return f"{request_id}.json"

    def _path_for(self, request_id: str) -> str:
        return self._path(self._filename(request_id))

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create(self, request: PushedAuthorizationRequest) -> None:
        """Persist a new pushed request. Overwrites any prior entry
        for the same id."""
        path = self._path_for(request.request_id)
        await self._write_json(path, request.model_dump(mode="json"))

    async def get_by_request_id(self, request_id: str) -> Optional[PushedAuthorizationRequest]:
        """Return the request, or ``None`` for missing / corrupt /
        used / expired (auto-deleted) entries."""
        path = self._path_for(request_id)
        if not await self._exists(path):
            return None
        try:
            data, _ = await self._read_json_versioned(path)
        except (ValueError, TypeError):
            return None
        if data is None:
            return None
        try:
            par = PushedAuthorizationRequest(**data)
        except Exception:
            return None
        if par.used:
            return None
        if utcnow() > par.expires_at:
            await self._delete(path)
            return None
        return par

    async def mark_used(self, request_id: str) -> bool:
        """Atomically mark the request as used. ``True`` on first use."""
        path = self._path_for(request_id)
        for _ in range(self.MAX_CAS_RETRIES):
            if not await self._exists(path):
                return False
            try:
                data, version = await self._read_json_versioned(path)
            except (ValueError, TypeError):
                return False
            if data is None:
                return False
            try:
                par = PushedAuthorizationRequest(**data)
            except Exception:
                return False
            if par.used:
                return False
            if utcnow() > par.expires_at:
                return False
            par.used = True
            try:
                await self._write_json_versioned(path, par.model_dump(mode="json"), version)
                return True
            except Exception:
                continue
        return False

    async def delete(self, request_id: str) -> None:
        """Remove the request. No-op if absent."""
        await self._delete(self._path_for(request_id))
