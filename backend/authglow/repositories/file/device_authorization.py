"""File-backed persistence for OAuth 2.0 Device Authorization Grants (RFC 8628).

Device authorizations are stored as one JSON file per ``device_code``
with a secondary index file keyed by ``user_code`` for fast lookup
during the browser-based approval flow.

File layout::

    <storage_path>/device_auth/{device_code}.json
    <storage_path>/device_auth/_by_user_code/{user_code}.json

The ``_by_user_code`` directory contains tiny JSON files that reference
the ``device_code``, avoiding a full glob scan on every user_code lookup.
"""

from typing import List, Optional

from authglow.core.config import Settings
from authglow.core.datetime import utcnow
from authglow.models.token import DeviceAuthorization
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import DeviceAuthorizationRepository


class FileDeviceAuthorizationRepository(
    BaseFileRepository, DeviceAuthorizationRepository
):
    """Persists device authorizations as JSON files.

    Two indices:
    * ``device_auth/{device_code}.json`` — primary, full model
    * ``device_auth/_by_user_code/{user_code}.json`` — secondary index
    """

    _subdir = "device_auth"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    @staticmethod
    def _filename(device_code: str) -> str:
        return f"{device_code}.json"

    @staticmethod
    def _user_code_filename(user_code: str) -> str:
        return f"_by_user_code/{user_code}.json"

    def _path_for(self, device_code: str) -> str:
        return self._path(self._filename(device_code))

    def _path_for_user_code(self, user_code: str) -> str:
        return self._path(self._user_code_filename(user_code))

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create(self, auth: DeviceAuthorization) -> None:
        """Persist a new device authorization with both indices."""
        primary_path = self._path_for(auth.device_code)
        index_path = self._path_for_user_code(auth.user_code)

        await self._ensure_parent(primary_path)
        await self._ensure_parent(index_path)

        await self._write_json(primary_path, auth.model_dump(mode="json"))
        await self._write_json(index_path, {"device_code": auth.device_code})

    async def get_by_device_code(self, device_code: str) -> Optional[DeviceAuthorization]:
        """Return the device authorization by device_code, or None."""
        path = self._path_for(device_code)
        if not await self._exists(path):
            return None
        try:
            data = await self._read_json(path)
        except (ValueError, TypeError):
            return None
        if data is None:
            return None
        try:
            auth = DeviceAuthorization(**data)
        except Exception:
            return None
        if utcnow() > auth.expires_at:
            auth.status = "expired"
        return auth

    async def get_by_user_code(self, user_code: str) -> Optional[DeviceAuthorization]:
        """Return the device authorization by user_code, or None."""
        index_path = self._path_for_user_code(user_code)
        if not await self._exists(index_path):
            return None
        try:
            index_data = await self._read_json(index_path)
        except (ValueError, TypeError):
            return None
        if index_data is None:
            return None
        device_code = index_data.get("device_code")
        if not device_code:
            return None
        return await self.get_by_device_code(device_code)

    async def update(self, auth: DeviceAuthorization) -> None:
        """Update an existing device authorization."""
        primary_path = self._path_for(auth.device_code)
        await self._write_json(primary_path, auth.model_dump(mode="json"))

    async def delete_expired(self) -> int:
        """Delete all expired device authorizations. Returns count deleted."""
        import os as _os

        pattern = self._path("*.json")
        files = await self._glob(pattern)
        count = 0
        now = utcnow()
        for filepath in files:
            filename = _os.path.basename(filepath)
            if filename.startswith("_"):
                continue
            try:
                data = await self._read_json(filepath)
            except (ValueError, TypeError):
                continue
            if data is None:
                continue
            try:
                auth = DeviceAuthorization(**data)
            except Exception:
                continue
            if now > auth.expires_at:
                await self._delete(filepath)
                index_path = self._path_for_user_code(auth.user_code)
                await self._delete(index_path)
                count += 1
        return count

    async def list_all(
        self, status_filter: Optional[str] = None
    ) -> List[DeviceAuthorization]:
        """Return all device authorizations, optionally filtered by status."""
        import os as _os

        pattern = self._path("*.json")
        files = await self._glob(pattern)
        result: List[DeviceAuthorization] = []
        for filepath in files:
            filename = _os.path.basename(filepath)
            if filename.startswith("_"):
                continue
            try:
                data = await self._read_json(filepath)
            except (ValueError, TypeError):
                continue
            if data is None:
                continue
            try:
                auth = DeviceAuthorization(**data)
            except Exception:
                continue
            if utcnow() > auth.expires_at:
                auth.status = "expired"
            if status_filter and auth.status != status_filter:
                continue
            result.append(auth)
        result.sort(key=lambda a: a.created_at, reverse=True)
        return result

    async def delete(self, device_code: str) -> None:
        """Delete a single device authorization. No-op if absent."""
        auth = await self.get_by_device_code(device_code)
        if auth is None:
            return
        primary_path = self._path_for(device_code)
        index_path = self._path_for_user_code(auth.user_code)
        await self._delete(primary_path)
        await self._delete(index_path)
