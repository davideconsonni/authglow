"""File-backed persistence for admin ``Settings`` overrides.

Single JSON document at ``<storage_path>/settings_override/overrides.json``
holding the ``{setting_key: value}`` map applied by
``SettingsOverrideService`` onto the live ``Settings`` singleton at
startup and on the periodic refresh tick.

File layout::

    <storage_path>/settings_override/overrides.json
"""

from typing import Any, Dict, Optional

from authglow.core.config import Settings
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import SettingsOverrideRepository


class FileSettingsOverrideRepository(BaseFileRepository, SettingsOverrideRepository):
    """Persists the settings overrides as a single JSON file."""

    _subdir = "settings_override"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    async def load(self) -> Optional[Dict[str, Any]]:
        """Return the persisted overrides map, or ``None`` if absent/corrupt."""
        path = self._path("overrides.json")
        data = await self._read_json(path)
        if data is None or not isinstance(data, dict):
            return None
        return dict(data)

    async def save(self, overrides: Dict[str, Any]) -> None:
        """Persist the overrides map (atomic full replace)."""
        path = self._path("overrides.json")
        await self._write_json_atomic(path, overrides)
