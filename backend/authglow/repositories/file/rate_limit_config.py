"""File-backed persistence for the admin rate-limit configuration.

Single JSON document at ``<storage_path>/rate_limit_config/config.json``
holding the global enable flag and the per-route overrides. Every node
reads this file at startup and on the periodic refresh tick, so a PUT
processed by one worker converges on the others within the refresh
interval (see ``RateLimitConfigService.refresh_if_changed``).

File layout::

    <storage_path>/rate_limit_config/config.json
"""

from typing import Optional

from authglow.core.config import Settings
from authglow.models.rate_limit_config import RateLimitConfig
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import RateLimitConfigRepository


class FileRateLimitConfigRepository(BaseFileRepository, RateLimitConfigRepository):
    """Persists the rate-limit configuration as a single JSON file."""

    _subdir = "rate_limit_config"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    async def load(self) -> Optional[RateLimitConfig]:
        """Return the persisted configuration, or ``None`` if absent/corrupt."""
        path = self._path("config.json")
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return RateLimitConfig.model_validate(data)
        except (ValueError, TypeError):
            return None

    async def save(self, config: RateLimitConfig) -> None:
        """Persist the configuration (atomic full replace)."""
        path = self._path("config.json")
        await self._write_json_atomic(path, config.model_dump(mode="json"))
