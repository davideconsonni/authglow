"""Login history service — file-based store of login attempts per user.

Persistence is delegated to a single :class:`LoginHistoryRepository`.
The pre-refactor service had two backend-bypass bugs:

1. ``__init__`` constructed ``fsspec.filesystem("file")`` directly,
   ignoring ``Settings.storage_backend`` (line 73 of the original).
2. ``_cleanup_old_entries`` used ``os.remove(file_path)`` instead
   of the fsspec filesystem's ``rm`` (line 141 of the original),
   so cleanup would crash on any non-``file`` backend with a
   confusing ``FileNotFoundError`` / ``OSError`` from the OS
   unlink.

Both are fixed: the service no longer touches fsspec or
``AsyncFileSystem`` directly; cleanup is delegated to
:meth:`LoginHistoryRepository.cleanup_old` which uses the
backend-agnostic async fsspec ``rm``.
"""

from datetime import timedelta
from typing import List, Optional, Tuple
from uuid import uuid4

from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.core.pii import hash_pii, mask_ip, truncate
from authglow.repositories.protocols import LoginHistoryRepository


class LoginHistoryEntry:
    """A single login attempt record.

    Kept as a lightweight dataclass (not a Pydantic model) for
    backward compatibility with the pre-refactor public API
    (the admin routes in ``api/admin.py`` consume
    ``LoginHistoryService.get_login_history`` which returns
    ``List[dict]``). The repository stores records as plain
    dicts (``model_dump``-equivalent), so the service is free to
    use whatever shape it wants internally.
    """

    def __init__(
        self,
        user_id: str,
        email: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        failure_reason: Optional[str] = None,
    ):
        self.id = str(uuid4())
        self.user_id = user_id
        self.email = email
        self.success = success
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.failure_reason = failure_reason
        self.timestamp = utcnow()

    def to_dict(self) -> dict:
        """Return the *raw* (in-memory) view of the record.

        The persistence path (:meth:`LoginHistoryService.record`)
        calls :meth:`to_masked_dict` instead, which is what
        actually hits disk.
        """
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email": self.email,
            "success": self.success,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "failure_reason": self.failure_reason,
            "timestamp": self.timestamp.isoformat(),
        }

    def to_masked_dict(self, secret_key: str) -> dict:
        """Return the *masked* view for persistence (VAPT-081).

        ``email`` is replaced with a stable 16-char HMAC digest;
        ``ip_address`` is truncated to a ``/24`` / ``/48`` prefix;
        ``user_agent`` is capped to 256 chars with a marker.
        ``user_id`` is left untouched (it is an opaque
        identifier, not PII).
        """
        d = self.to_dict()
        d["email"] = hash_pii(self.email, secret_key)
        d["ip_address"] = mask_ip(self.ip_address)
        d["user_agent"] = truncate(self.user_agent)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "LoginHistoryEntry":
        entry = cls(
            user_id=data["user_id"],
            email=data["email"],
            success=data["success"],
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            failure_reason=data.get("failure_reason"),
        )
        entry.id = data["id"]
        from datetime import datetime as dt

        entry.timestamp = dt.fromisoformat(data["timestamp"])
        return entry


class LoginHistoryService:
    """Service for recording and querying login history."""

    RETENTION_DAYS = 90

    def __init__(self, repository: Optional[LoginHistoryRepository] = None):
        """Initialize the service with settings + repository.

        ``repository`` defaults to ``None`` and is resolved lazily
        via :func:`get_login_history_repository` (which returns a
        :class:`FileLoginHistoryRepository`). Tests can pass a stub
        or an in-memory implementation directly.

        The factory receives the already-resolved ``self.settings``
        so the repository's filesystem binds to the same
        ``Settings.storage_path`` the service uses — otherwise
        :class:`BaseFileRepository` would hit the ``lru_cache``'d
        global ``get_settings`` singleton and bypass the per-test
        settings patch.
        """
        from authglow.repositories.dependencies import (
            get_login_history_repository,
        )

        self.settings = get_settings()
        self._repo = repository or get_login_history_repository(settings=self.settings)

    async def record_login(
        self,
        user_id: str,
        email: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        failure_reason: Optional[str] = None,
    ) -> LoginHistoryEntry:
        """Record a new login attempt and trigger the per-user
        retention sweep (90 days, configurable via
        :attr:`RETENTION_DAYS`).

        VAPT-081: PII is masked *before* persistence. The raw
        values are kept on the returned :class:`LoginHistoryEntry`
        so the API response can still surface them to the admin
        viewer (per the pre-VAPT-081 contract). What hits disk
        via :meth:`record` is the masked form.
        """
        entry = LoginHistoryEntry(
            user_id=user_id,
            email=email,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            failure_reason=failure_reason,
        )
        # VAPT-081: mask PII before persistence. The repository
        # takes individual kwargs so we unwrap ``to_masked_dict``.
        masked = entry.to_masked_dict(self.settings.secret_key)
        await self._repo.record(
            user_id=masked["user_id"],
            email=masked["email"],
            success=masked["success"],
            ip_address=masked["ip_address"],
            user_agent=masked["user_agent"],
            failure_reason=masked["failure_reason"],
            entry_id=masked["id"],
            timestamp=masked["timestamp"],
        )
        await self._cleanup_old_entries(entry.user_id)
        return entry

    async def get_login_history(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[dict], int]:
        """Return a paginated slice of the user's login history
        (newest first) plus the total count."""
        return await self._repo.list_for_user(user_id, limit=limit, offset=offset)

    async def _cleanup_old_entries(self, user_id: str) -> None:
        """Sweep records older than :attr:`RETENTION_DAYS` for one
        user. Delegates to the repository (which uses the
        async-fsspec ``rm`` — backend-agnostic).
        """
        cutoff = (utcnow() - timedelta(days=self.RETENTION_DAYS)).isoformat()
        await self._repo.cleanup_old(user_id, cutoff)
