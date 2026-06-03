"""Login history service — file-based store of login attempts per user."""

import os
from datetime import timedelta
from typing import List, Optional
from uuid import uuid4

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow


class LoginHistoryEntry:
    """A single login attempt record."""

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

    def __init__(self):
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/login_history"
        self.fs = fsspec.filesystem("file")
        self._afs = AsyncFileSystem(self.fs)

    def _get_user_dir(self, user_id: str) -> str:
        return f"{self.storage_path}/{user_id}"

    def _get_entry_path(self, user_id: str, entry_id: str) -> str:
        return f"{self._get_user_dir(user_id)}/{entry_id}.json"

    async def record_login(
        self,
        user_id: str,
        email: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        failure_reason: Optional[str] = None,
    ) -> LoginHistoryEntry:
        entry = LoginHistoryEntry(
            user_id=user_id,
            email=email,
            success=success,
            ip_address=ip_address,
            user_agent=user_agent,
            failure_reason=failure_reason,
        )
        entry_path = self._get_entry_path(user_id, entry.id)
        os.makedirs(os.path.dirname(entry_path), exist_ok=True)
        await self._afs.write_json(entry_path, entry.to_dict())
        await self._cleanup_old_entries(user_id)
        return entry

    async def get_login_history(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[dict], int]:
        entries = []
        try:
            pattern = f"{self._get_user_dir(user_id)}/*.json"
            files = await self._afs.glob(pattern)
            for file_path in sorted(files, reverse=True):
                try:
                    data = await self._afs.read_json(file_path)
                    entry = LoginHistoryEntry.from_dict(data)
                    entries.append(entry.to_dict())
                except Exception:
                    continue
        except Exception:
            pass

        total = len(entries)
        page = entries[offset : offset + limit]
        return page, total

    async def _cleanup_old_entries(self, user_id: str) -> None:
        cutoff = utcnow() - timedelta(days=self.RETENTION_DAYS)
        try:
            pattern = f"{self._get_user_dir(user_id)}/*.json"
            files = await self._afs.glob(pattern)
            for file_path in files:
                try:
                    data = await self._afs.read_json(file_path)
                    from datetime import datetime as dt

                    ts = dt.fromisoformat(data["timestamp"])
                    if ts < cutoff:
                        os.remove(file_path)
                except Exception:
                    continue
        except Exception:
            pass
