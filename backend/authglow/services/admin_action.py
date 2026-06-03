"""Admin action service — file-based store of admin actions per user."""

import os
from typing import List, Optional
from uuid import uuid4

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow


class AdminAction:
    """A single admin action record."""

    def __init__(
        self,
        admin_user_id: str,
        admin_email: str,
        action_type: str,
        target_user_id: str,
        target_user_email: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
    ):
        self.id = str(uuid4())
        self.admin_user_id = admin_user_id
        self.admin_email = admin_email
        self.action_type = action_type
        self.target_user_id = target_user_id
        self.target_user_email = target_user_email
        self.details = details or {}
        self.ip_address = ip_address
        self.timestamp = utcnow()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "admin_user_id": self.admin_user_id,
            "admin_email": self.admin_email,
            "action_type": self.action_type,
            "target_user_id": self.target_user_id,
            "target_user_email": self.target_user_email,
            "details": self.details,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AdminAction":
        action = cls(
            admin_user_id=data["admin_user_id"],
            admin_email=data["admin_email"],
            action_type=data["action_type"],
            target_user_id=data["target_user_id"],
            target_user_email=data.get("target_user_email"),
            details=data.get("details", {}),
            ip_address=data.get("ip_address"),
        )
        action.id = data["id"]
        from datetime import datetime as dt

        action.timestamp = dt.fromisoformat(data["timestamp"])
        return action


class AdminActionService:
    """Service for recording and querying admin actions."""

    RETENTION_DAYS = 365

    def __init__(self):
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/admin_actions"
        self.fs = fsspec.filesystem("file")
        self._afs = AsyncFileSystem(self.fs)

    def _get_user_dir(self, user_id: str) -> str:
        return f"{self.storage_path}/{user_id}"

    def _get_action_path(self, user_id: str, action_id: str) -> str:
        return f"{self._get_user_dir(user_id)}/{action_id}.json"

    async def record_action(
        self,
        admin_user_id: str,
        admin_email: str,
        action_type: str,
        target_user_id: str,
        target_user_email: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
    ) -> AdminAction:
        action = AdminAction(
            admin_user_id=admin_user_id,
            admin_email=admin_email,
            action_type=action_type,
            target_user_id=target_user_id,
            target_user_email=target_user_email,
            details=details,
            ip_address=ip_address,
        )
        action_path = self._get_action_path(target_user_id, action.id)
        os.makedirs(os.path.dirname(action_path), exist_ok=True)
        await self._afs.write_json(action_path, action.to_dict())
        return action

    async def get_admin_actions(
        self,
        target_user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[dict], int]:
        entries = []
        try:
            pattern = f"{self._get_user_dir(target_user_id)}/*.json"
            files = await self._afs.glob(pattern)
            for file_path in sorted(files, reverse=True):
                try:
                    data = await self._afs.read_json(file_path)
                    action = AdminAction.from_dict(data)
                    entries.append(action.to_dict())
                except Exception:
                    continue
        except Exception:
            pass

        total = len(entries)
        page = entries[offset : offset + limit]
        return page, total
