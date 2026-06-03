"""Security events service — file-based store of security events per user."""

import os
from typing import List, Optional
from uuid import uuid4

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow


class SecurityEvent:
    """A single security event record."""

    def __init__(
        self,
        user_id: str,
        event_type: str,
        email: Optional[str] = None,
        description: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[dict] = None,
    ):
        self.id = str(uuid4())
        self.user_id = user_id
        self.event_type = event_type
        self.email = email
        self.description = description
        self.ip_address = ip_address
        self.metadata = metadata or {}
        self.timestamp = utcnow()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "email": self.email,
            "description": self.description,
            "ip_address": self.ip_address,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SecurityEvent":
        event = cls(
            user_id=data["user_id"],
            event_type=data["event_type"],
            email=data.get("email"),
            description=data.get("description"),
            ip_address=data.get("ip_address"),
            metadata=data.get("metadata", {}),
        )
        event.id = data["id"]
        from datetime import datetime as dt

        event.timestamp = dt.fromisoformat(data["timestamp"])
        return event


class SecurityEventService:
    """Service for recording and querying security events."""

    RETENTION_DAYS = 365

    def __init__(self):
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/security_events"
        self.fs = fsspec.filesystem("file")
        self._afs = AsyncFileSystem(self.fs)

    def _get_user_dir(self, user_id: str) -> str:
        return f"{self.storage_path}/{user_id}"

    def _get_event_path(self, user_id: str, event_id: str) -> str:
        return f"{self._get_user_dir(user_id)}/{event_id}.json"

    async def record_event(
        self,
        user_id: str,
        event_type: str,
        email: Optional[str] = None,
        description: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> SecurityEvent:
        event = SecurityEvent(
            user_id=user_id,
            event_type=event_type,
            email=email,
            description=description,
            ip_address=ip_address,
            metadata=metadata,
        )
        event_path = self._get_event_path(user_id, event.id)
        os.makedirs(os.path.dirname(event_path), exist_ok=True)
        await self._afs.write_json(event_path, event.to_dict())
        return event

    async def get_security_events(
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
                    event = SecurityEvent.from_dict(data)
                    entries.append(event.to_dict())
                except Exception:
                    continue
        except Exception:
            pass

        total = len(entries)
        page = entries[offset : offset + limit]
        return page, total
