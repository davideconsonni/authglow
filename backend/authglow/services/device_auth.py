"""Device Authorization Grant (RFC 8628) service.

Handles the creation, polling, and lifecycle of device
authorizations. The device-initiated flow:

1. Device calls ``POST /oauth2/device/authorize`` →
   ``create_device_authorization``
2. User visits ``verification_uri``, enters ``user_code`` →
   ``verify_user_code``
3. User approves/denies → ``approve`` / ``deny``
4. Device polls ``POST /oauth2/token`` with
   ``grant_type=urn:ietf:params:oauth:grant-type:device_code``
   → ``poll`` (returns model or None)
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import structlog

from authglow.core.config import Settings, get_settings
from authglow.models.token import DeviceAuthorization
from authglow.repositories.protocols import DeviceAuthorizationRepository

logger = structlog.get_logger("authglow.audit")


class DeviceAuthorizationService:
    """Business logic for the OAuth 2.0 Device Authorization Grant."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self._repo: DeviceAuthorizationRepository = self._default_repository()

    def _default_repository(self) -> DeviceAuthorizationRepository:
        from authglow.repositories.file.device_authorization import (
            FileDeviceAuthorizationRepository,
        )

        return FileDeviceAuthorizationRepository(settings=self.settings)

    @staticmethod
    def _generate_user_code() -> str:
        raw = secrets.token_hex(4).upper()
        return f"{raw[:4]}-{raw[4:8]}"

    async def create_device_authorization(
        self,
        client_id: str,
        scope: str,
        verification_uri: str,
    ) -> DeviceAuthorization:
        """Create a new device authorization request."""
        now = datetime.now(timezone.utc)
        auth = DeviceAuthorization(
            device_code=secrets.token_urlsafe(32),
            user_code=self._generate_user_code(),
            client_id=client_id,
            scope=scope,
            verification_uri=verification_uri,
            expires_at=now + timedelta(seconds=self.settings.device_code_expire_seconds),
            interval=self.settings.device_poll_interval_seconds,
            status="pending",
        )
        await self._repo.create(auth)
        logger.info(
            "device_authorization_created",
            client_id=client_id,
            device_code=auth.device_code[:8] + "...",
        )
        return auth

    async def poll(self, device_code: str) -> Optional[DeviceAuthorization]:
        """Poll for the current state of a device authorization.

        Updates ``last_poll_at`` when the status is still ``pending``.
        Returns the model, or ``None`` if not found.
        """
        auth: Optional[DeviceAuthorization] = await self._repo.get_by_device_code(device_code)
        if auth is None:
            return None
        if auth.status == "pending":
            now = datetime.now(timezone.utc)
            if auth.last_poll_at:
                elapsed = (now - auth.last_poll_at).total_seconds()
                if elapsed < auth.interval:
                    return auth
            auth.last_poll_at = now
            await self._repo.update(auth)
        return auth

    async def verify_user_code(self, user_code: str) -> Optional[DeviceAuthorization]:
        """Look up a device authorization by user_code."""
        result: Optional[DeviceAuthorization] = await self._repo.get_by_user_code(user_code)
        return result

    async def approve(self, user_code: str, user_id: str) -> bool:
        """Approve a device authorization for the given user."""
        auth = await self._repo.get_by_user_code(user_code)
        if auth is None or auth.status != "pending":
            return False
        auth.status = "authorized"
        auth.user_id = user_id
        auth.authorized_at = datetime.now(timezone.utc)
        await self._repo.update(auth)
        logger.info(
            "device_authorization_approved",
            user_id=user_id,
            client_id=auth.client_id,
            device_code=auth.device_code[:8] + "...",
        )
        return True

    async def deny(self, user_code: str) -> bool:
        """Deny a device authorization."""
        auth = await self._repo.get_by_user_code(user_code)
        if auth is None or auth.status != "pending":
            return False
        auth.status = "denied"
        await self._repo.update(auth)
        logger.info(
            "device_authorization_denied",
            client_id=auth.client_id,
            device_code=auth.device_code[:8] + "...",
        )
        return True

    async def cleanup_expired(self) -> int:
        """Delete all expired device authorizations."""
        count: int = await self._repo.delete_expired()
        return count

    async def list_all(
        self, status_filter: Optional[str] = None
    ) -> List[DeviceAuthorization]:
        """Return all device authorizations, optionally filtered by status."""
        result: List[DeviceAuthorization] = await self._repo.list_all(status_filter)
        return result

    async def list_by_user(self, user_id: str) -> List[DeviceAuthorization]:
        """Return all device authorizations for a specific user."""
        all_auths: List[DeviceAuthorization] = await self._repo.list_all()
        return [a for a in all_auths if a.user_id == user_id]

    async def revoke(self, device_code: str) -> bool:
        """Revoke a device authorization by setting it to denied."""
        auth: Optional[DeviceAuthorization] = await self._repo.get_by_device_code(
            device_code
        )
        if auth is None:
            return False
        if auth.status not in ("pending", "authorized"):
            return False
        auth.status = "denied"
        await self._repo.update(auth)
        logger.info(
            "device_authorization_revoked",
            device_code=auth.device_code[:8] + "...",
            client_id=auth.client_id,
        )
        return True
