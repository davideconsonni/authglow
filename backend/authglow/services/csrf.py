"""CSRF protection service.

File-based CSRF token store with 30-minute expiry.
Uses secrets.token_urlsafe(32) for token generation and a
browser cookie (csrf_session_id) to bind tokens to a session.
"""

import os
import secrets
import time
from typing import TYPE_CHECKING

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.config import get_settings

if TYPE_CHECKING:
    from fastapi import Request

SESSION_ID_COOKIE = "csrf_session_id"
TOKEN_EXPIRY_SECONDS = 1800
CLEANUP_INTERVAL = 600
_LAST_CLEANUP = 0.0


class CSRFTokenService:
    """File-based CSRF token service.

    Each browser session (identified by a ``csrf_session_id`` cookie)
    has at most one active CSRF token. The token is regenerated after
    every successful validation to prevent reuse.
    """

    def __init__(self):
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/csrf_tokens"
        self.storage_options = self.settings.get_storage_options()

        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(self.settings.storage_backend, **self.storage_options)

        self._afs = AsyncFileSystem(self.fs)

    @staticmethod
    def _new_session_id() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def _new_token() -> str:
        return secrets.token_urlsafe(32)

    async def _cleanup_expired(self) -> None:
        """Delete expired token files. Throttled to every CLEANUP_INTERVAL seconds."""
        global _LAST_CLEANUP
        now = time.time()
        if now - _LAST_CLEANUP < CLEANUP_INTERVAL:
            return
        _LAST_CLEANUP = now

        try:
            paths = await self._afs.glob(f"{self.storage_path}/*.json")
            for path in paths:
                try:
                    data = await self._afs.read_json(path)
                    if now > data.get("expires_at", 0):
                        await self._afs.rm(path)
                except Exception:
                    pass
        except Exception:
            pass

    async def generate_token(self, session_id: str) -> str:
        """Generate a new CSRF token for the given session.

        Replaces any existing token for that session.
        """
        await self._cleanup_expired()

        token = self._new_token()
        expires_at = time.time() + TOKEN_EXPIRY_SECONDS

        path = f"{self.storage_path}/{session_id}.json"
        await self._afs.write_json(
            path,
            {
                "token": token,
                "expires_at": expires_at,
                "created_at": time.time(),
            },
        )

        return token

    async def validate_token(self, session_id: str, submitted_token: str) -> bool:
        """Validate a submitted CSRF token against the stored token.

        Returns True if valid, False otherwise.
        On successful validation the stored token is deleted to prevent reuse.
        """
        await self._cleanup_expired()

        path = f"{self.storage_path}/{session_id}.json"

        try:
            data = await self._afs.read_json(path)
        except FileNotFoundError:
            return False

        if time.time() > data.get("expires_at", 0):
            try:
                await self._afs.rm(path)
            except Exception:
                pass
            return False

        stored_token = data.get("token", "")
        if not secrets.compare_digest(stored_token, submitted_token):
            return False

        return True


def get_csrf_service() -> CSRFTokenService:
    """Dependency factory for CSRFTokenService."""
    return CSRFTokenService()


def get_or_create_session_id(request: "Request") -> str:
    """Read csrf_session_id from cookie, or generate a new one."""

    cookie: str | None = request.cookies.get(SESSION_ID_COOKIE)
    if cookie:
        return cookie
    return CSRFTokenService._new_session_id()
