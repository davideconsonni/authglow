"""Session management for MFA flow."""

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.session import MFASession


class SessionService:
    """Service for managing temporary MFA sessions.

    Security: Sessions are stored with HMAC-SHA256 lookup keys as
    filenames — the plaintext ``session_token`` is never persisted.
    """

    def __init__(self):
        """Initialize session service with settings."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/sessions"
        self.storage_options = self.settings.get_storage_options()
        self._secret_bytes = self.settings.secret_key.encode()

        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(self.settings.storage_backend, **self.storage_options)

        self._afs = AsyncFileSystem(self.fs)

    def _compute_lookup(self, session_token: str) -> str:
        """Compute HMAC lookup key from a plaintext session token."""
        return hmac.new(self._secret_bytes, session_token.encode(), hashlib.sha256).hexdigest()

    async def create_mfa_session(
        self,
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> MFASession:
        """Create a temporary MFA session (5 minutes)."""
        plaintext = secrets.token_urlsafe(32)
        token_lookup = self._compute_lookup(plaintext)

        session = MFASession(
            session_token=plaintext,
            token_lookup=token_lookup,
            user_id=user_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            expires_at=utcnow() + timedelta(minutes=5),
        )

        path = f"{self.storage_path}/{token_lookup}.json"
        await self._afs.write_json(path, session.model_dump(mode="json"))

        return session

    async def get_mfa_session(self, session_token: str) -> Optional[MFASession]:
        """Get and validate an MFA session.

        Uses O(1) HMAC lookup — no directory scanning.
        """
        token_lookup = self._compute_lookup(session_token)
        path = f"{self.storage_path}/{token_lookup}.json"

        try:
            data = await self._afs.read_json(path)
            session = MFASession(**data)

            if utcnow() > session.expires_at:
                await self._afs.rm(path)
                return None

            session.session_token = session_token
            return session

        except Exception:
            return None

    async def delete_mfa_session(self, session_token: str) -> None:
        """Delete an MFA session."""
        token_lookup = self._compute_lookup(session_token)
        path = f"{self.storage_path}/{token_lookup}.json"
        try:
            await self._afs.rm(path)
        except Exception:
            pass

    async def create_consent_session(
        self,
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> dict:
        """Create a temporary consent session (10 minutes)."""
        plaintext = secrets.token_urlsafe(32)
        token_lookup = self._compute_lookup(plaintext)

        session_data = {
            "session_token": plaintext,
            "token_lookup": token_lookup,
            "user_id": user_id,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "nonce": nonce,
            "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(),
        }

        path = f"{self.storage_path}/consent_{token_lookup}.json"
        await self._afs.write_json(path, session_data)

        return session_data

    async def get_consent_session(self, session_token: str) -> Optional[dict]:
        """Get and validate a consent session."""
        token_lookup = self._compute_lookup(session_token)
        path = f"{self.storage_path}/consent_{token_lookup}.json"

        try:
            session_data: dict = await self._afs.read_json(path)

            expires_at = datetime.fromisoformat(session_data["expires_at"])
            if utcnow() > expires_at:
                await self._afs.rm(path)
                return None

            return session_data

        except Exception:
            return None

    async def delete_consent_session(self, session_token: str) -> None:
        """Delete a consent session."""
        token_lookup = self._compute_lookup(session_token)
        path = f"{self.storage_path}/consent_{token_lookup}.json"
        try:
            await self._afs.rm(path)
        except Exception:
            pass
