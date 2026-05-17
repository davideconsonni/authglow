"""Session management for MFA flow."""

import json
import os
from datetime import datetime, timedelta
from typing import Optional
import fsspec

from authglow.core.config import get_settings
from authglow.core.async_io import AsyncFileSystem
from authglow.core.datetime import utcnow
from authglow.models.session import MFASession


class SessionService:
    """Service for managing temporary MFA sessions."""

    def __init__(self):
        """Initialize session service with settings."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/sessions"
        self.storage_options = self.settings.get_storage_options()

        # Initialize filesystem
        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend, **self.storage_options
            )

        self._afs = AsyncFileSystem(self.fs)

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
        session = MFASession(
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

        path = f"{self.storage_path}/{session.session_token}.json"
        await self._afs.write_json(path, session.model_dump(mode="json"))

        return session

    async def get_mfa_session(self, session_token: str) -> Optional[MFASession]:
        """Get and validate an MFA session."""
        path = f"{self.storage_path}/{session_token}.json"

        try:
            data = await self._afs.read_json(path)
            session = MFASession(**data)

            # Check if expired
            if utcnow() > session.expires_at:
                await self._afs.rm(path)
                return None

            return session

        except FileNotFoundError:
            return None

    async def delete_mfa_session(self, session_token: str):
        """Delete an MFA session."""
        path = f"{self.storage_path}/{session_token}.json"
        try:
            await self._afs.rm(path)
        except FileNotFoundError:
            pass

    # Consent session methods (for OAuth2 consent flow)

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
        from secrets import token_urlsafe

        session_token = token_urlsafe(32)
        session_data = {
            "session_token": session_token,
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

        path = f"{self.storage_path}/consent_{session_token}.json"
        await self._afs.write_json(path, session_data)

        return session_data

    async def get_consent_session(self, session_token: str) -> Optional[dict]:
        """Get and validate a consent session."""
        path = f"{self.storage_path}/consent_{session_token}.json"

        try:
            session_data = await self._afs.read_json(path)

            # Check if expired
            expires_at = datetime.fromisoformat(session_data["expires_at"])
            if utcnow() > expires_at:
                await self._afs.rm(path)
                return None

            return session_data

        except FileNotFoundError:
            return None

    async def delete_consent_session(self, session_token: str):
        """Delete a consent session."""
        path = f"{self.storage_path}/consent_{session_token}.json"
        try:
            await self._afs.rm(path)
        except FileNotFoundError:
            pass
