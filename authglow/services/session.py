"""Session management for MFA flow."""

import json
import os
from datetime import datetime, timedelta
from typing import Optional
import fsspec

from authglow.core.config import get_settings
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
                self.settings.storage_backend,
                **self.storage_options
            )

    async def create_mfa_session(
        self,
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None
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
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )

        path = f"{self.storage_path}/{session.session_token}.json"
        with self.fs.open(path, "w") as f:
            json.dump(session.model_dump(mode="json"), f, indent=2, default=str)

        return session

    async def get_mfa_session(self, session_token: str) -> Optional[MFASession]:
        """Get and validate an MFA session."""
        path = f"{self.storage_path}/{session_token}.json"

        try:
            with self.fs.open(path, "r") as f:
                data = json.load(f)
                session = MFASession(**data)

                # Check if expired
                if datetime.utcnow() > session.expires_at:
                    self.fs.rm(path)
                    return None

                return session

        except FileNotFoundError:
            return None

    async def delete_mfa_session(self, session_token: str):
        """Delete an MFA session."""
        path = f"{self.storage_path}/{session_token}.json"
        try:
            self.fs.rm(path)
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
        nonce: Optional[str] = None
    ) -> dict:
        """Create a temporary consent session (10 minutes)."""
        from uuid import uuid4

        session_token = str(uuid4())
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
            "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        }

        path = f"{self.storage_path}/consent_{session_token}.json"
        with self.fs.open(path, "w") as f:
            json.dump(session_data, f, indent=2, default=str)

        return session_data

    async def get_consent_session(self, session_token: str) -> Optional[dict]:
        """Get and validate a consent session."""
        path = f"{self.storage_path}/consent_{session_token}.json"

        try:
            with self.fs.open(path, "r") as f:
                session_data = json.load(f)

                # Check if expired
                expires_at = datetime.fromisoformat(session_data["expires_at"])
                if datetime.utcnow() > expires_at:
                    self.fs.rm(path)
                    return None

                return session_data

        except FileNotFoundError:
            return None

    async def delete_consent_session(self, session_token: str):
        """Delete a consent session."""
        path = f"{self.storage_path}/consent_{session_token}.json"
        try:
            self.fs.rm(path)
        except FileNotFoundError:
            pass
