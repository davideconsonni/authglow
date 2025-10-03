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
        state: Optional[str] = None
    ) -> MFASession:
        """Create a temporary MFA session (5 minutes)."""
        session = MFASession(
            user_id=user_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
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
