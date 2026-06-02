"""Temporary session models for MFA flow."""

import secrets
from datetime import datetime

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class MFASession(BaseModel):
    """Temporary session after first auth step, waiting for MFA."""

    session_token: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    user_id: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    nonce: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime  # Short-lived (5 minutes)
