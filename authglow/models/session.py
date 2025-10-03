"""Temporary session models for MFA flow."""

from datetime import datetime
from pydantic import BaseModel, Field
from uuid import uuid4


class MFASession(BaseModel):
    """Temporary session after first auth step, waiting for MFA."""

    session_token: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime  # Short-lived (5 minutes)
