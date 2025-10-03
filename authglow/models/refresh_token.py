"""Refresh token models for token rotation."""

from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel, Field
from uuid import uuid4


class RefreshToken(BaseModel):
    """Refresh token model with rotation support."""

    token_id: str = Field(default_factory=lambda: str(uuid4()))
    token: str = Field(default_factory=lambda: str(uuid4()))  # The actual token
    user_id: str
    client_id: str
    scopes: list[str] = Field(default_factory=list)

    # Rotation tracking
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    used: bool = False
    used_at: Optional[datetime] = None
    replaced_by: Optional[str] = None  # token_id of replacement token
    parent_token_id: Optional[str] = None  # token_id of previous token

    # Security
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None

    # Metadata
    issued_ip: Optional[str] = None
    last_used_ip: Optional[str] = None

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class RefreshTokenFamily(BaseModel):
    """Represents a chain of rotated refresh tokens."""

    family_id: str  # Usually the token_id of the first token
    user_id: str
    client_id: str
    created_at: datetime
    current_token_id: str
    all_token_ids: list[str] = Field(default_factory=list)
    revoked: bool = False
