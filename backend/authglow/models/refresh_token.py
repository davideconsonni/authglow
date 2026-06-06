"""Refresh token models for token rotation."""

import secrets
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class RefreshToken(BaseModel):
    """Refresh token model with rotation support.

    Security: The plaintext ``token`` is never persisted to disk. Only
    ``token_hash`` (bcrypt) and ``token_lookup`` (HMAC-SHA256) are
    stored. The HMAC lookup key doubles as the on-disk filename for O(1)
    direct access — mirroring the PasswordResetToken pattern.
    """

    token_id: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    token: Optional[str] = Field(default_factory=lambda: secrets.token_urlsafe(32), exclude=True)
    token_hash: str = ""
    token_lookup: str = ""
    user_id: str
    client_id: str
    scopes: List[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    used: bool = False
    used_at: Optional[datetime] = None
    replaced_by: Optional[str] = None
    parent_token_id: Optional[str] = None

    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None

    issued_ip: Optional[str] = None
    last_used_ip: Optional[str] = None


class RefreshTokenFamily(BaseModel):
    """Represents a chain of rotated refresh tokens."""

    family_id: str
    user_id: str
    client_id: str
    created_at: datetime
    current_token_id: str
    all_token_ids: List[str] = Field(default_factory=list)
    revoked: bool = False
