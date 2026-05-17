"""API Key models."""

from datetime import datetime, timedelta
from typing import List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class APIKey(BaseModel):
    """API Key model."""

    key_id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str
    name: str
    description: Optional[str] = None
    key_prefix: str  # First 8 chars for display (e.g., "ak_12345678")
    key_hash: str  # Hashed full key
    scopes: List[str] = Field(default_factory=list)
    is_active: bool = True

    # Expiration
    expires_at: Optional[datetime] = None
    never_expires: bool = False

    # Usage tracking
    last_used_at: Optional[datetime] = None
    total_requests: int = 0
    last_used_ip: Optional[str] = None
    last_used_ua: Optional[str] = None

    # Metadata
    created_at: datetime = Field(default_factory=utcnow)
    created_by: str  # user_id of creator
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None

    # IP restrictions (optional)
    allowed_ips: List[str] = Field(default_factory=list)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}


class APIKeyCreate(BaseModel):
    """Request model for creating an API key."""

    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    scopes: List[str] = Field(default_factory=lambda: ["read"])
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)
    never_expires: bool = False
    allowed_ips: List[str] = Field(default_factory=list)


class APIKeyResponse(BaseModel):
    """Response model for API key (without sensitive data)."""

    key_id: str
    user_id: str
    user_email: Optional[str] = None
    name: str
    description: Optional[str]
    key_prefix: str
    scopes: List[str]
    is_active: bool
    expires_at: Optional[datetime]
    never_expires: bool
    last_used_at: Optional[datetime]
    total_requests: int
    created_at: datetime
    allowed_ips: List[str]
    last_used_ip: Optional[str] = None
    last_used_ua: Optional[str] = None

    @property
    def usage_count(self) -> int:
        """Alias for total_requests for backward compatibility."""
        return self.total_requests


class APIKeyWithSecret(APIKeyResponse):
    """Response model including the plaintext key (only returned on creation)."""

    api_key: str  # Full plaintext key, only shown once


class APIKeyUpdate(BaseModel):
    """Request model for updating an API key."""

    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    scopes: Optional[List[str]] = None
    is_active: Optional[bool] = None
    allowed_ips: Optional[List[str]] = None


class APIKeyUsageStats(BaseModel):
    """Usage statistics for an API key."""

    key_id: str
    name: str
    total_requests: int
    last_used_at: Optional[datetime]
    requests_last_24h: int = 0
    requests_last_7d: int = 0
    requests_last_30d: int = 0
