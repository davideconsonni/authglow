"""OAuth2 consent models."""

from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class OAuth2Consent(BaseModel):
    """OAuth2 user consent for client access."""

    consent_id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str
    client_id: str
    scopes: List[str] = Field(default_factory=list)
    granted_at: datetime = Field(default_factory=utcnow)
    expires_at: Optional[datetime] = None  # None = never expires
    revoked: bool = False
    revoked_at: Optional[datetime] = None

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}


class ConsentRequest(BaseModel):
    """User consent decision."""

    client_id: str
    scopes: List[str]
    approved: bool
    remember: bool = False  # Remember consent for future requests


class ConsentInfo(BaseModel):
    """Information shown on consent screen."""

    client_id: str
    client_name: str
    client_description: Optional[str] = None
    client_logo_url: Optional[str] = None
    requested_scopes: List[str]
    scope_descriptions: dict[str, str] = Field(default_factory=dict)
    user_email: str
    redirect_uri: str
    state: Optional[str] = None
