"""External Identity Provider federation models."""

from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from authglow.core.datetime import utcnow


class ExternalIdpConfig(BaseModel):
    """Configuration for an external OIDC identity provider."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    label: str
    description: Optional[str] = None

    issuer: str
    client_id: str
    client_secret: str
    scopes: List[str] = Field(default_factory=lambda: ["openid", "profile", "email"])

    icon_uri: Optional[str] = None
    logo_uri: Optional[str] = None

    enabled: bool = True

    auth_levels: Optional[List[str]] = None

    visible_contexts: List[str] = Field(
        default_factory=lambda: ["dashboard", "oauth2"],
        description="Contexts where this provider is visible: dashboard, oauth2.",
    )

    claims_mapping: Dict[str, str] = Field(
        default_factory=lambda: {
            "sub": "external_id",
            "email": "email",
            "name": "name",
            "given_name": "given_name",
            "family_name": "family_name",
            "picture": "picture",
        }
    )

    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    created_by: Optional[str] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "label": "CIE",
                "issuer": "https://idserver.servizicie.interno.gov.it",
                "client_id": "your-client-id",
                "scopes": ["openid", "profile", "email"],
                "auth_levels": ["L1", "L2", "L3"],
            }
        }
    )


class ExternalIdpConfigCreate(BaseModel):
    """Schema for creating an external IdP configuration."""

    label: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    issuer: str
    client_id: str
    client_secret: str
    scopes: List[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    icon_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    enabled: bool = True
    auth_levels: Optional[List[str]] = None
    visible_contexts: Optional[List[str]] = None
    claims_mapping: Optional[Dict[str, str]] = None


class ExternalIdpConfigUpdate(BaseModel):
    """Schema for updating an external IdP configuration."""

    label: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    issuer: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scopes: Optional[List[str]] = None
    icon_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    enabled: Optional[bool] = None
    auth_levels: Optional[List[str]] = None
    visible_contexts: Optional[List[str]] = None
    claims_mapping: Optional[Dict[str, str]] = None


class ExternalIdpConfigResponse(BaseModel):
    """Public response for an external IdP config (without secret)."""

    id: str
    label: str
    description: Optional[str] = None
    issuer: str
    client_id: str
    scopes: List[str]
    icon_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    enabled: bool
    auth_levels: Optional[List[str]] = None
    visible_contexts: List[str]
    claims_mapping: Dict[str, str]
    created_at: datetime
    updated_at: datetime
