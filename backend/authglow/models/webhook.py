"""Webhook Endpoint domain model.

A Webhook Endpoint is a URL registered by an admin that receives signed
IdP events (see CONTEXT.md). HTTPS endpoints are the norm; plain-HTTP
endpoints require the explicit per-endpoint ``insecure`` opt-in (the
dispatcher skips its SSRF guard for them). The ``secret`` field carries
the Signing Secret in PLAINTEXT at the domain layer — the repository is
responsible for encrypting it at rest (same pattern as User PII fields).
"""

from datetime import datetime
from typing import List

from pydantic import BaseModel, Field, field_validator

from authglow.core.datetime import utcnow
from authglow.models.webhook_events import VALID_EVENT_TYPES


class WebhookEndpoint(BaseModel):
    """A registered webhook endpoint receiving signed IdP events."""

    id: str = Field(pattern=r"^wh_[A-Za-z0-9_-]{10,}$")
    url: str
    events: List[str]
    secret: str  # plaintext in the DOMAIN; encrypted at rest by the repository
    active: bool = True
    # Explicit opt-out from HTTPS enforcement and from the delivery-time
    # SSRF guard. Default False covers legacy documents stored before the
    # field existed (no migration needed).
    insecure: bool = False
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @field_validator("events")
    @classmethod
    def _events_must_be_in_catalog(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("At least one event type is required")
        unknown = [e for e in v if e not in VALID_EVENT_TYPES]
        if unknown:
            raise ValueError(f"Unknown event types: {', '.join(sorted(unknown))}")
        # De-duplicate preserving order so the subscription list stays clean.
        seen: set = set()
        return [e for e in v if not (e in seen or seen.add(e))]

    @field_validator("url")
    @classmethod
    def _url_non_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("URL is required")
        return v.strip()
