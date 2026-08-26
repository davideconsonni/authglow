"""Webhook Delivery domain model.

One record PER ATTEMPT (not per event): a failed first try followed by a
successful retry produces two records. Kept for observability of the
retry/backoff behaviour and for the admin deliveries view (B4).
"""

import secrets
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class WebhookDelivery(BaseModel):
    """A single delivery attempt of an event to a Webhook Endpoint."""

    id: str = Field(default_factory=lambda: "dlv_" + secrets.token_urlsafe(12))
    webhook_id: str
    event_type: str
    attempt: int  # 1-based
    ok: bool
    status_code: Optional[int] = None  # present when an HTTP response arrived
    error: Optional[str] = None  # present on transport errors / SSRF block
    duration_ms: int = 0
    delivered_at: datetime = Field(default_factory=utcnow)
