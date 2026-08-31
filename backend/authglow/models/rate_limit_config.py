"""Admin-managed rate-limit configuration domain model.

The configuration is a single persisted document owned by admins via
the ``/admin/rate-limits`` UI:

* ``enabled`` — global kill-switch for the rate limiter. slowapi
  checks ``Limiter.enabled`` on every request, so flipping it takes
  effect immediately on the node that writes it and on every other
  node within the periodic refresh interval.
* ``overrides`` — per-route limit replacements keyed by route *path*
  (e.g. ``"/api/auth/login"``) with a slowapi limit string as value
  (e.g. ``"5/minute"``). slowapi resolves ``Limit.limit`` (a
  ``limits.RateLimitItem``) at request-evaluation time, so patching
  that attribute changes the effective limit with no restart.
"""

from datetime import datetime
from typing import Dict

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class RateLimitConfig(BaseModel):
    """Admin-managed rate-limit configuration document."""

    enabled: bool = True
    overrides: Dict[str, str] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utcnow)
