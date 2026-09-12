"""Pushed Authorization Request (PAR) models (RFC 9126, OA-501).

A PAR request stores the authorization parameters a client pushed to
``POST /oauth2/par`` so the later authorize call only carries the
opaque ``request_uri``. Requests are short-lived (TTL, 90s default),
single-use, and bound to the pushing client.
"""

import secrets
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow

#: URN prefix for issued request identifiers (RFC 9126 §2.2).
REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"


class PushedAuthorizationRequest(BaseModel):
    """A stored pushed authorization request (server-side)."""

    request_id: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    client_id: str
    redirect_uri: str
    scope: str = "read"
    response_type: str = "code"
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    nonce: Optional[str] = None
    prompt: Optional[str] = None
    max_age: Optional[int] = None
    claims: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    used: bool = False

    @property
    def request_uri(self) -> str:
        """The full ``request_uri`` URN handed to the client."""
        return f"{REQUEST_URI_PREFIX}{self.request_id}"

    @staticmethod
    def request_id_from_uri(request_uri: str) -> Optional[str]:
        """Extract the opaque id from a ``request_uri`` URN, or ``None``."""
        if not request_uri.startswith(REQUEST_URI_PREFIX):
            return None
        tail = request_uri[len(REQUEST_URI_PREFIX):]
        return tail or None


class PushedAuthorizationResponse(BaseModel):
    """Response for ``POST /oauth2/par`` (RFC 9126 §2.2)."""

    request_uri: str
    expires_in: int
