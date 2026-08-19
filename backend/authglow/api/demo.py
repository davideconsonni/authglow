"""Public demo-mode endpoints.

Exposes demo-only affordances for the public sandbox. The only current
endpoint is the demo inbox (``GET /api/demo/inbox``): it lets anonymous
visitors read the emails the server "sent" to their address — verification
codes, password reset codes, welcome emails — when no real mail provider is
configured (``EMAIL_BACKEND`` falls back to ``console``).

Security note: like ``GET /api/meta``, this endpoint is public and
rate-limited by design. A demo instance is a throwaway sandbox whose data
is wiped on every restart; exposing codes to "anyone who knows the email
address" is acceptable there — the same exposure already applies to the
boot-time demo password. With ``demo_mode=false`` every route returns
``404`` so production instances are never affected.
"""

from typing import List

from fastapi import APIRouter, HTTPException, Request, status

from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.services.email.demo_mailbox import CapturedEmail, get_demo_mailbox

router = APIRouter(tags=["Demo"])


@router.get("/api/demo/inbox")
@limiter.limit("30/minute")
async def demo_inbox(request: Request, email: str) -> dict:
    """Return the demo mailbox for a recipient address.

    Only active when ``Settings.demo_mode`` is true; otherwise ``404``.
    Emails are returned newest first, with the rendered ``body_text``
    containing any verification / reset codes.
    """
    settings = get_settings()
    if not settings.demo_mode:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
        )

    emails: List[CapturedEmail] = get_demo_mailbox().list_for(email)
    return {"emails": emails}
