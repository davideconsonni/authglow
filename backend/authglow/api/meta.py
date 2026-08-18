"""Public metadata endpoint.

Exposes lightweight, non-sensitive server metadata without requiring
authentication so the SPA can render environment-aware UI before a user
signs in (e.g. the demo-mode warning banner and demo credentials).

Security note: the demo user password is returned ONLY when
``Settings.demo_mode`` is true. That is deliberate — a public demo must
let anonymous visitors log in — and the credential is rotated on every
boot (see ``authglow.services.demo``). With ``demo_mode=false`` this
endpoint returns no credential material at all.
"""

from fastapi import APIRouter, Request

from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter

router = APIRouter(tags=["Meta"])


@router.get("/api/meta")
@limiter.limit("20/minute")
async def get_meta(request: Request):
    """Return public environment metadata.

    When ``demo_mode`` is enabled the response includes the demo admin
    credentials so anonymous visitors can log in to the sandbox. When
    disabled only ``{"demo_mode": false}`` is returned.
    """
    settings = get_settings()

    if not settings.demo_mode:
        return {"demo_mode": False}

    # The boot-time password lives on ``app.state`` (set by the lifespan
    # in ``main.py``); it is never persisted or logged.
    demo_password = getattr(request.app.state, "demo_password", None)
    return {
        "demo_mode": True,
        "demo_banner_text": settings.demo_banner_text,
        "demo_user_email": settings.demo_user_email,
        "demo_user_password": demo_password or "",
    }
