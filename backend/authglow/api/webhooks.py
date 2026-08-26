"""Admin CRUD API for Webhook Endpoints (initiative B, fase B1).

Global admin-scoped registry (ADR 0001). The Signing Secret follows the
reveal-once / rotate-immediate lifecycle (ADR 0002): plaintext appears only
in the ``POST`` and rotate responses; every read returns a masked prefix.
"""

import secrets as pysecrets
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from authglow.api.admin import require_admin
from authglow.core.concurrency import named_lock
from authglow.models.user import User
from authglow.models.webhook import WebhookEndpoint
from authglow.models.webhook_events import VALID_EVENT_TYPES, WEBHOOK_TEST
from authglow.repositories.dependencies import (
    get_webhook_delivery_repository,
    get_webhook_repository,
)
from authglow.repositories.protocols import WebhookDeliveryRepository, WebhookRepository
from authglow.services.webhook_dispatcher import WebhookDispatcher

router = APIRouter()

# Process-global named locks (same primitive used by the service layer).
_LOCKS = named_lock()


def get_dispatcher(
    repo: WebhookRepository = Depends(get_webhook_repository),
    delivery_repo: "WebhookDeliveryRepository" = Depends(get_webhook_delivery_repository),
) -> WebhookDispatcher:
    """Build a dispatcher bound to the request-scoped repositories."""
    return WebhookDispatcher(repository=repo, delivery_repository=delivery_repo)


def _new_webhook_id() -> str:
    return "wh_" + pysecrets.token_urlsafe(12)


def _new_signing_secret() -> str:
    return "whsec_" + pysecrets.token_urlsafe(32)


def _mask_secret(secret: str) -> str:
    """Return a recognisable-but-useless preview of the Signing Secret."""
    return f"{secret[:10]}…"


def _validate_registration_url(url: str) -> None:
    """Enforce the URL Policy: HTTPS always, localhost-HTTP only debug/demo.

    Reuses the DCR URI validator so the project has ONE URI validation
    philosophy. Raises ``ValueError`` with a human-readable message.
    """
    # Lazy import: oidc.py is large and pulls JWT machinery.
    from authglow.api.oidc import _validate_redirect_uri

    _validate_redirect_uri(url)


def _validate_events(events: List[str]) -> List[str]:
    """Deduplicate (order-preserving) and validate against the Event Catalog."""
    seen: set = set()
    deduped = [e for e in events if not (e in seen or seen.add(e))]
    if not deduped:
        raise ValueError("At least one event type is required")
    unknown = [e for e in deduped if e not in VALID_EVENT_TYPES]
    if unknown:
        raise ValueError(
            "Unknown event types: " + ", ".join(sorted(set(unknown)))
        )
    return deduped


def _to_response(webhook: WebhookEndpoint, *, include_secret: bool = False,
                 plaintext_secret: Optional[str] = None) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "id": webhook.id,
        "url": webhook.url,
        "events": webhook.events,
        "active": webhook.active,
        "masked_secret": _mask_secret(webhook.secret),
        "created_at": webhook.created_at.isoformat(),
        "updated_at": webhook.updated_at.isoformat(),
    }
    if include_secret and plaintext_secret:
        data["secret"] = plaintext_secret
    return data


class WebhookCreate(BaseModel):
    url: str
    events: List[str]


class WebhookUpdate(BaseModel):
    url: Optional[str] = None
    events: Optional[List[str]] = None
    active: Optional[bool] = None


@router.post("/api/admin/webhooks", status_code=status.HTTP_201_CREATED)
async def create_webhook(
    payload: WebhookCreate,
    request: Request,
    current_user: User = Depends(require_admin),
    repo: WebhookRepository = Depends(get_webhook_repository),
):
    """Register a new webhook endpoint. Returns the Signing Secret ONCE."""
    try:
        _validate_registration_url(payload.url.strip())
        events = _validate_events(payload.events)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    webhook = WebhookEndpoint(
        id=_new_webhook_id(),
        url=payload.url.strip(),
        events=events,
        secret=_new_signing_secret(),
        active=True,
    )

    async with _LOCKS("webhooks"):
        await repo.create(webhook)

    data = _to_response(webhook, include_secret=True, plaintext_secret=webhook.secret)
    return data


@router.get("/api/admin/webhooks")
async def list_webhooks(
    request: Request,
    active_only: bool = False,
    current_user: User = Depends(require_admin),
    repo: WebhookRepository = Depends(get_webhook_repository),
):
    webhooks = await repo.list(active_only=active_only)
    return [_to_response(w) for w in webhooks]


@router.get("/api/admin/webhooks/{webhook_id}")
async def get_webhook(
    webhook_id: str,
    request: Request,
    current_user: User = Depends(require_admin),
    repo: WebhookRepository = Depends(get_webhook_repository),
):
    webhook = await repo.get_by_id(webhook_id)
    if webhook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    return _to_response(webhook)


@router.patch("/api/admin/webhooks/{webhook_id}")
async def update_webhook(
    webhook_id: str,
    payload: WebhookUpdate,
    request: Request,
    current_user: User = Depends(require_admin),
    repo: WebhookRepository = Depends(get_webhook_repository),
):
    updates: Dict[str, Any] = {}
    if payload.url is not None:
        try:
            _validate_registration_url(payload.url.strip())
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
        updates["url"] = payload.url.strip()
    if payload.events is not None:
        try:
            updates["events"] = _validate_events(payload.events)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if payload.active is not None:
        updates["active"] = payload.active

    async with _LOCKS("webhooks"):
        webhook = await repo.update(webhook_id, updates)

    if webhook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    return _to_response(webhook)


@router.delete("/api/admin/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: str,
    request: Request,
    current_user: User = Depends(require_admin),
    repo: WebhookRepository = Depends(get_webhook_repository),
):
    async with _LOCKS("webhooks"):
        deleted = await repo.delete(webhook_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")


@router.post("/api/admin/webhooks/{webhook_id}/rotate-secret")
async def rotate_webhook_secret(
    webhook_id: str,
    request: Request,
    current_user: User = Depends(require_admin),
    repo: WebhookRepository = Depends(get_webhook_repository),
):
    """Replace the Signing Secret immediately (ADR 0002 — no grace period).

    Returns the new secret ONCE; the caller must update its verification
    atomically.
    """
    new_secret = _new_signing_secret()
    async with _LOCKS("webhooks"):
        webhook = await repo.update(webhook_id, {"secret": new_secret})

    if webhook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    return {
        "message": "Signing Secret rotated. Update your endpoint's verification now.",
        "secret": new_secret,
        "masked_secret": _mask_secret(new_secret),
    }


@router.post("/api/admin/webhooks/{webhook_id}/test")
async def test_webhook(
    webhook_id: str,
    request: Request,
    current_user: User = Depends(require_admin),
    repo: WebhookRepository = Depends(get_webhook_repository),
    dispatcher: WebhookDispatcher = Depends(get_dispatcher),
):
    """Send a signed ``webhook.test`` event to this endpoint NOW.

    Runs synchronously (including retries) so the admin sees the delivery
    outcome immediately — the building block of the B4 "Send test event"
    button.
    """
    webhook = await repo.get_by_id(webhook_id)
    if webhook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    summary = await dispatcher.deliver_to_endpoint(webhook, WEBHOOK_TEST)
    return summary


@router.get("/api/admin/webhooks/{webhook_id}/deliveries")
async def list_webhook_deliveries(
    webhook_id: str,
    request: Request,
    limit: int = 20,
    current_user: User = Depends(require_admin),
    repo: WebhookRepository = Depends(get_webhook_repository),
    delivery_repo: "WebhookDeliveryRepository" = Depends(get_webhook_delivery_repository),
):
    """Most recent delivery attempts for the endpoint (newest first)."""
    if await repo.get_by_id(webhook_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
    deliveries = await delivery_repo.list_for_webhook(webhook_id, limit=limit)
    return [d.model_dump(mode="json") for d in deliveries]
