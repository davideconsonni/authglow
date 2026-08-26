"""Signed delivery dispatcher for Webhook Endpoints (initiative B, fase B2).

Responsibilities:

* build the event envelope ``{"id": "evt_…", "type", "created_at", "data"}``
* sign it with the endpoint's Signing Secret — Stripe-style header
  ``X-AuthGlow-Signature: t=<unix_ts>,v1=<hex(HMAC-SHA256(secret, "{t}.{body}"))>``
  so consumers can verify AND reject replays (timestamp inside the signed
  material);
* deliver via the shared outbound httpx client with a per-attempt timeout,
  retrying failed attempts up to :data:`MAX_ATTEMPTS` with the delays in
  :data:`RETRY_DELAYS_SECONDS` (ADR: in-process retries only);
* block SSRF before any network I/O: the URL's host must resolve ONLY to
  globally-routable addresses (loopback / private / link-local are refused
  unconditionally, per grill decision 2026-08-25);
* record EVERY attempt into the capped deliveries log.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import secrets as pysecrets
import socket
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from authglow.core.datetime import utcnow
from authglow.core.http_client import get_http_client
from authglow.models.webhook import WebhookEndpoint
from authglow.models.webhook_delivery import WebhookDelivery
from authglow.repositories.dependencies import (
    get_webhook_delivery_repository,
    get_webhook_repository,
)

SIGNATURE_HEADER = "X-AuthGlow-Signature"
MAX_ATTEMPTS = 3
RETRY_DELAYS_SECONDS: tuple = (1.0, 5.0)
REQUEST_TIMEOUT_SECONDS = 10.0


def emit_webhook_event(event_type: str, data: Dict[str, Any]) -> None:
    """Fire-and-forget emission used by services/routes (initiative B3).

    Never raises and never blocks the caller's business flow: builds a
    dispatcher on the fly and schedules the fan-out as a background task.
    Safe to call from any async context.
    """
    try:
        WebhookDispatcher().fan_out_background(event_type, data)
    except Exception:  # pragma: no cover - defensive
        pass


def sign_payload(secret: str, timestamp: str, body: bytes) -> str:
    """Return the hex HMAC-SHA256 of ``"{timestamp}.{body}"`` under *secret*."""
    mac = hmac.new(
        secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + body, hashlib.sha256
    )
    return mac.hexdigest()


def _build_headers(secret: str, body: bytes) -> Dict[str, str]:
    timestamp = str(int(time.time()))
    signature = sign_payload(secret, timestamp, body)
    return {
        "Content-Type": "application/json",
        SIGNATURE_HEADER: f"t={timestamp},v1={signature}",
    }


def assert_public_url(url: str) -> None:
    """Refuse URLs whose host resolves to a non-globally-routable address.

    Raises ``ValueError`` when the host is an IP literal in a private /
    loopback / link-local / reserved range, or when every DNS record for
    the hostname resolves to one. Called BEFORE any network request.

    NOTE: a *resolution failure* raises ``ValueError`` too, but callers
    MUST treat it as a retryable delivery error (transient DNS hiccups
    happen) rather than a permanent block — see ``deliver_to_endpoint``.
    """
    host = urlparse(url).hostname or ""
    try:
        candidates = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError as exc:
            raise ValueError(f"Cannot resolve webhook host '{host}': {exc}") from exc
        candidates = [ipaddress.ip_address(info[4][0]) for info in infos]

    for ip in candidates:
        if not ip.is_global:
            raise ValueError(
                f"Webhook host '{host}' resolves to a non-public address "
                f"({ip}) — blocked to prevent SSRF"
            )


class WebhookDispatcher:
    """Fan-out + signed delivery engine for the Event Catalog."""

    def __init__(self, repository=None, delivery_repository=None) -> None:
        self._repo = repository
        self._delivery_repo = delivery_repository

    async def _repository(self):
        if self._repo is None:
            self._repo = get_webhook_repository()
        return self._repo

    async def _deliveries(self):
        if self._delivery_repo is None:
            self._delivery_repo = get_webhook_delivery_repository()
        return self._delivery_repo

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    async def fan_out(self, event_type: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Deliver *event_type* to every active subscribed endpoint.

        Runs attempts sequentially per endpoint (endpoints themselves run
        concurrently via tasks created by :meth:`fan_out_background` or by
        awaiting this coroutine directly). Returns a per-endpoint summary.
        """
        repo = await self._repository()
        webhooks = await repo.list(active_only=True)
        targets = [w for w in webhooks if event_type in w.events]
        if not targets:
            return []

        event_id = "evt_" + pysecrets.token_urlsafe(12)
        envelope = {
            "id": event_id,
            "type": event_type,
            "created_at": utcnow().isoformat(),
            "data": data,
        }
        body = json.dumps(envelope).encode("utf-8")

        results = await asyncio.gather(
            *(self.deliver_to_endpoint(w, event_type, body) for w in targets)
        )
        return list(results)

    def fan_out_background(self, event_type: str, data: Dict[str, Any]) -> None:
        """Fire-and-forget variant used by B3 emission hooks.

        Never raises; exceptions are swallowed after logging (a failing
        subscriber must never break the caller's business flow).
        """

        async def _runner():
            try:
                await self.fan_out(event_type, data)
            except Exception:  # pragma: no cover - defensive
                import structlog

                structlog.get_logger("authglow.audit").warning(
                    "webhook_fan_out_failed", event_type=event_type
                )

        asyncio.create_task(_runner())

    async def deliver_to_endpoint(
        self, webhook: WebhookEndpoint, event_type: str, body: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Deliver (with retries) to ONE endpoint and log every attempt.

        When *body* is ``None`` a fresh single-recipient envelope is built
        (used by the admin "send test event" action).
        """
        if body is None:
            envelope = {
                "id": "evt_" + pysecrets.token_urlsafe(12),
                "type": event_type,
                "created_at": utcnow().isoformat(),
                "data": {"source": "admin_test"},
            }
            body = json.dumps(envelope).encode("utf-8")

        headers = _build_headers(webhook.secret, body)
        summary: Dict[str, Any] = {
            "webhook_id": webhook.id,
            "url": webhook.url,
            "event_type": event_type,
            "delivered": False,
            "attempts": [],
        }

        delivery_repo = await self._deliveries()
        for attempt in range(1, MAX_ATTEMPTS + 1):
            start = time.perf_counter()
            status_code: Optional[int] = None
            error: Optional[str] = None
            hard_block = False
            try:
                # SSRF guard per attempt: an IP literal in a private range is
                # a HARD block (no retry); a transient DNS failure is treated
                # like any other delivery error and participates in retries.
                assert_public_url(webhook.url)

                client = await get_http_client()
                resp = await client.post(
                    webhook.url,
                    content=body,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                )
                status_code = resp.status_code
                ok = 200 <= resp.status_code < 300
            except httpx.HTTPError as exc:
                ok = False
                error = f"{type(exc).__name__}: {exc}"
            except ValueError as exc:
                ok = False
                error = str(exc)
                if "non-public address" in error:
                    hard_block = True

            duration_ms = int((time.perf_counter() - start) * 1000)
            summary["attempts"].append(
                {"attempt": attempt, "status_code": status_code, "error": error}
            )
            await delivery_repo.append(
                WebhookDelivery(
                    webhook_id=webhook.id,
                    event_type=event_type,
                    attempt=attempt,
                    ok=ok,
                    status_code=status_code,
                    error=error,
                    duration_ms=duration_ms,
                )
            )
            if ok or hard_block:
                summary["delivered"] = ok
                break
            if attempt < MAX_ATTEMPTS:
                await asyncio.sleep(RETRY_DELAYS_SECONDS[attempt - 1])

        return summary
