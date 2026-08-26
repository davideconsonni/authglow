"""File-system-backed repository for Webhook Endpoints (initiative B).

On-disk layout (relative to ``settings.storage_path`` — an fsspec path, so
the same code serves the ``file``, ``s3``, ``gcs`` and ``abfs`` backends):

* ``<storage>/webhooks/<webhook_id>.json`` - one document per endpoint.

The Signing Secret is encrypted at rest with the same AES-GCM field
encryption used for User PII (``encrypt_field``/``decrypt_field``): the
domain model carries it in plaintext, this repository encrypts before
write and decrypts after read. Cross-process safety is delegated to the
``named_lock("webhooks")`` held by the API layer.
"""

from typing import Any, Dict, List, Optional

from authglow.core.crypto import decrypt_field, encrypt_field
from authglow.models.webhook import WebhookEndpoint
from authglow.models.webhook_delivery import WebhookDelivery
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import WebhookDeliveryRepository, WebhookRepository

_SECRET_FIELDS = ("secret",)
MAX_DELIVERIES_PER_ENDPOINT = 50


class FileWebhookRepository(BaseFileRepository, WebhookRepository):
    """File-backed implementation of :class:`WebhookRepository`.

    Stores each endpoint as a JSON document at
    ``<storage>/webhooks/<webhook_id>.json``.
    """

    _subdir = "webhooks"

    # ------------------------------------------------------------------
    # Encryption helpers (Signing Secret at rest)
    # ------------------------------------------------------------------

    @staticmethod
    def _encrypt_webhook(webhook: WebhookEndpoint) -> Dict[str, Any]:
        data = webhook.model_dump(mode="json")
        for field in _SECRET_FIELDS:
            if data.get(field):
                data[field] = encrypt_field(data[field])
        return data

    def _webhook_path(self, webhook_id: str) -> str:
        """Return the fsspec path for a webhook document."""
        return self._path(f"{webhook_id}.json")

    async def _deliveries_doc_path(self, webhook_id: str) -> str:
        """Path of the deliveries document owned by *webhook_id*."""
        return self._path(f"{webhook_id}/deliveries.json")

    async def _read_webhook(self, webhook_id: str) -> Optional[WebhookEndpoint]:
        """Read and decrypt one webhook. ``None`` on missing/corrupt file."""
        data = await self._read_json(self._webhook_path(webhook_id))
        if not isinstance(data, dict):
            return None
        try:
            for field in _SECRET_FIELDS:
                if data.get(field):
                    data[field] = decrypt_field(data[field])
            return WebhookEndpoint(**data)
        except Exception:
            return None

    async def _read_all(self) -> List[WebhookEndpoint]:
        pattern = self._path("*.json")
        files = await self._glob(pattern)
        webhooks: List[WebhookEndpoint] = []
        for path in files:
            data = await self._read_json(path)
            if not isinstance(data, dict):
                continue
            try:
                for field in _SECRET_FIELDS:
                    if data.get(field):
                        data[field] = decrypt_field(data[field])
                webhooks.append(WebhookEndpoint(**data))
            except Exception:
                continue
        return webhooks

    # ------------------------------------------------------------------
    # Protocol: create
    # ------------------------------------------------------------------

    async def create(self, webhook: WebhookEndpoint) -> None:
        """Persist a new webhook endpoint.

        Sets ``created_at`` / ``updated_at`` to now as a side effect
        (matches the federation repository convention).
        """
        from authglow.core.datetime import utcnow

        webhook.created_at = utcnow()
        webhook.updated_at = utcnow()
        await self._ensure_parent(self._webhook_path(webhook.id))
        await self._write_json(self._webhook_path(webhook.id), self._encrypt_webhook(webhook))

    # ------------------------------------------------------------------
    # Protocol: read
    # ------------------------------------------------------------------

    async def get_by_id(self, webhook_id: str) -> Optional[WebhookEndpoint]:
        """Return the endpoint, or ``None`` if missing/corrupt."""
        return await self._read_webhook(webhook_id)

    async def list(self, active_only: bool = False) -> List[WebhookEndpoint]:
        """Return every endpoint, optionally filtered by ``active``."""
        webhooks = await self._read_all()
        if active_only:
            webhooks = [w for w in webhooks if w.active]
        return sorted(webhooks, key=lambda w: w.created_at)

    # ------------------------------------------------------------------
    # Protocol: update
    # ------------------------------------------------------------------

    async def update(
        self, webhook_id: str, updates: Dict[str, Any]
    ) -> Optional[WebhookEndpoint]:
        """Apply the given non-``None`` field updates and persist.

        Returns the updated webhook, or ``None`` if it was missing.
        ``updated_at`` is refreshed on success.
        """
        from authglow.core.datetime import utcnow

        webhook = await self._read_webhook(webhook_id)
        if webhook is None:
            return None

        for key, value in updates.items():
            if value is not None:
                setattr(webhook, key, value)
        webhook.updated_at = utcnow()

        await self._write_json(
            self._webhook_path(webhook_id), self._encrypt_webhook(webhook)
        )
        return webhook

    # ------------------------------------------------------------------
    # Protocol: delete
    # ------------------------------------------------------------------

    async def delete(self, webhook_id: str) -> bool:
        """Remove the endpoint AND its capped deliveries log (cascade)."""
        deleted = await self._delete(self._webhook_path(webhook_id))
        # Best-effort cascade: the deliveries document lives in a
        # sub-directory named after the endpoint.
        await self._delete(await self._deliveries_doc_path(webhook_id))
        return deleted


# ---------------------------------------------------------------------------
# Delivery attempt log (append-only, capped per endpoint)
# ---------------------------------------------------------------------------


class FileWebhookDeliveryRepository(BaseFileRepository, WebhookDeliveryRepository):
    """File-backed implementation of :class:`WebhookDeliveryRepository`.

    One document per endpoint at ``<storage>/webhooks/<id>/deliveries.json``
    holding a newest-first array, trimmed to
    :data:`MAX_DELIVERIES_PER_ENDPOINT` entries on every append.
    """

    _subdir = "webhooks"

    async def _deliveries_path(self, webhook_id: str) -> str:
        return self._path(f"{webhook_id}/deliveries.json")

    async def append(self, delivery: WebhookDelivery) -> None:
        path = await self._deliveries_path(delivery.webhook_id)
        await self._ensure_parent(path)
        doc: Dict[str, Any] = {"deliveries": []}
        raw = await self._read_json(path)
        if isinstance(raw, dict) and isinstance(raw.get("deliveries"), list):
            doc["deliveries"] = raw["deliveries"]
        doc["deliveries"].insert(0, delivery.model_dump(mode="json"))
        doc["deliveries"] = doc["deliveries"][:MAX_DELIVERIES_PER_ENDPOINT]
        await self._write_json(path, doc)

    async def list_for_webhook(
        self, webhook_id: str, limit: int = 20
    ) -> List[WebhookDelivery]:
        path = await self._deliveries_path(webhook_id)
        raw = await self._read_json(path)
        if not isinstance(raw, dict) or not isinstance(raw.get("deliveries"), list):
            return []
        out: List[WebhookDelivery] = []
        for item in raw["deliveries"][:limit]:
            try:
                out.append(WebhookDelivery(**item))
            except Exception:
                continue
        return out
