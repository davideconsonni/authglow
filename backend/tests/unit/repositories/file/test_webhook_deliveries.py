"""File-backed repository tests for the webhook deliveries log (B2)."""

import pytest

from authglow.models.webhook_delivery import WebhookDelivery
from authglow.models.webhook_events import USER_CREATED
from authglow.repositories.file.webhook import (
    MAX_DELIVERIES_PER_ENDPOINT,
    FileWebhookDeliveryRepository,
)


@pytest.fixture
def repo(test_settings):
    return FileWebhookDeliveryRepository(settings=test_settings)


def _delivery(webhook_id: str = "wh_dlv0000001", n: int = 0, ok: bool = True):
    return WebhookDelivery(
        webhook_id=webhook_id,
        event_type=USER_CREATED,
        attempt=1,
        ok=ok,
        status_code=200 if ok else None,
        error=None if ok else "boom",
    )


class TestFileWebhookDeliveryRepository:
    async def test_append_and_list_newest_first(self, repo):
        for i in range(3):
            d = _delivery(n=i)
            d.id = f"dlv_{i:012d}"
            await repo.append(d)

        got = await repo.list_for_webhook("wh_dlv0000001")
        assert [g.id for g in got] == ["dlv_000000000002", "dlv_000000000001", "dlv_000000000000"]

    async def test_limit_slices(self, repo):
        for i in range(5):
            d = _delivery()
            d.id = f"dlv_{i:012d}"
            await repo.append(d)
        got = await repo.list_for_webhook("wh_dlv0000001", limit=2)
        assert len(got) == 2

    async def test_empty_returns_list(self, repo):
        assert await repo.list_for_webhook("wh_nope0000001") == []

    async def test_cap_trims_to_max(self, repo, test_settings):
        for i in range(MAX_DELIVERIES_PER_ENDPOINT + 10):
            d = _delivery()
            d.id = f"dlv_{i:012d}"
            await repo.append(d)

        got = await repo.list_for_webhook("wh_dlv0000001", limit=MAX_DELIVERIES_PER_ENDPOINT + 10)
        assert len(got) == MAX_DELIVERIES_PER_ENDPOINT
        # newest-first: the first appended ones were trimmed away
        assert got[0].id == f"dlv_{MAX_DELIVERIES_PER_ENDPOINT + 9:012d}"
