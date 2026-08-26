"""File-backed repository tests for Webhook Endpoints (initiative B, B1).

Covers CRUD round-trip, the secret-encryption-at-rest contract (the raw
JSON on disk must never contain the plaintext Signing Secret), list
filtering and delete semantics.
"""

import pytest

from authglow.models.webhook import WebhookEndpoint
from authglow.models.webhook_events import LOGIN_FAILED, USER_CREATED
from authglow.repositories.file.webhook import FileWebhookRepository


def _make(webhook_id: str = "wh_unit000001", **overrides) -> WebhookEndpoint:
    base = dict(
        id=webhook_id,
        url="https://example.com/hook",
        events=[USER_CREATED],
        secret="whsec_plaintextvalue123456",
        active=True,
    )
    base.update(overrides)
    return WebhookEndpoint(**base)


@pytest.fixture
def repo(test_settings):
    return FileWebhookRepository(settings=test_settings)


class TestFileWebhookRepository:
    async def test_create_get_roundtrip(self, repo, test_settings):
        await repo.create(_make())
        got = await repo.get_by_id("wh_unit000001")
        assert got is not None
        assert got.url == "https://example.com/hook"
        assert got.events == [USER_CREATED]
        # Domain layer sees the plaintext secret.
        assert got.secret == "whsec_plaintextvalue123456"
        assert got.created_at is not None and got.updated_at is not None

    async def test_secret_is_encrypted_at_rest(self, repo, test_settings):
        await repo.create(_make())
        raw_path = f"{test_settings.storage_path}/webhooks/wh_unit000001.json"
        with open(raw_path, encoding="utf-8") as fh:
            raw = fh.read()
        assert "whsec_plaintextvalue123456" not in raw

    async def test_get_missing_returns_none(self, repo):
        assert await repo.get_by_id("wh_missing00001") is None

    async def test_update_applies_fields_and_refreshes_updated_at(self, repo):
        await repo.create(_make())
        before = (await repo.get_by_id("wh_unit000001")).updated_at

        updated = await repo.update(
            "wh_unit000001",
            {"active": False, "events": [USER_CREATED, LOGIN_FAILED]},
        )
        assert updated.active is False
        assert set(updated.events) == {USER_CREATED, LOGIN_FAILED}
        assert updated.updated_at >= before

    async def test_update_missing_returns_none(self, repo):
        assert await repo.update("wh_missing00001", {"active": False}) is None

    async def test_list_and_active_only_filter(self, repo):
        await repo.create(_make("wh_list000001"))
        await repo.create(_make("wh_list000002", active=False))
        await repo.create(_make("wh_list000003"))

        all_webhooks = await repo.list()
        assert [w.id for w in all_webhooks] == [
            "wh_list000001",
            "wh_list000002",
            "wh_list000003",
        ]
        active = await repo.list(active_only=True)
        assert [w.id for w in active] == ["wh_list000001", "wh_list000003"]

    async def test_delete_returns_true_then_false(self, repo):
        await repo.create(_make())
        assert await repo.delete("wh_unit000001") is True
        assert await repo.delete("wh_unit000001") is False
        assert await repo.get_by_id("wh_unit000001") is None
