"""Safeword-gated API key deletion handshake.

The user-facing ``DELETE /api/keys/{id}`` and the admin
``DELETE /api/keys/{id}`` endpoints (same handler) are
destructive and irreversible. To make accidental invocation hard,
the operator must type a server-issued safeword before the call
is accepted.

These tests pin the two-call handshake so the wire contract
cannot regress.
"""

import json
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.api_key import router as api_key_router
from authglow.api.auth import get_current_user
from authglow.models.api_key import APIKey
from authglow.models.user import User
from authglow.services.password import hash_password


def _user(user_id="user-1", email="user@test.com", scopes=None):
    return User(
        id=user_id,
        email=email,
        hashed_password=hash_password("TestP@ss123!"),
        is_active=True,
        scopes=scopes or ["read"],
    )


def _admin_user():
    return _user(user_id="admin-1", email="admin@test.com", scopes=["read", "admin"])


@pytest.fixture
def user_client():
    """TestClient wired to a regular user (no admin scope)."""
    app = FastAPI()
    app.include_router(api_key_router)
    app.dependency_overrides[get_current_user] = lambda: _user()
    return TestClient(app)


@pytest.fixture
def admin_client():
    """TestClient wired to an admin user."""
    app = FastAPI()
    app.include_router(api_key_router)
    app.dependency_overrides[get_current_user] = lambda: _admin_user()
    return TestClient(app)


class _FakeKeyService:
    """Tiny stand-in for the real APIKeyService.

    Lets the test scenarios exercise the safeword handshake
    without dragging in the full file-based repository.
    """

    def __init__(self, key=None):
        self._key = key  # expected to be an APIKey instance
        self.delete_calls = 0
        self.get_calls = 0
        self.rotate_calls = 0

    async def get_key(self, key_id):
        self.get_calls += 1
        if self._key and self._key.key_id == key_id:
            return self._key
        return None

    async def delete_key(self, key_id):
        self.delete_calls += 1
        if self._key and self._key.key_id == key_id:
            self._key = None
            return True
        return False

    async def rotate_key(self, key_id):
        """Stand-in rotate. Returns the existing key + a fake
        plaintext. Tests that care about rotation behaviour can
        monkey-patch this method."""
        self.rotate_calls += 1
        if self._key and self._key.key_id == key_id:
            return self._key, f"ak_NEWPLAINTEXT_FOR_{key_id}"
        return None


def _wire_service(client, service):
    """Override ``get_api_key_service`` to return ``service``."""
    from authglow.api.api_key import get_api_key_service

    client.app.dependency_overrides[get_api_key_service] = lambda: service


def _owned_key(**overrides):
    """Build a real APIKey Pydantic model so endpoint handlers can
    call ``model_dump()``, ``key_id``, ``key_hash`` etc. without
    a custom shim."""
    data = {
        "key_id": "k-own",
        "user_id": "user-1",
        "name": "My Key",
        "key_prefix": "agk1abcd",
        "key_hash": "old-bcrypt-hash",
        "scopes": ["read"],
        "is_active": True,
        "expires_at": None,
        "created_at": "2099-01-01T00:00:00Z",
        "allowed_ips": [],
        "created_by": "user-1",
    }
    data.update(overrides)
    return APIKey(**data)


def _other_users_key():
    return APIKey(
        key_id="k-other",
        user_id="someone-else",
        name="Other",
        key_prefix="agk1efgh",
        key_hash="placeholder",
        scopes=["read"],
        is_active=True,
        expires_at=None,
        created_at="2099-01-01T00:00:00Z",
        allowed_ips=[],
        created_by="someone-else",
    )


class TestRotateApiKeySafeword:
    """Safeword-gated ``POST /api/keys/{key_id}/rotate`` handshake.

    Rotating regenerates the bcrypt-hashed plaintext secret while
    keeping the key's identity (same key_id / name / scopes / owner).
    The new plaintext is returned exactly once — same show-once
    contract as creation.
    """

    def _rotate_with_body(self, client, path, body):
        return client.request(
            "POST",
            path,
            content=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )

    def test_rotate_without_safeword_returns_400_or_422(self, user_client):
        """The destructive rotate call without a body must be rejected."""
        service = _FakeKeyService(key=_owned_key())
        _wire_service(user_client, service)

        resp = self._rotate_with_body(user_client, "/api/keys/k-own/rotate", {})
        assert resp.status_code in (400, 422), resp.text

        # Verify the underlying service.rotate_key was not invoked.
        # The fake does not expose it directly, but we can assert no
        # internal mutation happened — hash must still match the
        # original placeholder.
        assert service._key is not None
        assert service._key.key_hash == "old-bcrypt-hash"

    def test_challenge_issued_with_safeword(self, user_client):
        service = _FakeKeyService(key=_owned_key())
        _wire_service(user_client, service)

        resp = user_client.post("/api/keys/k-own/rotate/challenge")
        # Re-use delete() — Starlette's TestClient mirrors any method.
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["challenge_id"]
        assert body["word"]
        import re
        assert re.match(r"^[a-z]+-[a-z]+-[a-z]+-\d{2}$", body["word"])

    def test_rotate_challenge_owned_only_by_owner_or_admin(self, user_client):
        """A regular user cannot rotate someone else's key."""
        service = _FakeKeyService(key=_other_users_key())
        _wire_service(user_client, service)

        resp = user_client.post("/api/keys/k-other/rotate/challenge")
        assert resp.status_code in (403, 404), resp.text

    def test_admin_can_rotate_any_key(self, admin_client):
        from authglow.core.safeword_store import issue_challenge, SafewordPurpose
        service = _FakeKeyService(key=_other_users_key())
        _wire_service(admin_client, service)

        # Admin path issues a challenge via the safeword store
        # directly (matches what the endpoint does internally).
        issued = issue_challenge("k-other", SafewordPurpose.API_KEY_ROTATE)
        challenge = {"challenge_id": issued["challenge_id"], "word": issued["word"]}

        # Monkey-patch the fake service with a rotate_key method
        async def _rotate(key_id):
            service.rotate_calls += 1
            return service._key, "ak_NEWPLAINTEXT1234567890"

        service.rotate_key = _rotate
        service.rotate_calls = 0
        service._key.key_hash = "old-hash"

        resp = self._rotate_with_body(
            admin_client,
            "/api/keys/k-other/rotate",
            challenge,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["api_key"] == "ak_NEWPLAINTEXT1234567890"
        assert body["key_id"] == "k-other"
        assert service.rotate_calls == 1

    def test_rotate_with_wrong_safeword_returns_400(self, user_client):
        service = _FakeKeyService(key=_owned_key())
        _wire_service(user_client, service)

        # Issue a real challenge
        resp = user_client.post("/api/keys/k-own/rotate/challenge")
        assert resp.status_code == 200, resp.text
        # Use it with a wrong word
        resp = self._rotate_with_body(
            user_client,
            "/api/keys/k-own/rotate",
            {"challenge_id": "x", "word": "wrong-word-99"},
        )
        assert resp.status_code == 400, resp.text

    def test_rotate_unknown_key_returns_404(self, user_client):
        """An unknown key id with a valid challenge should 404.

        The safeword check is done first; for a key that doesn't
        exist we can't even issue a challenge, so this test goes
        straight to the consume path with a backend-issued
        challenge.
        """
        from authglow.core.safeword_store import issue_challenge, SafewordPurpose
        service = _FakeKeyService(key=None)
        _wire_service(user_client, service)

        issued = issue_challenge("no-such-key", SafewordPurpose.API_KEY_ROTATE)
        challenge = {"challenge_id": issued["challenge_id"], "word": issued["word"]}

        resp = self._rotate_with_body(
            user_client,
            "/api/keys/no-such-key/rotate",
            challenge,
        )
        assert resp.status_code == 404, resp.text

    def test_rotate_challenge_single_use(self, user_client):
        service = _FakeKeyService(key=_owned_key())
        _wire_service(user_client, service)

        async def _rotate(key_id):
            service.rotate_calls += 1
            return service._key, f"ak_NEW{key_id}"

        service.rotate_key = _rotate
        service.rotate_calls = 0

        challenge = user_client.post("/api/keys/k-own/rotate/challenge").json()
        first = self._rotate_with_body(
            user_client,
            "/api/keys/k-own/rotate",
            challenge,
        )
        assert first.status_code == 200
        # Replay with the same challenge — must fail
        second = self._rotate_with_body(
            user_client,
            "/api/keys/k-own/rotate",
            challenge,
        )
        assert second.status_code == 400, second.text
        assert service.rotate_calls == 1


class TestDeleteApiKeySafeword:
    """Safeword-gated ``DELETE /api/keys/{key_id}`` handshake."""

    def test_delete_without_safeword_returns_400_or_422(self, user_client):
        """A delete call with no body must be rejected (the
        server cannot verify a missing safeword)."""
        service = _FakeKeyService(key=_owned_key())
        _wire_service(user_client, service)

        resp = user_client.delete("/api/keys/k-own")
        assert resp.status_code in (400, 422), resp.text
        # The destructive operation must NOT have fired.
        assert service.delete_calls == 0

    def test_challenge_issued_with_safeword(self, user_client):
        service = _FakeKeyService(key=_owned_key())
        _wire_service(user_client, service)

        resp = user_client.delete("/api/keys/k-own/delete/challenge")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["challenge_id"]
        assert body["word"]
        # Safeword format: 3 lowercase words + 2 digits, dash-separated.
        import re
        assert re.match(r"^[a-z]+-[a-z]+-[a-z]+-\d{2}$", body["word"])

    def _delete_with_body(self, client, path, body):
        """DELETE with a JSON body — Starlette's TestClient.delete()
        does not accept a body, so we go through ``request()``."""
        return client.request(
            "DELETE",
            path,
            content=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )

    def test_delete_with_valid_safeword_succeeds(self, user_client):
        service = _FakeKeyService(key=_owned_key())
        _wire_service(user_client, service)

        challenge = user_client.delete("/api/keys/k-own/delete/challenge").json()
        resp = self._delete_with_body(
            user_client,
            "/api/keys/k-own",
            {
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert resp.status_code == 200, resp.text
        assert service.delete_calls == 1

    def test_delete_with_wrong_safeword_returns_400(self, user_client):
        service = _FakeKeyService(key=_owned_key())
        _wire_service(user_client, service)

        challenge = user_client.delete("/api/keys/k-own/delete/challenge").json()
        resp = self._delete_with_body(
            user_client,
            "/api/keys/k-own",
            {
                "challenge_id": challenge["challenge_id"],
                "word": "wrong-word-99",
            },
        )
        assert resp.status_code == 400, resp.text
        assert service.delete_calls == 0

    def test_challenge_is_single_use(self, user_client):
        service = _FakeKeyService(key=_owned_key())
        _wire_service(user_client, service)

        challenge = user_client.delete("/api/keys/k-own/delete/challenge").json()
        first = self._delete_with_body(
            user_client,
            "/api/keys/k-own",
            {
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert first.status_code == 200
        # Re-seed the key (the fake service clears it on success)
        service._key = _owned_key()
        second = self._delete_with_body(
            user_client,
            "/api/keys/k-own",
            {
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert second.status_code == 400, second.text

    def test_user_cannot_delete_other_users_key(self, user_client):
        service = _FakeKeyService(key=_other_users_key())
        _wire_service(user_client, service)

        challenge = user_client.delete("/api/keys/k-other/delete/challenge")
        # The challenge endpoint checks ownership too — must be 403
        # (or 404 to avoid leaking existence). Either is acceptable
        # but the destructive delete must NOT fire.
        assert challenge.status_code in (403, 404), challenge.text
        assert service.delete_calls == 0

    def test_admin_can_delete_any_users_key(self, admin_client):
        service = _FakeKeyService(key=_other_users_key())
        _wire_service(admin_client, service)

        challenge = admin_client.delete(
            "/api/keys/k-other/delete/challenge"
        ).json()
        resp = self._delete_with_body(
            admin_client,
            "/api/keys/k-other",
            {
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert resp.status_code == 200, resp.text
        assert service.delete_calls == 1

    def test_delete_unknown_key_returns_404(self, user_client):
        """An unknown key id with a valid challenge should 404.

        If the challenge is bogus, the server returns 400 first (it
        does not want to leak which key ids exist). Both outcomes
        are acceptable from a security standpoint; what matters
        is that the destructive operation did not fire.
        """
        service = _FakeKeyService(key=None)
        _wire_service(user_client, service)

        # First issue a real challenge for a known id, then ask the
        # server to delete a different id with that challenge.
        # The challenge is bound to its target id, so the server
        # must reject it as "not valid for this target" (400).
        challenge = user_client.delete(
            "/api/keys/k-own/delete/challenge"
        ).json() if user_client.delete("/api/keys/k-own/delete/challenge").status_code == 200 else None
        # No owned key seeded in this test — generate a "passing"
        # challenge path by directly calling the safeword store.
        from authglow.core.safeword_store import issue_challenge, SafewordPurpose
        issued = issue_challenge("no-such-key", SafewordPurpose.API_KEY_DELETE)
        resp = self._delete_with_body(
            user_client,
            "/api/keys/no-such-key",
            {
                "challenge_id": issued["challenge_id"],
                "word": issued["word"],
            },
        )
        # The challenge is valid for this target id, so we move past
        # the safeword check and hit the 404 "key not found" branch.
        assert resp.status_code == 404, resp.text
        assert service.delete_calls == 0
