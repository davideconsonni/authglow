"""Integration tests for the OAuth2 client admin API.

Regression tests for the ``POST /api/oauth-clients`` happy
path on every ``token_endpoint_auth_method`` — the previous
regression (duplicate ``client_secret_jwt_key`` keyword) was
only caught by running the server manually. These tests
exercise the create endpoint via ``TestClient`` for every
auth method so the response assembly is always validated.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.oauth_client import require_admin, router
from authglow.models.user import User
from authglow.services.password import hash_password


def _admin() -> User:
    return User(
        id="admin-1",
        email="admin@test.com",
        hashed_password=hash_password("TestP@ss123!"),
        is_active=True,
        scopes=["admin"],
    )


@pytest.fixture
def admin_client(test_settings) -> TestClient:
    """``TestClient`` with ``require_admin`` bypassed."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_admin] = _admin
    return TestClient(app)


class TestCreateOAuthClient:
    def test_create_client_secret_basic(self, admin_client, test_settings):
        resp = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "Basic Client",
                "redirect_uris": ["https://example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": True,
                "token_endpoint_auth_method": "client_secret_basic",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert "client_id" in body
        assert "client_secret" in body
        # No JWT key for this method
        assert body.get("client_secret_jwt_key") is None

    def test_create_client_secret_jwt(self, admin_client, test_settings):
        """Regression: ``OAuth2ClientWithSecret`` was being
        constructed with two values for
        ``client_secret_jwt_key`` (once from the model_dump,
        once from the explicit kwarg). The fix excludes
        ``client_secret_jwt_key`` from the dump and only
        passes the PLAINTEXT key to the response."""
        resp = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "JWT Secret Client",
                "redirect_uris": ["https://example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": True,
                "token_endpoint_auth_method": "client_secret_jwt",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert "client_id" in body
        assert "client_secret" in body
        # The plaintext JWT key is returned once
        assert body.get("client_secret_jwt_key")
        # The response must not contain the ENCRYPTED server-side
        # copy (it would leak the storage envelope).
        # (No direct way to assert this from the wire — the dump
        # excluded the field. We rely on the absence of
        # an "agcj1:" prefix in the value, which is the
        # encryption envelope.)
        jwt_key = body["client_secret_jwt_key"]
        assert not jwt_key.startswith("agcj1:")

    def test_create_private_key_jwt(self, admin_client, test_settings):
        resp = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "PKJ Client",
                "redirect_uris": ["https://example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": True,
                "token_endpoint_auth_method": "private_key_jwt",
                "public_jwk": {
                    "kty": "RSA",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z",
                    "e": "AQAB",
                },
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert "client_id" in body
        # No JWT key for PKJ — the client owns its key
        assert body.get("client_secret_jwt_key") is None
        # The public_jwk round-trips in the response
        assert body["public_jwk"]["kty"] == "RSA"

    def test_create_none(self, admin_client, test_settings):
        """Public client, no secret — for SPA / mobile flows."""
        resp = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "Public SPA",
                "redirect_uris": ["https://app.example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": False,
                "token_endpoint_auth_method": "none",
            },
        )
        assert resp.status_code == 201, resp.text


class TestRotateSecret:
    """End-to-end tests for the safeword-gated rotate-secret flow.

    The destructive admin action is split into a two-call handshake:

      1. POST /api/oauth-clients/{id}/rotate-secret/challenge
         -> { challenge_id, word, expires_at }
      2. POST /api/oauth-clients/{id}/rotate-secret
         body:   { challenge_id, word }
         -> 200 + new secret, OR 400 on any mismatch

    These tests pin the handshake contract so a frontend or backend
    change cannot silently bypass the confirmation step.
    """

    @pytest.fixture
    def seeded_client(self, admin_client, test_settings):
        """Create one client and return its plaintext secret + id."""
        create = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "Rotate Me",
                "redirect_uris": ["https://example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": True,
                "token_endpoint_auth_method": "client_secret_basic",
            },
        )
        assert create.status_code == 201, create.text
        body = create.json()
        return {
            "client_id": body["client_id"],
            "old_secret": body["client_secret"],
        }

    def _issue_challenge(self, admin_client, client_id):
        resp = admin_client.post(
            f"/api/oauth-clients/{client_id}/rotate-secret/challenge"
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    # ------------------------------------------------------------------
    # Challenge issuance
    # ------------------------------------------------------------------

    def test_challenge_returns_word_and_id(self, admin_client, seeded_client):
        body = self._issue_challenge(admin_client, seeded_client["client_id"])
        assert "challenge_id" in body and body["challenge_id"]
        assert "word" in body and body["word"]
        assert "expires_at" in body
        # The word must follow the safeword format
        # (3 lowercase words from the EFF list + 2 digits, dash-separated).
        import re
        assert re.match(r"^[a-z]+-[a-z]+-[a-z]+-\d{2}$", body["word"]), (
            f"Safeword {body['word']!r} does not match the expected format"
        )

    def test_challenge_for_unknown_client_returns_404(self, admin_client):
        resp = admin_client.post(
            "/api/oauth-clients/no-such-client/rotate-secret/challenge"
        )
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # Rotate handshake — happy path
    # ------------------------------------------------------------------

    def test_rotate_with_valid_challenge_returns_new_secret(
        self, admin_client, seeded_client
    ):
        challenge = self._issue_challenge(
            admin_client, seeded_client["client_id"]
        )
        resp = admin_client.post(
            f"/api/oauth-clients/{seeded_client['client_id']}/rotate-secret",
            json={
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "new_client_secret" in body
        assert body["new_client_secret"] != seeded_client["old_secret"], (
            "Rotated secret must differ from the previous one"
        )
        # Legacy field must not appear.
        assert "secret" not in body

    # ------------------------------------------------------------------
    # Rotate handshake — rejection paths
    # ------------------------------------------------------------------

    def test_rotate_without_challenge_returns_400(
        self, admin_client, seeded_client
    ):
        # Body missing -> FastAPI returns 422 from the model
        # validation; we accept either 400 (no body parsing yet) or
        # 422 (validation error). Anything else is a regression.
        resp = admin_client.post(
            f"/api/oauth-clients/{seeded_client['client_id']}/rotate-secret"
        )
        assert resp.status_code in (400, 422), resp.text

    def test_rotate_with_unknown_challenge_returns_400(
        self, admin_client, seeded_client
    ):
        resp = admin_client.post(
            f"/api/oauth-clients/{seeded_client['client_id']}/rotate-secret",
            json={"challenge_id": "nope", "word": "anything-else-00"},
        )
        assert resp.status_code == 400, resp.text
        assert "Invalid" in resp.json()["detail"] or "expired" in resp.json()["detail"]

    def test_rotate_with_wrong_word_returns_400(
        self, admin_client, seeded_client
    ):
        challenge = self._issue_challenge(
            admin_client, seeded_client["client_id"]
        )
        resp = admin_client.post(
            f"/api/oauth-clients/{seeded_client['client_id']}/rotate-secret",
            json={"challenge_id": challenge["challenge_id"], "word": "wrong-word-99"},
        )
        assert resp.status_code == 400, resp.text
        assert "Safeword" in resp.json()["detail"]

    def test_challenge_is_single_use(
        self, admin_client, seeded_client
    ):
        challenge = self._issue_challenge(
            admin_client, seeded_client["client_id"]
        )
        # First consume — success
        first = admin_client.post(
            f"/api/oauth-clients/{seeded_client['client_id']}/rotate-secret",
            json={
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert first.status_code == 200, first.text
        # Second consume with the same challenge id — must fail
        second = admin_client.post(
            f"/api/oauth-clients/{seeded_client['client_id']}/rotate-secret",
            json={
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert second.status_code == 400, second.text

    def test_wrong_word_invalidates_challenge(
        self, admin_client, seeded_client
    ):
        challenge = self._issue_challenge(
            admin_client, seeded_client["client_id"]
        )
        # First attempt with wrong word -> 400
        bad = admin_client.post(
            f"/api/oauth-clients/{seeded_client['client_id']}/rotate-secret",
            json={
                "challenge_id": challenge["challenge_id"],
                "word": "wrong-word-99",
            },
        )
        assert bad.status_code == 400
        # Even with the correct word, the challenge is now invalidated
        good = admin_client.post(
            f"/api/oauth-clients/{seeded_client['client_id']}/rotate-secret",
            json={
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert good.status_code == 400, good.text

    def test_challenge_expires_after_60_seconds(
        self, admin_client, seeded_client, monkeypatch
    ):
        challenge = self._issue_challenge(
            admin_client, seeded_client["client_id"]
        )

        from datetime import timedelta
        from authglow.core import safeword_store
        from authglow.core import datetime as datetime_mod

        future = datetime_mod.utcnow() + timedelta(seconds=61)

        def _future_now():
            return future

        # Patch the utcnow binding inside the shared safeword
        # store module — that's the one used by both the store
        # helper and the route handlers.
        monkeypatch.setattr(safeword_store, "utcnow", _future_now)
        monkeypatch.setattr("authglow.core.datetime.utcnow", _future_now)

        resp = admin_client.post(
            f"/api/oauth-clients/{seeded_client['client_id']}/rotate-secret",
            json={
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert resp.status_code == 400, resp.text
        assert "expired" in resp.json()["detail"].lower()

    def test_challenge_bound_to_specific_client(
        self, admin_client, seeded_client
    ):
        # Create a second client
        second = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "Other Client",
                "redirect_uris": ["https://example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": True,
                "token_endpoint_auth_method": "client_secret_basic",
            },
        )
        assert second.status_code == 201, second.text
        other_id = second.json()["client_id"]

        # Issue challenge for the first client
        challenge = self._issue_challenge(
            admin_client, seeded_client["client_id"]
        )

        # Try to use it against the second client -> 400
        resp = admin_client.post(
            f"/api/oauth-clients/{other_id}/rotate-secret",
            json={
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert resp.status_code == 400, resp.text

    # ------------------------------------------------------------------
    # Cross-purpose isolation
    # ------------------------------------------------------------------

    def test_jwt_key_challenge_does_not_open_secret(
        self, admin_client, seeded_client
    ):
        """A challenge minted for ``rotate-jwt-key`` cannot be
        redeemed against ``rotate-secret`` (and vice versa)."""
        # The seeded client is client_secret_basic, so we first
        # have to create a client_secret_jwt one to issue a jwt_key
        # challenge against it.
        jwt_client = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "JWT Client",
                "redirect_uris": ["https://example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": True,
                "token_endpoint_auth_method": "client_secret_jwt",
            },
        )
        assert jwt_client.status_code == 201, jwt_client.text
        jwt_id = jwt_client.json()["client_id"]

        # Issue a JWT-key challenge
        challenge_resp = admin_client.post(
            f"/api/oauth-clients/{jwt_id}/rotate-jwt-key/challenge"
        )
        assert challenge_resp.status_code == 200, challenge_resp.text
        challenge = challenge_resp.json()

        # Attempt to use it on rotate-secret -> 400
        bad = admin_client.post(
            f"/api/oauth-clients/{jwt_id}/rotate-secret",
            json={
                "challenge_id": challenge["challenge_id"],
                "word": challenge["word"],
            },
        )
        assert bad.status_code == 400, bad.text
