import pytest
from datetime import timedelta
import json

from authglow.core.datetime import utcnow


class TestMFASession:
    def test_create_mfa_session(self, session_service):
        session = asyncio_run(
            session_service.create_mfa_session(
                user_id="user-1",
                client_id="client-1",
                redirect_uri="https://example.com/callback",
                scope="read write",
            )
        )
        assert session is not None
        assert session.user_id == "user-1"
        assert session.client_id == "client-1"
        assert session.redirect_uri == "https://example.com/callback"
        assert session.scope == "read write"
        assert session.session_token is not None
        assert len(session.session_token) > 20

    def test_mfa_session_has_expires_at(self, session_service):
        before = utcnow()
        session = asyncio_run(
            session_service.create_mfa_session(
                user_id="user-1",
                client_id="client-1",
                redirect_uri="https://example.com/callback",
                scope="read",
            )
        )
        after = utcnow()
        assert session.expires_at > before
        assert session.expires_at <= after + timedelta(minutes=5)

    def test_mfa_session_with_optional_fields(self, session_service):
        session = asyncio_run(
            session_service.create_mfa_session(
                user_id="user-1",
                client_id="client-1",
                redirect_uri="https://example.com/callback",
                scope="openid profile",
                state="abc123",
                code_challenge="challenge_xyz",
                code_challenge_method="S256",
                nonce="nonce_456",
            )
        )
        assert session.state == "abc123"
        assert session.code_challenge == "challenge_xyz"
        assert session.code_challenge_method == "S256"
        assert session.nonce == "nonce_456"

    def test_get_mfa_session_valid(self, session_service):
        session = asyncio_run(
            session_service.create_mfa_session(
                user_id="user-2",
                client_id="client-2",
                redirect_uri="https://example.com/cb",
                scope="read",
            )
        )
        retrieved = asyncio_run(session_service.get_mfa_session(session.session_token))
        assert retrieved is not None
        assert retrieved.user_id == "user-2"
        assert retrieved.client_id == "client-2"

    def test_get_mfa_session_not_found(self, session_service):
        result = asyncio_run(session_service.get_mfa_session("nonexistent-token"))
        assert result is None

    def test_delete_mfa_session(self, session_service):
        session = asyncio_run(
            session_service.create_mfa_session(
                user_id="user-3",
                client_id="client-3",
                redirect_uri="https://example.com/cb",
                scope="read",
            )
        )
        asyncio_run(session_service.delete_mfa_session(session.session_token))
        retrieved = asyncio_run(session_service.get_mfa_session(session.session_token))
        assert retrieved is None

    def test_delete_mfa_session_nonexistent(self, session_service):
        asyncio_run(session_service.delete_mfa_session("nonexistent"))
        assert True

    def test_mfa_session_token_uses_secrets(self, session_service):
        import re

        session = asyncio_run(
            session_service.create_mfa_session(
                user_id="user-tok",
                client_id="client-tok",
                redirect_uri="https://example.com/cb",
                scope="read",
            )
        )
        uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        assert not uuid_pattern.match(session.session_token), (
            "MFA session token should not be UUID4"
        )


class TestMFAExpiry:
    def test_expired_mfa_session_returns_none(self, session_service):
        session = asyncio_run(
            session_service.create_mfa_session(
                user_id="user-exp",
                client_id="client-exp",
                redirect_uri="https://example.com/cb",
                scope="read",
            )
        )
        path = f"{session_service.repository._storage_path}/{session.token_lookup}.json"
        data = session.model_dump(mode="json")
        data["expires_at"] = (utcnow() - timedelta(minutes=1)).isoformat()
        with session_service.repository._filesystem.open(path, "w") as f:
            json.dump(data, f)

        result = asyncio_run(session_service.get_mfa_session(session.session_token))
        assert result is None


class TestConsentSession:
    def test_create_consent_session(self, session_service):
        result = asyncio_run(
            session_service.create_consent_session(
                user_id="user-1",
                client_id="client-1",
                redirect_uri="https://example.com/callback",
                scope="read write",
            )
        )
        assert result is not None
        assert result["user_id"] == "user-1"
        assert result["client_id"] == "client-1"
        assert result["redirect_uri"] == "https://example.com/callback"
        assert result["scope"] == "read write"
        assert "session_token" in result
        assert "expires_at" in result

    def test_consent_session_with_optional_fields(self, session_service):
        result = asyncio_run(
            session_service.create_consent_session(
                user_id="user-1",
                client_id="client-1",
                redirect_uri="https://example.com/callback",
                scope="openid",
                state="state123",
                code_challenge="challenge",
                code_challenge_method="S256",
                nonce="nonce123",
            )
        )
        assert result["state"] == "state123"
        assert result["code_challenge"] == "challenge"
        assert result["code_challenge_method"] == "S256"
        assert result["nonce"] == "nonce123"

    def test_get_consent_session_valid(self, session_service):
        result = asyncio_run(
            session_service.create_consent_session(
                user_id="user-2",
                client_id="client-2",
                redirect_uri="https://example.com/cb",
                scope="read",
            )
        )
        token = result["session_token"]
        retrieved = asyncio_run(session_service.get_consent_session(token))
        assert retrieved is not None
        assert retrieved["user_id"] == "user-2"
        assert retrieved["client_id"] == "client-2"

    def test_get_consent_session_not_found(self, session_service):
        result = asyncio_run(session_service.get_consent_session("nonexistent"))
        assert result is None

    def test_delete_consent_session(self, session_service):
        result = asyncio_run(
            session_service.create_consent_session(
                user_id="user-3",
                client_id="client-3",
                redirect_uri="https://example.com/cb",
                scope="read",
            )
        )
        token = result["session_token"]
        asyncio_run(session_service.delete_consent_session(token))
        retrieved = asyncio_run(session_service.get_consent_session(token))
        assert retrieved is None

    def test_delete_consent_session_nonexistent(self, session_service):
        asyncio_run(session_service.delete_consent_session("nonexistent"))
        assert True

    def test_consent_session_token_uses_secrets(self, session_service):
        import re

        result = asyncio_run(
            session_service.create_consent_session(
                user_id="user-tok",
                client_id="client-tok",
                redirect_uri="https://example.com/cb",
                scope="read",
            )
        )
        uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        token = result["session_token"]
        assert not uuid_pattern.match(token), "Consent session token should not be UUID4"
        assert len(token) > 20


class TestConsentSessionExpiry:
    def test_expired_consent_session_returns_none(self, session_service):
        result = asyncio_run(
            session_service.create_consent_session(
                user_id="user-exp",
                client_id="client-exp",
                redirect_uri="https://example.com/cb",
                scope="read",
            )
        )
        token = result["session_token"]
        path = (
            f"{session_service.repository._storage_path}/consent_{result['token_lookup']}.json"
        )
        result["expires_at"] = (utcnow() - timedelta(minutes=1)).isoformat()
        with session_service.repository._filesystem.open(path, "w") as f:
            json.dump(result, f)

        retrieved = asyncio_run(session_service.get_consent_session(token))
        assert retrieved is None


def asyncio_run(coro):
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)
