import pytest
import asyncio
from datetime import timedelta
from authglow.core.datetime import utcnow
from authglow.models.oauth_consent import OAuth2Consent


def asyncio_run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class TestCreateAndGetConsent:
    def test_create_consent(self, oauth_consent_service):
        consent = asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-1",
                client_id="client-1",
                scopes=["read", "write"],
            )
        )
        assert isinstance(consent, OAuth2Consent)
        assert consent.user_id == "user-1"
        assert consent.client_id == "client-1"
        assert consent.scopes == ["read", "write"]
        assert consent.revoked is False

    def test_create_consent_with_expiry(self, oauth_consent_service):
        expires = utcnow() + timedelta(days=30)
        consent = asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-2",
                client_id="client-2",
                scopes=["read"],
                expires_at=expires,
            )
        )
        assert consent.expires_at is not None

    def test_get_consent(self, oauth_consent_service):
        consent = asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-3", client_id="client-3", scopes=["read"]
            )
        )
        retrieved = asyncio_run(oauth_consent_service.get_consent(consent.consent_id))
        assert retrieved is not None
        assert retrieved.consent_id == consent.consent_id

    def test_get_consent_not_found(self, oauth_consent_service):
        result = asyncio_run(oauth_consent_service.get_consent("nonexistent"))
        assert result is None


class TestGetUserConsent:
    def test_get_user_consent(self, oauth_consent_service):
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-uc", client_id="client-uc", scopes=["read"]
            )
        )
        result = asyncio_run(
            oauth_consent_service.get_user_consent("user-uc", "client-uc")
        )
        assert result is not None
        assert result.user_id == "user-uc"

    def test_get_user_consent_not_found(self, oauth_consent_service):
        result = asyncio_run(
            oauth_consent_service.get_user_consent("nouser", "noclient")
        )
        assert result is None

    def test_get_user_consent_skips_revoked(self, oauth_consent_service):
        consent = asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-rev", client_id="client-rev", scopes=["read"]
            )
        )
        asyncio_run(oauth_consent_service.revoke_consent(consent.consent_id))
        result = asyncio_run(
            oauth_consent_service.get_user_consent("user-rev", "client-rev")
        )
        assert result is None


class TestCheckConsent:
    def test_check_consent_all_scopes_present(self, oauth_consent_service):
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-check", client_id="client-check", scopes=["read", "write"]
            )
        )
        has, consent = asyncio_run(
            oauth_consent_service.check_consent("user-check", "client-check", ["read"])
        )
        assert has is True
        assert consent is not None

    def test_check_consent_missing_scopes(self, oauth_consent_service):
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-check2", client_id="client-check2", scopes=["read"]
            )
        )
        has, consent = asyncio_run(
            oauth_consent_service.check_consent(
                "user-check2", "client-check2", ["read", "admin"]
            )
        )
        assert has is False

    def test_check_consent_no_consent(self, oauth_consent_service):
        has, consent = asyncio_run(
            oauth_consent_service.check_consent("nonexistent", "nonexistent", ["read"])
        )
        assert has is False
        assert consent is None


class TestRevokeConsent:
    def test_revoke_consent(self, oauth_consent_service):
        consent = asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-revoke", client_id="client-revoke", scopes=["read"]
            )
        )
        result = asyncio_run(oauth_consent_service.revoke_consent(consent.consent_id))
        assert result is True
        retrieved = asyncio_run(oauth_consent_service.get_consent(consent.consent_id))
        assert retrieved.revoked is True

    def test_revoke_nonexistent_consent(self, oauth_consent_service):
        result = asyncio_run(oauth_consent_service.revoke_consent("nonexistent"))
        assert result is False

    def test_revoke_user_client_consent(self, oauth_consent_service):
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-ucr", client_id="client-ucr", scopes=["read"]
            )
        )
        result = asyncio_run(
            oauth_consent_service.revoke_user_client_consent("user-ucr", "client-ucr")
        )
        assert result is True

    def test_revoke_user_client_consent_not_found(self, oauth_consent_service):
        result = asyncio_run(
            oauth_consent_service.revoke_user_client_consent("nouser", "noclient")
        )
        assert result is False


class TestListUserConsents:
    def test_list_user_consents(self, oauth_consent_service):
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-list", client_id="c1", scopes=["read"]
            )
        )
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-list", client_id="c2", scopes=["write"]
            )
        )
        consents = asyncio_run(oauth_consent_service.list_user_consents("user-list"))
        assert len(consents) >= 2
        assert all(c.user_id == "user-list" for c in consents)


class TestCleanupExpiredConsents:
    def test_cleanup_expired_consents(self, oauth_consent_service):
        import json
        from datetime import timedelta

        consent = asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-exp",
                client_id="client-exp",
                scopes=["read"],
            )
        )
        path = f"{oauth_consent_service.storage_path}/{consent.consent_id}.json"
        data = consent.model_dump(mode="json")
        data["expires_at"] = (utcnow() - timedelta(days=1)).isoformat()
        with oauth_consent_service.fs.open(path, "w") as f:
            json.dump(data, f)

        deleted = asyncio_run(oauth_consent_service.cleanup_expired_consents())
        assert deleted >= 1
