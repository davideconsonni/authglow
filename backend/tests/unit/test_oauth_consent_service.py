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
        result = asyncio_run(oauth_consent_service.get_user_consent("user-uc", "client-uc"))
        assert result is not None
        assert result.user_id == "user-uc"

    def test_get_user_consent_not_found(self, oauth_consent_service):
        result = asyncio_run(oauth_consent_service.get_user_consent("nouser", "noclient"))
        assert result is None

    def test_get_user_consent_skips_revoked(self, oauth_consent_service):
        consent = asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-rev", client_id="client-rev", scopes=["read"]
            )
        )
        asyncio_run(oauth_consent_service.revoke_consent(consent.consent_id))
        result = asyncio_run(oauth_consent_service.get_user_consent("user-rev", "client-rev"))
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
            oauth_consent_service.check_consent("user-check2", "client-check2", ["read", "admin"])
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
        result = asyncio_run(oauth_consent_service.revoke_user_client_consent("nouser", "noclient"))
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
        repo = oauth_consent_service.repository
        path = f"{repo._storage_path}/{consent.user_id}/{consent.client_id}.json"
        data = consent.model_dump(mode="json")
        data["expires_at"] = (utcnow() - timedelta(days=1)).isoformat()
        with repo._filesystem.open(path, "w") as f:
            json.dump(data, f)

        deleted = asyncio_run(oauth_consent_service.cleanup_expired_consents())
        assert deleted >= 1

    def test_retention_days_constant(self, oauth_consent_service):
        """VAPT-086 — ``OAuth2ConsentService.RETENTION_DAYS`` is
        the contract that drives the retention sweep. Match the
        other persistent services (``security_event``,
        ``admin_action``) at 365 days.
        """
        from authglow.services.oauth_consent import OAuth2ConsentService

        assert OAuth2ConsentService.RETENTION_DAYS == 365
        assert oauth_consent_service.RETENTION_DAYS == 365


class TestP5DeterministicConsentLookup:
    """P5: get_user_consent() uses O(1) direct path, not glob."""

    def test_get_user_consent_uses_deterministic_path(self, oauth_consent_service):
        """get_user_consent builds path as {user_id}/{client_id}.json."""
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="user-p5", client_id="client-p5", scopes=["read"]
            )
        )
        repo = oauth_consent_service.repository
        expected_path = repo._path_for("user-p5", "client-p5")
        result = asyncio_run(oauth_consent_service.get_user_consent("user-p5", "client-p5"))
        assert result is not None
        assert result.user_id == "user-p5"
        assert result.client_id == "client-p5"
        assert expected_path == repo._path_for("user-p5", "client-p5")
        assert repo._filesystem.exists(expected_path)

    def test_get_user_consent_no_glob_on_hit(self, oauth_consent_service):
        """On a match, get_user_consent does NOT call glob."""
        asyncio_run(
            oauth_consent_service.create_consent(user_id="p5-hit", client_id="c1", scopes=["read"])
        )
        from unittest.mock import patch

        import authglow.repositories.file.base as mod

        with patch.object(mod.BaseFileRepository, "_glob", wraps=None) as mock_glob:
            result = asyncio_run(oauth_consent_service.get_user_consent("p5-hit", "c1"))
            assert result is not None
            mock_glob.assert_not_called()

    def test_get_user_consent_no_glob_on_miss(self, oauth_consent_service):
        """On a miss, get_user_consent does NOT call glob either."""
        from unittest.mock import patch

        import authglow.repositories.file.base as mod

        with patch.object(mod.BaseFileRepository, "_glob", wraps=None) as mock_glob:
            result = asyncio_run(oauth_consent_service.get_user_consent("nouser", "noclient"))
            assert result is None
            mock_glob.assert_not_called()

    def test_create_consent_deterministic_path(self, oauth_consent_service):
        """create_consent saves to {user_id}/{client_id}.json."""
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="p5-create", client_id="c2", scopes=["read", "write"]
            )
        )
        repo = oauth_consent_service.repository
        path = repo._path_for("p5-create", "c2")
        assert repo._filesystem.exists(path)
        data = repo._filesystem.cat(path)
        loaded = __import__("json").loads(data)
        assert loaded["user_id"] == "p5-create"
        assert loaded["client_id"] == "c2"
        assert loaded["scopes"] == ["read", "write"]

    def test_create_consent_overwrites_same_user_client(self, oauth_consent_service):
        """Second create_consent for same user+client overwrites."""
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="p5-ov", client_id="c-ov", scopes=["read"]
            )
        )
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="p5-ov", client_id="c-ov", scopes=["read", "write"]
            )
        )
        result = asyncio_run(oauth_consent_service.get_user_consent("p5-ov", "c-ov"))
        assert result is not None
        assert result.scopes == ["read", "write"]

    def test_revoke_user_client_consent_no_glob(self, oauth_consent_service):
        """revoke_user_client_consent is O(1), no glob."""
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="p5-rev", client_id="c-rev", scopes=["read"]
            )
        )
        from unittest.mock import patch

        import authglow.repositories.file.base as mod

        with patch.object(mod.BaseFileRepository, "_glob", wraps=None) as mock_glob:
            success = asyncio_run(
                oauth_consent_service.revoke_user_client_consent("p5-rev", "c-rev")
            )
            assert success is True
            mock_glob.assert_not_called()

    def test_get_consent_by_id_still_works(self, oauth_consent_service):
        """get_consent(consent_id) still finds consent via scan."""
        consent = asyncio_run(
            oauth_consent_service.create_consent(
                user_id="p5-byid", client_id="c-byid", scopes=["read"]
            )
        )
        found = asyncio_run(oauth_consent_service.get_consent(consent.consent_id))
        assert found is not None
        assert found.consent_id == consent.consent_id

    def test_list_user_consents_bounded_glob(self, oauth_consent_service):
        """list_user_consents only globs under the user directory."""
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="p5-list", client_id="c-a", scopes=["read"]
            )
        )
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="p5-list", client_id="c-b", scopes=["write"]
            )
        )
        asyncio_run(
            oauth_consent_service.create_consent(
                user_id="other-user", client_id="c-c", scopes=["admin"]
            )
        )
        consents = asyncio_run(oauth_consent_service.list_user_consents("p5-list"))
        assert len(consents) >= 2
        assert all(c.user_id == "p5-list" for c in consents)

    def test_consent_expiration_auto_delete(self, oauth_consent_service):
        """Expired consent is auto-deleted on get_user_consent."""
        import json
        from datetime import timedelta

        consent = asyncio_run(
            oauth_consent_service.create_consent(
                user_id="p5-exp", client_id="c-exp", scopes=["read"]
            )
        )
        repo = oauth_consent_service.repository
        path = repo._path_for("p5-exp", "c-exp")
        data = consent.model_dump(mode="json")
        data["expires_at"] = (utcnow() - timedelta(days=1)).isoformat()
        with repo._filesystem.open(path, "w") as f:
            json.dump(data, f)

        result = asyncio_run(oauth_consent_service.get_user_consent("p5-exp", "c-exp"))
        assert result is None
        assert not repo._filesystem.exists(path)
