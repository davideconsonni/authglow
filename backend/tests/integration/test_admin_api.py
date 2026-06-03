import pytest
from unittest.mock import patch, AsyncMock, MagicMock


def _make_admin_user():
    from authglow.models.user import User

    return User(
        id="admin-test-1",
        email="admin@authglow.io",
        hashed_password="not-used-in-test",
        is_active=True,
        scopes=["admin"],
    )


def _make_test_user(user_id, email):
    from authglow.models.user import User

    return User(
        id=user_id,
        email=email,
        hashed_password="not-used-in-test",
        is_active=True,
        scopes=["read"],
    )


def _make_token(token_id, user_id, client_id="test-client"):
    from authglow.models.refresh_token import RefreshToken
    from authglow.core.datetime import utcnow
    from datetime import timedelta

    return RefreshToken(
        token_id=token_id,
        user_id=user_id,
        client_id=client_id,
        scopes=["read"],
        expires_at=utcnow() + timedelta(days=30),
    )


def _mock_services(page_tokens, total_matching):
    mock_rt_svc = AsyncMock()
    mock_rt_svc.list_all_tokens = AsyncMock(return_value=(page_tokens, total_matching))

    mock_user_svc = AsyncMock()
    mock_user_svc.get_user = AsyncMock(
        side_effect=lambda uid: _make_test_user(uid, f"{uid}@test.io")
    )
    mock_user_svc.get_user_by_email = AsyncMock(
        side_effect=lambda email: _make_test_user(email.split("@")[0], email)
    )

    return mock_rt_svc, mock_user_svc


class TestGetActiveSessions:
    def test_returns_empty_when_no_tokens(self):
        import asyncio
        from authglow.api.admin import get_active_sessions

        mock_rt_svc, mock_user_svc = _mock_services([], 0)

        with (
            patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc),
            patch("authglow.api.admin.UserStorage", return_value=mock_user_svc),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                get_active_sessions(
                    email=None,
                    type="all",
                    limit=50,
                    offset=0,
                    current_user=_make_admin_user(),
                )
            )

        assert result["sessions"] == []
        assert result["total_sessions"] == 0
        assert result["total_refresh_tokens"] == 0
        assert result["unique_users"] == 0
        assert result["limit"] == 50
        assert result["offset"] == 0

    def test_returns_active_refresh_tokens(self):
        import asyncio
        from authglow.api.admin import get_active_sessions

        token = _make_token("t1", "session-user-1")

        mock_rt_svc, mock_user_svc = _mock_services([token], 1)

        with (
            patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc),
            patch("authglow.api.admin.UserStorage", return_value=mock_user_svc),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                get_active_sessions(
                    email=None,
                    type="all",
                    limit=50,
                    offset=0,
                    current_user=_make_admin_user(),
                )
            )

        assert len(result["sessions"]) == 1
        assert result["sessions"][0]["id"] == token.token_id
        assert result["sessions"][0]["type"] == "refresh"
        assert result["sessions"][0]["user_email"] == "session-user-1@test.io"
        assert result["sessions"][0]["client_id"] == "test-client"
        assert result["total_sessions"] == 1
        assert result["total_refresh_tokens"] == 1
        assert result["unique_users"] == 1

    def test_excludes_revoked_tokens(self):
        import asyncio
        from authglow.api.admin import get_active_sessions
        from authglow.core.datetime import utcnow
        from datetime import timedelta

        # Token already handled by the service (active_only=True),
        # but get_user returns None (user deleted)
        token = _make_token("t2-orphan", "no-such-user")

        mock_rt_svc, mock_user_svc = _mock_services([token], 1)
        mock_user_svc.get_user = AsyncMock(return_value=None)

        with (
            patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc),
            patch("authglow.api.admin.UserStorage", return_value=mock_user_svc),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                get_active_sessions(
                    email=None,
                    type="all",
                    limit=50,
                    offset=0,
                    current_user=_make_admin_user(),
                )
            )

        assert result["sessions"] == []
        assert result["total_sessions"] == 1

    def test_email_filter_resolves_and_filters(self):
        import asyncio
        from authglow.api.admin import get_active_sessions

        token_a = _make_token("t3a", "session-user-3a")
        token_b = _make_token("t3b", "session-user-3b")

        mock_rt_svc, mock_user_svc = _mock_services([token_b], 1)
        mock_user_svc.get_user_by_email = AsyncMock(
            return_value=_make_test_user("session-user-3b", "filtered@test.io")
        )
        mock_user_svc.get_user = AsyncMock(
            return_value=_make_test_user("session-user-3b", "filtered@test.io")
        )

        mock_rt_svc.list_all_tokens = AsyncMock(return_value=([token_b], 1))

        with (
            patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc),
            patch("authglow.api.admin.UserStorage", return_value=mock_user_svc),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                get_active_sessions(
                    email="filtered@test.io",
                    type="all",
                    limit=50,
                    offset=0,
                    current_user=_make_admin_user(),
                )
            )

        assert len(result["sessions"]) == 1
        assert result["sessions"][0]["id"] == token_b.token_id
        assert result["sessions"][0]["user_email"] == "filtered@test.io"
        assert result["total_sessions"] == 1

    def test_email_not_found_returns_empty(self):
        import asyncio
        from authglow.api.admin import get_active_sessions

        mock_user_svc = AsyncMock()
        mock_user_svc.get_user_by_email = AsyncMock(return_value=None)

        with patch("authglow.api.admin.UserStorage", return_value=mock_user_svc):
            result = asyncio.get_event_loop().run_until_complete(
                get_active_sessions(
                    email="nonexistent@test.io",
                    type="all",
                    limit=50,
                    offset=0,
                    current_user=_make_admin_user(),
                )
            )

        assert result["sessions"] == []
        assert result["total_sessions"] == 0

    def test_pagination_offset_and_limit(self):
        import asyncio
        from authglow.api.admin import get_active_sessions

        tokens = [_make_token(f"t4-{i}", f"user-pag-{i}") for i in range(10)]

        page1 = tokens[:3]
        page2 = tokens[3:6]

        mock_rt_svc = AsyncMock()
        mock_rt_svc.list_all_tokens = AsyncMock(
            side_effect=[
                (page1, 10),
                (page2, 10),
            ]
        )

        mock_user_svc = AsyncMock()
        mock_user_svc.get_user = AsyncMock(
            side_effect=lambda uid: _make_test_user(uid, f"{uid}@test.io")
        )

        with (
            patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc),
            patch("authglow.api.admin.UserStorage", return_value=mock_user_svc),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                get_active_sessions(
                    email=None,
                    type="all",
                    limit=3,
                    offset=0,
                    current_user=_make_admin_user(),
                )
            )

        assert len(result["sessions"]) == 3
        assert result["total_sessions"] == 10
        assert result["limit"] == 3
        assert result["offset"] == 0

        with (
            patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc),
            patch("authglow.api.admin.UserStorage", return_value=mock_user_svc),
        ):
            result2 = asyncio.get_event_loop().run_until_complete(
                get_active_sessions(
                    email=None,
                    type="all",
                    limit=3,
                    offset=3,
                    current_user=_make_admin_user(),
                )
            )

        assert len(result2["sessions"]) == 3
        assert result2["total_sessions"] == 10
        page1_ids = {s["id"] for s in result["sessions"]}
        page2_ids = {s["id"] for s in result2["sessions"]}
        assert page1_ids.isdisjoint(page2_ids)

    def test_total_sessions_reflects_filter_count(self):
        import asyncio
        from authglow.api.admin import get_active_sessions

        tokens = [_make_token(f"t5-{i}", f"user-total-{i}") for i in range(5)]
        page = tokens[:2]

        mock_rt_svc, mock_user_svc = _mock_services(page, 5)

        with (
            patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc),
            patch("authglow.api.admin.UserStorage", return_value=mock_user_svc),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                get_active_sessions(
                    email=None,
                    type="all",
                    limit=2,
                    offset=0,
                    current_user=_make_admin_user(),
                )
            )

        assert len(result["sessions"]) == 2
        assert result["total_sessions"] == 5
        assert result["total_refresh_tokens"] == 5


class TestGetUserSessions:
    def test_returns_sessions_for_specific_user(self):
        import asyncio
        from authglow.api.admin import get_user_sessions

        token = _make_token("us-t1", "specific-user")

        mock_rt_svc = AsyncMock()
        mock_rt_svc.list_all_tokens = AsyncMock(return_value=([token], 1))

        with patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc):
            result = asyncio.get_event_loop().run_until_complete(
                get_user_sessions(
                    user_id="specific-user",
                    limit=50,
                    offset=0,
                    current_user=_make_admin_user(),
                )
            )

        assert len(result.items) == 1
        assert result.items[0]["id"] == token.token_id
        assert result.items[0]["client_id"] == "test-client"
        assert result.total == 1

    def test_returns_empty_when_no_sessions(self):
        import asyncio
        from authglow.api.admin import get_user_sessions

        mock_rt_svc = AsyncMock()
        mock_rt_svc.list_all_tokens = AsyncMock(return_value=([], 0))

        with patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc):
            result = asyncio.get_event_loop().run_until_complete(
                get_user_sessions(
                    user_id="no-sessions-user",
                    limit=50,
                    offset=0,
                    current_user=_make_admin_user(),
                )
            )

        assert result.items == []
        assert result.total == 0

    def test_pagination(self):
        import asyncio
        from authglow.api.admin import get_user_sessions

        tokens = [_make_token(f"us-pag-{i}", "pag-user") for i in range(10)]
        mock_rt_svc = AsyncMock()
        mock_rt_svc.list_all_tokens = AsyncMock(return_value=(tokens[:3], 10))

        with patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc):
            result = asyncio.get_event_loop().run_until_complete(
                get_user_sessions(
                    user_id="pag-user",
                    limit=3,
                    offset=0,
                    current_user=_make_admin_user(),
                )
            )

        assert len(result.items) == 3
        assert result.total == 10
        assert result.limit == 3
        assert result.offset == 0


class TestRevokeAllUserSessions:
    def test_revokes_all_sessions(self):
        import asyncio
        from authglow.api.admin import revoke_all_user_sessions

        mock_rt_svc = AsyncMock()
        mock_rt_svc.revoke_user_tokens = AsyncMock(return_value=3)

        mock_user_svc = AsyncMock()
        mock_user_svc.get_user = AsyncMock(
            return_value=_make_test_user("revoke-target", "target@test.io")
        )

        audit_svc = AsyncMock()

        user_id = "revoke-target"

        with (
            patch("authglow.api.admin.RefreshTokenService", return_value=mock_rt_svc),
            patch("authglow.api.admin.UserStorage", return_value=mock_user_svc),
            patch("authglow.api.admin.AuditService", return_value=audit_svc),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                revoke_all_user_sessions(
                    user_id=user_id,
                    current_user=_make_admin_user(),
                    audit_service=audit_svc,
                )
            )

        assert result["revoked_count"] == 3
        assert "Revoked" in result["message"]
        mock_rt_svc.revoke_user_tokens.assert_called_once_with(user_id)

    def test_returns_404_when_user_not_found(self):
        import asyncio
        from authglow.api.admin import revoke_all_user_sessions
        from fastapi import HTTPException

        mock_user_svc = AsyncMock()
        mock_user_svc.get_user = AsyncMock(return_value=None)

        with patch("authglow.api.admin.UserStorage", return_value=mock_user_svc):
            with pytest.raises(HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(
                    revoke_all_user_sessions(
                        user_id="nonexistent",
                        current_user=_make_admin_user(),
                        audit_service=MagicMock(),
                    )
                )

        assert exc.value.status_code == 404


class TestDisableUserMFA:
    def test_disables_mfa_and_preserves_backup_codes(self):
        import asyncio
        from authglow.api.admin import disable_user_mfa

        mock_storage = AsyncMock()
        mock_user = _make_test_user("mfa-target", "mfa@test.io")
        mock_user.mfa_enabled = True
        mock_user.mfa_secret = "some-secret"
        mock_user.mfa_verified = True
        mock_storage.get_user = AsyncMock(return_value=mock_user)
        mock_storage.update_user = AsyncMock(return_value=True)

        audit_svc = AsyncMock()
        mfa_svc = AsyncMock()

        with (
            patch("authglow.api.admin.UserStorage", return_value=mock_storage),
            patch("authglow.api.admin.AuditService", return_value=audit_svc),
            patch("authglow.api.admin.MFAService", return_value=mfa_svc),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                disable_user_mfa(
                    user_id="mfa-target",
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=audit_svc,
                    mfa_service=mfa_svc,
                )
            )

        assert result["message"] == "MFA disabled successfully"
        assert mock_user.mfa_enabled is False
        assert mock_user.mfa_secret is None
        assert mock_user.mfa_verified is False
        mock_storage.update_user.assert_called_once_with(mock_user)
        mfa_svc.delete_backup_codes.assert_not_called()

    def test_returns_404_when_user_not_found(self):
        import asyncio
        from authglow.api.admin import disable_user_mfa
        from fastapi import HTTPException

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)

        with patch("authglow.api.admin.UserStorage", return_value=mock_storage):
            with pytest.raises(HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(
                    disable_user_mfa(
                        user_id="nonexistent",
                        current_user=_make_admin_user(),
                        storage=mock_storage,
                        audit_service=AsyncMock(),
                        mfa_service=AsyncMock(),
                    )
                )

        assert exc.value.status_code == 404

    def test_returns_400_when_mfa_not_enabled(self):
        import asyncio
        from authglow.api.admin import disable_user_mfa
        from fastapi import HTTPException

        mock_storage = AsyncMock()
        mock_user = _make_test_user("no-mfa", "nomfa@test.io")
        mock_user.mfa_enabled = False
        mock_storage.get_user = AsyncMock(return_value=mock_user)

        with patch("authglow.api.admin.UserStorage", return_value=mock_storage):
            with pytest.raises(HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(
                    disable_user_mfa(
                        user_id="no-mfa",
                        current_user=_make_admin_user(),
                        storage=mock_storage,
                        audit_service=AsyncMock(),
                        mfa_service=AsyncMock(),
                    )
                )

        assert exc.value.status_code == 400


class TestRegenerateUserBackupCodes:
    def test_regenerates_and_returns_codes(self):
        import asyncio
        from authglow.api.admin import regenerate_user_backup_codes

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(
            return_value=_make_test_user("codes-target", "codes@test.io")
        )

        mfa_svc = MagicMock()
        mfa_svc.generate_backup_codes = MagicMock(return_value=["CODE1-AAAA", "CODE2-BBBB"])
        mfa_svc.save_backup_codes = AsyncMock(return_value=None)

        audit_svc = AsyncMock()

        with (
            patch("authglow.api.admin.UserStorage", return_value=mock_storage),
            patch("authglow.api.admin.AuditService", return_value=audit_svc),
            patch("authglow.api.admin.MFAService", return_value=mfa_svc),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                regenerate_user_backup_codes(
                    user_id="codes-target",
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=audit_svc,
                    mfa_service=mfa_svc,
                )
            )

        assert result["message"] == "Backup codes regenerated successfully"
        assert len(result["backup_codes"]) == 2
        assert result["backup_codes"] == ["CODE1-AAAA", "CODE2-BBBB"]
        mfa_svc.save_backup_codes.assert_called_once_with(
            "codes-target", ["CODE1-AAAA", "CODE2-BBBB"]
        )

    def test_returns_404_when_user_not_found(self):
        import asyncio
        from authglow.api.admin import regenerate_user_backup_codes
        from fastapi import HTTPException

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)

        with patch("authglow.api.admin.UserStorage", return_value=mock_storage):
            with pytest.raises(HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(
                    regenerate_user_backup_codes(
                        user_id="nonexistent",
                        current_user=_make_admin_user(),
                        storage=mock_storage,
                        audit_service=AsyncMock(),
                        mfa_service=AsyncMock(),
                    )
                )

        assert exc.value.status_code == 404


class TestGetUserLoginHistory:
    def test_returns_login_history(self):
        import asyncio
        from authglow.api.admin import get_user_login_history

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(
            return_value=_make_test_user("login-hist", "login@test.io")
        )

        items = [
            {
                "id": "e1",
                "user_id": "login-hist",
                "email": "login@test.io",
                "success": True,
                "ip_address": "127.0.0.1",
                "user_agent": "Mozilla/5.0",
                "failure_reason": None,
                "timestamp": "2025-01-01T00:00:00+00:00",
            },
            {
                "id": "e2",
                "user_id": "login-hist",
                "email": "login@test.io",
                "success": False,
                "ip_address": "192.168.1.1",
                "user_agent": "curl/7.0",
                "failure_reason": "invalid_password",
                "timestamp": "2025-01-02T00:00:00+00:00",
            },
        ]

        mock_login_svc = AsyncMock()
        mock_login_svc.get_login_history = AsyncMock(return_value=(items, 2))

        with (
            patch("authglow.api.admin.UserStorage", return_value=mock_storage),
            patch(
                "authglow.services.login_history.LoginHistoryService", return_value=mock_login_svc
            ),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                get_user_login_history(
                    user_id="login-hist",
                    limit=50,
                    offset=0,
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                )
            )

        assert result.total == 2
        assert len(result.items) == 2
        assert result.items[0]["success"] is True
        assert result.items[1]["success"] is False
        assert result.items[1]["failure_reason"] == "invalid_password"

    def test_returns_404_when_user_not_found(self):
        import asyncio
        from authglow.api.admin import get_user_login_history
        from fastapi import HTTPException

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)

        with patch("authglow.api.admin.UserStorage", return_value=mock_storage):
            with pytest.raises(HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(
                    get_user_login_history(
                        user_id="nonexistent",
                        limit=50,
                        offset=0,
                        current_user=_make_admin_user(),
                        storage=mock_storage,
                    )
                )

        assert exc.value.status_code == 404


class TestGetUserSecurityEvents:
    def test_returns_security_events(self):
        import asyncio
        from authglow.api.admin import get_user_security_events

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=_make_test_user("sec-events", "sec@test.io"))

        items = [
            {
                "id": "s1",
                "user_id": "sec-events",
                "event_type": "password_changed",
                "email": "sec@test.io",
                "description": "Password changed by admin",
                "ip_address": "127.0.0.1",
                "metadata": {},
                "timestamp": "2025-01-01T00:00:00+00:00",
            },
            {
                "id": "s2",
                "user_id": "sec-events",
                "event_type": "mfa_disabled",
                "email": "sec@test.io",
                "description": "MFA disabled by admin",
                "ip_address": None,
                "metadata": {"admin_id": "admin-test-1"},
                "timestamp": "2025-01-02T00:00:00+00:00",
            },
        ]

        mock_event_svc = AsyncMock()
        mock_event_svc.get_security_events = AsyncMock(return_value=(items, 2))

        with (
            patch("authglow.api.admin.UserStorage", return_value=mock_storage),
            patch(
                "authglow.services.security_event.SecurityEventService", return_value=mock_event_svc
            ),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                get_user_security_events(
                    user_id="sec-events",
                    limit=50,
                    offset=0,
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                )
            )

        assert result.total == 2
        assert len(result.items) == 2
        assert result.items[0]["event_type"] == "password_changed"
        assert result.items[1]["event_type"] == "mfa_disabled"

    def test_returns_404_when_user_not_found(self):
        import asyncio
        from authglow.api.admin import get_user_security_events
        from fastapi import HTTPException

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)

        with patch("authglow.api.admin.UserStorage", return_value=mock_storage):
            with pytest.raises(HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(
                    get_user_security_events(
                        user_id="nonexistent",
                        limit=50,
                        offset=0,
                        current_user=_make_admin_user(),
                        storage=mock_storage,
                    )
                )

        assert exc.value.status_code == 404


class TestGetUserOAuthConsents:
    def test_returns_oauth_consents(self):
        import asyncio
        from authglow.api.admin import get_user_oauth_consents
        from authglow.services.oauth_consent import OAuth2ConsentService
        from authglow.core.datetime import utcnow

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(
            return_value=_make_test_user("consent-user", "consent@test.io")
        )

        consent = MagicMock()
        consent.consent_id = "c1"
        consent.client_id = "test-client"
        consent.scopes = ["openid", "profile"]
        consent.granted_at = utcnow()
        consent.expires_at = None
        consent.revoked = False
        consent.revoked_at = None

        mock_consent_svc = AsyncMock()
        mock_consent_svc.list_user_consents = AsyncMock(return_value=[consent])

        mock_client_storage = AsyncMock()
        mock_client = MagicMock()
        mock_client.client_name = "Test App"
        mock_client_storage.get_client = AsyncMock(return_value=mock_client)

        with (
            patch("authglow.api.admin.UserStorage", return_value=mock_storage),
            patch(
                "authglow.services.oauth_consent.OAuth2ConsentService",
                return_value=mock_consent_svc,
            ),
            patch(
                "authglow.services.oauth_client.OAuth2ClientStorage",
                return_value=mock_client_storage,
            ),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                get_user_oauth_consents(
                    user_id="consent-user",
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                )
            )

        assert len(result) == 1
        assert result[0]["consent_id"] == "c1"
        assert result[0]["client_name"] == "Test App"
        assert result[0]["scopes"] == ["openid", "profile"]
        assert result[0]["revoked"] is False

    def test_returns_404_when_user_not_found(self):
        import asyncio
        from authglow.api.admin import get_user_oauth_consents
        from fastapi import HTTPException

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)

        with patch("authglow.api.admin.UserStorage", return_value=mock_storage):
            with pytest.raises(HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(
                    get_user_oauth_consents(
                        user_id="nonexistent",
                        current_user=_make_admin_user(),
                        storage=mock_storage,
                    )
                )

        assert exc.value.status_code == 404


class TestCreateUser:
    def test_creates_user_with_password(self):
        import asyncio
        from authglow.api.admin import create_user
        from authglow.models.user import UserCreate

        mock_storage = AsyncMock()
        mock_storage.get_user_by_email = AsyncMock(return_value=None)
        mock_storage.create_user = AsyncMock(side_effect=lambda u: u)

        audit_svc = AsyncMock()

        body = UserCreate(
            email="newuser@test.io",
            password="StrongPass1!",
            first_name="New",
            last_name="User",
            scopes=["read", "write"],
        )

        def fake_hash(pw):
            return f"hashed-{pw}"

        with (
            patch("authglow.api.admin.UserStorage", return_value=mock_storage),
            patch("authglow.api.admin.AuditService", return_value=audit_svc),
            patch("authglow.api.admin.hash_password", side_effect=fake_hash),
            patch("authglow.api.admin.EmailVerificationService") as mock_ver_svc,
        ):
            mock_ver = AsyncMock()
            mock_ver.create_verification_token = AsyncMock()
            mock_ver.send_verification_email = AsyncMock(return_value=True)
            mock_ver_svc.return_value = mock_ver

            result = asyncio.get_event_loop().run_until_complete(
                create_user(
                    body=body,
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=audit_svc,
                )
            )

        assert result.email == "newuser@test.io"
        assert result.first_name == "New"
        assert result.last_name == "User"
        assert result.scopes == ["read", "write"]
        mock_storage.create_user.assert_called_once()
        created = mock_storage.create_user.call_args[0][0]
        assert created.hashed_password == "hashed-StrongPass1!"
        assert created.is_invited is False
        audit_svc.log_event.assert_called_once()

    def test_returns_400_when_email_exists(self):
        import asyncio
        from authglow.api.admin import create_user
        from authglow.models.user import UserCreate
        from fastapi import HTTPException

        mock_storage = AsyncMock()
        mock_storage.get_user_by_email = AsyncMock(
            return_value=_make_test_user("existing", "existing@test.io")
        )

        body = UserCreate(email="existing@test.io", password="StrongPass1!")

        with patch("authglow.api.admin.UserStorage", return_value=mock_storage):
            with pytest.raises(HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(
                    create_user(
                        body=body,
                        current_user=_make_admin_user(),
                        storage=mock_storage,
                        audit_service=AsyncMock(),
                    )
                )

        assert exc.value.status_code == 400

    def test_returns_400_when_password_weak(self):
        import asyncio
        from authglow.api.admin import create_user
        from authglow.models.user import UserCreate
        from fastapi import HTTPException

        mock_storage = AsyncMock()
        mock_storage.get_user_by_email = AsyncMock(return_value=None)
        mock_storage.create_user = AsyncMock(side_effect=lambda u: u)

        body = UserCreate(email="weak@test.io", password="abcdefgh")

        with (
            patch("authglow.api.admin.UserStorage", return_value=mock_storage),
            patch("authglow.api.admin.hash_password"),
        ):
            with pytest.raises(HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(
                    create_user(
                        body=body,
                        current_user=_make_admin_user(),
                        storage=mock_storage,
                        audit_service=AsyncMock(),
                    )
                )

        assert exc.value.status_code == 400
        assert "Password" in exc.value.detail


class TestUpdateUserExtended:
    def test_updates_phone_and_avatar(self):
        import asyncio
        from authglow.api.admin import update_user

        mock_user = _make_test_user("ext-update", "ext@test.io")
        mock_user.phone = None
        mock_user.avatar_url = None

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=mock_user)
        mock_storage.update_user = AsyncMock(side_effect=lambda u: u)

        audit_svc = AsyncMock()

        from authglow.models.admin import UserUpdate

        update_data = UserUpdate(
            phone="+1234567890",
            avatar_url="https://example.com/avatar.png",
        )

        with (
            patch("authglow.api.admin.UserStorage", return_value=mock_storage),
            patch("authglow.api.admin.AuditService", return_value=audit_svc),
        ):
            result = asyncio.get_event_loop().run_until_complete(
                update_user(
                    user_id="ext-update",
                    update_data=update_data,
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=audit_svc,
                )
            )

        assert result.phone == "+1234567890"
        assert result.avatar_url == "https://example.com/avatar.png"
        audit_svc.log_event.assert_called_once()

    def test_updates_email_triggers_verification(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        mock_user = _make_test_user("email-change", "old@test.io")

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=mock_user)
        mock_storage.update_email = AsyncMock(
            side_effect=lambda uid, email: _make_test_user(uid, email)
        )
        mock_storage.update_user = AsyncMock(side_effect=lambda u: u)

        audit_svc = AsyncMock()

        update_data = UserUpdate(email="new@test.io")

        with (
            patch("authglow.api.admin.UserStorage", return_value=mock_storage),
            patch("authglow.api.admin.AuditService", return_value=audit_svc),
            patch("authglow.api.admin.EmailVerificationService") as mock_ver_svc,
        ):
            mock_ver = AsyncMock()
            mock_ver.create_verification_token = AsyncMock()
            mock_ver.send_verification_email = AsyncMock(return_value=True)
            mock_ver_svc.return_value = mock_ver

            result = asyncio.get_event_loop().run_until_complete(
                update_user(
                    user_id="email-change",
                    update_data=update_data,
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=audit_svc,
                )
            )

        assert result.email == "new@test.io"
        mock_storage.update_email.assert_called_once_with("email-change", "new@test.io")
        mock_ver.create_verification_token.assert_called_once()
        audit_svc.log_event.assert_called_once()

    def test_updates_email_duplicate_returns_400(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate
        from fastapi import HTTPException

        mock_user = _make_test_user("dup-email", "old@test.io")

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=mock_user)
        mock_storage.update_email = AsyncMock(
            side_effect=ValueError("User with email dup@test.io already exists")
        )

        update_data = UserUpdate(email="dup@test.io")

        with (
            patch("authglow.api.admin.UserStorage", return_value=mock_storage),
            patch("authglow.api.admin.AuditService", return_value=AsyncMock()),
        ):
            with pytest.raises(HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(
                    update_user(
                        user_id="dup-email",
                        update_data=update_data,
                        current_user=_make_admin_user(),
                        storage=mock_storage,
                        audit_service=AsyncMock(),
                    )
                )

        assert exc.value.status_code == 400
