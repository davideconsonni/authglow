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
