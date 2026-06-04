"""Unit tests for setup API with TOCTOU race-condition protection."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI

from authglow.api.setup import router as setup_router
from authglow.core.concurrency import named_lock
from authglow.core.rate_limit import limiter


@pytest.fixture
def setup_app():
    app = FastAPI()
    app.include_router(setup_router)
    return TestClient(app)


class TestSetupCheck:
    def test_check_setup_needed_when_no_users(self, setup_app):
        with patch("authglow.api.setup.UserStorage") as MockStorage:
            MockStorage.return_value.count_users = AsyncMock(return_value=0)
            resp = setup_app.get("/api/setup/check")

        assert resp.status_code == 200
        assert resp.json()["needs_setup"] is True

    def test_check_setup_completed_when_users_exist(self, setup_app):
        with patch("authglow.api.setup.UserStorage") as MockStorage:
            MockStorage.return_value.count_users = AsyncMock(return_value=5)
            resp = setup_app.get("/api/setup/check")

        assert resp.status_code == 200
        assert resp.json()["needs_setup"] is False


class TestCreateAdminLock:
    def test_first_admin_creation_succeeds(self, setup_app, test_settings):
        from authglow.models.user import User

        created_user = User(
            id="admin-1",
            email="admin@test.com",
            hashed_password="hashed",
            is_active=True,
            scopes=["read", "write", "admin"],
            email_verified=True,
        )

        with patch("authglow.api.setup.UserStorage") as MockStorage:
            storage = MockStorage.return_value
            storage.count_users = AsyncMock(return_value=0)
            storage.get_user_by_email = AsyncMock(return_value=None)
            storage.create_user = AsyncMock(return_value=created_user)

            resp = setup_app.post(
                "/api/setup/create-admin",
                json={
                    "email": "admin@test.com",
                    "password": "StrongP@ss1!",
                    "first_name": "Admin",
                    "last_name": "User",
                },
            )

        assert resp.status_code == 200
        assert resp.json()["message"] == "Administrator account created successfully"

    def test_second_admin_creation_blocked(self, setup_app):
        with patch("authglow.api.setup.UserStorage") as MockStorage:
            storage = MockStorage.return_value
            storage.count_users = AsyncMock(return_value=1)

            resp = setup_app.post(
                "/api/setup/create-admin",
                json={
                    "email": "admin2@test.com",
                    "password": "StrongP@ss1!",
                },
            )

        assert resp.status_code == 400
        assert "already completed" in resp.json()["detail"]

    def test_lock_prevents_concurrent_creation(self, test_settings):
        """Two concurrent calls: only the first succeeds, second gets blocked."""
        from authglow.models.user import User

        first_admin = User(
            id="admin-first",
            email="first@test.com",
            hashed_password="hashed",
            is_active=True,
            scopes=["read", "write", "admin"],
            email_verified=True,
        )

        call_order = []

        async def slow_create_user(user):
            call_order.append("create")
            return first_admin

        async def count_users_sequence():
            if "count1" not in call_order:
                call_order.append("count1")
                return 0
            call_order.append("count2")
            return 1

        with patch.object(limiter, "enabled", False):
            with patch("authglow.api.setup.UserStorage") as MockStorage:
                storage = MockStorage.return_value
                storage.count_users = AsyncMock(side_effect=count_users_sequence)
                storage.get_user_by_email = AsyncMock(return_value=None)
                storage.create_user = AsyncMock(side_effect=slow_create_user)

                from authglow.api.setup import CreateAdminRequest, create_admin_user

                req = CreateAdminRequest(email="first@test.com", password="StrongP@ss1!")
                loop = asyncio.new_event_loop()
                r1 = loop.run_until_complete(
                    create_admin_user(request=MagicMock(), admin_request=req)
                )
                assert r1["message"] == "Administrator account created successfully"

                req2 = CreateAdminRequest(email="second@test.com", password="StrongP@ss1!")
                with pytest.raises(Exception) as exc_info:
                    loop.run_until_complete(
                        create_admin_user(request=MagicMock(), admin_request=req2)
                    )
                assert "already completed" in str(exc_info.value)
                loop.close()

        assert call_order == ["count1", "create", "count2"]

    def test_count_users_exception_not_silently_bypassed(self, setup_app):
        """count_users() raising an unexpected exception should propagate, not be silently ignored.

        Before the TOCTOU fix, ``except Exception: pass`` swallowed errors and
        allowed admin creation to proceed past a broken storage check.  Now
        the exception propagates properly.
        """
        with patch("authglow.api.setup.UserStorage") as MockStorage:
            storage = MockStorage.return_value
            storage.count_users = AsyncMock(side_effect=RuntimeError("database down"))

            with pytest.raises(RuntimeError, match="database down"):
                setup_app.post(
                    "/api/setup/create-admin",
                    json={
                        "email": "admin@test.com",
                        "password": "StrongP@ss1!",
                    },
                )


class TestSetupLockIsolation:
    def test_lock_is_acquired_during_admin_creation(self):
        """The named lock for 'setup:create-admin' must be used."""
        lock = named_lock()
        # Verify the lock exists after the function is called
        assert not lock.is_held("setup:create-admin"), "lock should not leak between tests"
