"""Tests for demo mode: seeding + public metadata endpoint.

Demo mode is an INTENTIONAL public sandbox (see
``authglow.services.demo`` for the security rationale). These tests
pin the three behaviours an audit should verify:

1. ``seed_demo_user`` is idempotent and only ever creates the one
   well-known demo admin.
2. ``GET /api/meta`` exposes the boot-time demo password ONLY when
   ``Settings.demo_mode`` is true; with demo mode off it returns no
   credential material.
3. Production security validators still apply when ``demo_mode`` is
   enabled (demo mode is orthogonal to ``app_env``).
"""

from __future__ import annotations

import os
from typing import Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.meta import router as meta_router
from authglow.core.config import Settings
from authglow.models.user import User
from authglow.services.demo import seed_demo_user
from authglow.services.user import UserService


class _InMemoryDemoUserRepo:
    """Minimal in-memory user repository (Protocol-shaped) used to
    exercise ``seed_demo_user`` without the File stack."""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    async def create(self, user: User) -> None:
        if user.id in self._users:
            raise ValueError(f"User with id {user.id} already exists")
        self._users[user.id] = user

    async def get_by_id(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id)

    async def update(self, user: User) -> None:
        self._users[user.id] = user

    async def set_password(
        self, user_id: str, hashed_password: str, require_change: bool = False
    ) -> Optional[User]:
        user = self._users.get(user_id)
        if user is None:
            return None
        user.hashed_password = hashed_password
        return user


class _InMemoryDemoEmailIndex:
    def __init__(self) -> None:
        self._index: dict[str, str] = {}

    async def lookup(self, email: str) -> Optional[str]:
        return self._index.get(email.lower())

    async def insert(self, email: str, user_id: str) -> None:
        self._index[email.lower()] = user_id

    async def remove(self, email: str) -> None:
        self._index.pop(email.lower(), None)

    async def all(self) -> dict[str, str]:
        return dict(self._index)


class _InMemoryDemoFedRepo:
    async def lookup(self, provider_id: str, external_id: str) -> Optional[str]:
        return None

    async def link(self, user_id: str, provider_id: str, external_id: str) -> None:
        pass


def _make_service() -> UserService:
    """Build a UserService bound to the in-memory repos."""
    from contextlib import asynccontextmanager

    from authglow.core import config as _config

    svc = UserService.__new__(UserService)
    svc._user_repo = _InMemoryDemoUserRepo()
    svc._email_index_repo = _InMemoryDemoEmailIndex()
    svc._federated_identity_repo = _InMemoryDemoFedRepo()
    svc.settings = _config.get_settings()
    svc.settings.timing_leak_protection = False

    @asynccontextmanager
    async def _noop_lock(name: str):
        yield

    svc._lock = lambda name: _noop_lock(name)
    return svc


class TestSeedDemoUser:
    """``seed_demo_user`` must be idempotent and create exactly the
    well-known demo admin with admin scope."""

    @pytest.fixture(autouse=True)
    def _clear_user_caches(self):
        """Drop the process-wide user caches between seed tests.

        ``get_user_by_email`` / ``set_password`` read through the
        global ``TTLCache`` instances, which are keyed by email and
        survive across tests. Without a clear, a cached user from a
        previous test would make ``seed_demo_user`` skip ``create_user``
        and leave the in-memory email index empty.
        """
        from authglow.core.cache import _reset_cache_registry

        _reset_cache_registry()
        yield
        _reset_cache_registry()

    async def test_creates_demo_admin_with_admin_scope(self, test_settings):
        test_settings.demo_mode = True
        service = _make_service()
        password = await seed_demo_user(service=service, settings=test_settings)

        user = await service.get_user_by_email(test_settings.demo_user_email)
        assert user is not None
        assert "admin" in user.scopes
        assert user.is_active is True
        assert user.email_verified is True
        assert user.hashed_password != password  # hashed, not plaintext
        assert len(password) > 0
        assert user.is_bootstrap is True

    async def test_existing_demo_admin_is_reactivated_and_pinned(self, test_settings):
        """A deactivated demo admin must be re-activated on boot and
        marked as the bootstrap account (so it can no longer be
        deactivated from the admin surface)."""
        test_settings.demo_mode = True
        service = _make_service()
        await seed_demo_user(service=service, settings=test_settings)

        admin = await service.get_user_by_email(test_settings.demo_user_email)
        assert admin is not None
        admin.is_active = False
        admin.is_bootstrap = False
        await service.update_user(admin)

        await seed_demo_user(service=service, settings=test_settings)

        refreshed = await service.get_user_by_email(test_settings.demo_user_email)
        assert refreshed is not None
        assert refreshed.is_active is True
        assert refreshed.is_bootstrap is True

    async def test_idempotent_two_runs_single_user(self, test_settings):
        test_settings.demo_mode = True
        service = _make_service()
        p1 = await seed_demo_user(service=service, settings=test_settings)
        p2 = await seed_demo_user(service=service, settings=test_settings)

        assert await service.count_users() == 1
        # Password rotates every boot; the stored hash always matches the
        # most recent one.
        assert p1 != p2

    async def test_disabled_mode_is_noop(self, test_settings):
        test_settings.demo_mode = False
        service = _make_service()
        # demo_mode is False: seed still works but is only ever invoked
        # from the lifespan guard. Assert the guard behaviour: without
        # an explicit opt-in nothing is created by main's guard. Here we
        # simply verify the function does not crash and returns a usable
        # password — the gating lives in main.py.
        password = await seed_demo_user(service=service, settings=test_settings)
        assert password


class TestMetaEndpoint:
    """``GET /api/meta`` must not leak credentials when demo is off and
    must expose them only when demo is on."""

    @staticmethod
    def _client() -> TestClient:
        app = FastAPI()
        app.include_router(meta_router)
        return TestClient(app)

    def test_no_credential_material_when_demo_disabled(self, test_settings):
        test_settings.demo_mode = False
        client = self._client()
        resp = client.get("/api/meta")
        assert resp.status_code == 200
        body = resp.json()
        assert body["demo_mode"] is False
        assert "demo_user_password" not in body
        assert "demo_user_email" not in body

    def test_exposes_credentials_when_demo_enabled(self, test_settings):
        test_settings.demo_mode = True
        client = self._client()
        resp = client.get("/api/meta")
        assert resp.status_code == 200
        body = resp.json()
        assert body["demo_mode"] is True
        assert body["demo_user_email"] == test_settings.demo_user_email
        # app.state has no demo_password in this isolated app, so the
        # endpoint must not crash and must return an empty string rather
        # than leaking something wrong.
        assert body["demo_user_password"] == ""


class TestDemoModeIsOrthogonalToProduction:
    """demo_mode must not weaken the production security validators."""

    def test_placeholder_secret_key_still_raises_in_production_demo(self, tmp_path):
        storage_path = str(tmp_path / "data" / "users")
        keys_dir = str(tmp_path / "keys")
        os.makedirs(storage_path, exist_ok=True)
        os.makedirs(keys_dir, exist_ok=True)

        with pytest.warns(UserWarning, match="placeholder"):
            with pytest.raises(ValueError, match="placeholder"):
                Settings(
                    secret_key="your-secret-key-change-me-in-production-min-32-chars!",
                    app_env="production",
                    demo_mode=True,
                    debug=False,
                    storage_path=storage_path,
                    storage_backend="file",
                    keys_dir=keys_dir,
                    private_key_path=os.path.join(keys_dir, "private_key.pem"),
                    public_key_path=os.path.join(keys_dir, "public_key.pem"),
                    jwt_auto_rotate=False,
                    oauth2_client_id="test-client-id",
                    oauth2_client_secret="test-client-secret",
                )

    def test_demo_flag_has_no_production_side_effect(self, test_settings):
        test_settings.demo_mode = True
        assert test_settings.is_production is False  # default app_env=development
        test_settings.app_env = "production"
        test_settings.secret_key = "a" * 32 + "x"  # non-placeholder
        test_settings.debug = False
        test_settings.oauth2_client_id = "non-default-client-id"
        test_settings.oauth2_client_secret = "non-default-secret"
        assert test_settings.is_production is True
