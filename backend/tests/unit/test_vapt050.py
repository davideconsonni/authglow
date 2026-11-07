"""Tests for VAPT-050 timing equalization on unknown-user credential paths.

The dummy-bcrypt machinery must (1) always fail, (2) cost the configured
bcrypt so the latency is indistinguishable from a real verify, and (3) be
dispatched by the patched endpoints before rejecting an unknown email.
The ``authorize_post`` assertion is source-order based, following the
established pattern in ``test_vapt048.py``.
"""

import asyncio
import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import Request

from authglow.services.password import (
    _extract_bcrypt_rounds,
    get_bcrypt_rounds,
    get_dummy_hash,
    verify_dummy_password_async,
)


def _run(coro):
    return asyncio.run(coro)


class TestDummyCredential:
    def test_dummy_hash_is_bcrypt_at_configured_cost(self):
        hashed = get_dummy_hash()
        assert hashed.startswith("$2")
        assert _extract_bcrypt_rounds(hashed) == get_bcrypt_rounds()

    def test_dummy_hash_cached_per_cost(self):
        assert get_dummy_hash() is get_dummy_hash()

    def test_dummy_verify_always_fails(self):
        assert _run(verify_dummy_password_async("anything")) is False


class TestChangeExpiredPasswordEqualization:
    """``change_expired_password`` must pay bcrypt for unknown emails too."""

    def _call(self, monkeypatch, *, gate: bool, user):
        from authglow.api import password_reset as pr_api
        from authglow.models.password_reset import ExpiredPasswordChange

        monkeypatch.setattr(pr_api, "settings", SimpleNamespace(timing_leak_protection=gate))
        dummy = AsyncMock(return_value=False)
        monkeypatch.setattr(pr_api, "verify_dummy_password_async", dummy)

        storage = MagicMock()
        storage.get_user_by_email = AsyncMock(return_value=user)
        audit = MagicMock()
        audit.log_event = AsyncMock()

        payload = ExpiredPasswordChange(
            email="ghost@example.com",
            current_password="wrong-password",
            new_password="brand-new-password",
        )
        request = Request({"type": "http", "method": "POST", "path": "", "headers": []})
        request.state.view_rate_limit = None

        with pytest.raises(Exception) as excinfo:
            _run(pr_api.change_expired_password(request, payload, storage, audit, MagicMock()))
        return excinfo.value, dummy, audit

    def test_unknown_user_pays_dummy_when_protection_on(self, monkeypatch):
        error, dummy, _audit = self._call(monkeypatch, gate=True, user=None)
        assert getattr(error, "status_code", None) == 401
        dummy.assert_awaited_once_with("wrong-password")

    def test_unknown_user_skips_dummy_when_protection_off(self, monkeypatch):
        error, dummy, _audit = self._call(monkeypatch, gate=False, user=None)
        assert getattr(error, "status_code", None) == 401
        dummy.assert_not_awaited()

    def test_existing_user_verifies_without_dummy(self, monkeypatch):
        from authglow.api import password_reset as pr_api

        user = SimpleNamespace(
            id="u-1",
            email="ghost@example.com",
            hashed_password="$2b$04$invalidbutunused",
            is_active=True,
        )
        verify = AsyncMock(return_value=False)
        monkeypatch.setattr(pr_api, "verify_password_async", verify)
        error, dummy, _audit = self._call(monkeypatch, gate=True, user=user)
        assert getattr(error, "status_code", None) == 401
        # A real verify was paid: no dummy on top, and the audit
        # still records invalid_credentials (unchanged envelope).
        dummy.assert_not_awaited()
        verify.assert_awaited_once()


class TestAuthorizePostEqualization:
    """The login path must dispatch the dummy before the unknown-user 401."""

    def test_dummy_precedes_unknown_user_rejection(self):
        from authglow.api.auth import authorize_post

        source = inspect.getsource(authorize_post)
        dummy_pos = source.find("verify_dummy_password_async(password)")
        assert dummy_pos != -1, "dummy bcrypt missing from authorize_post"
        lockout_pos = source.find("is_account_locked")
        assert lockout_pos == -1 or dummy_pos < lockout_pos, (
            "the unknown-user dummy must sit in the early not-found branch, "
            "before the user-exists lockout check"
        )
        # Same gate as the storage-layer read padding.
        assert "timing_leak_protection" in source
