"""Tests for CSRF token service and form protection."""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


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


class TestCSRFTokenService:
    """Unit tests for CSRFTokenService."""

    def test_new_token_is_random(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            t1 = svc._new_token()
            t2 = svc._new_token()
            assert t1 != t2
            assert len(t1) >= 32

    def test_new_session_id_is_random(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            s1 = svc._new_session_id()
            s2 = svc._new_session_id()
            assert s1 != s2
            assert len(s1) >= 32

    def test_generate_token_stores_file(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-abc"
            token = asyncio_run(svc.generate_token(session_id))

            assert token is not None
            assert len(token) >= 32

            lookup = svc._compute_lookup(session_id)
            path = f"{svc.storage_path}/{lookup}.json"
            data = json.loads(svc.fs.cat(path))
            assert data["token_hash"] == svc._hash_token(token)
            assert "expires_at" in data
            assert data["expires_at"] > time.time()

    def test_validate_correct_token(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-validate"
            token = asyncio_run(svc.generate_token(session_id))

            result = asyncio_run(svc.validate_token(session_id, token))
            assert result is True

    def test_validate_wrong_token(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-wrong"
            asyncio_run(svc.generate_token(session_id))

            result = asyncio_run(svc.validate_token(session_id, "wrong-token"))
            assert result is False

    def test_validate_wrong_session(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-1"
            token = asyncio_run(svc.generate_token(session_id))

            result = asyncio_run(svc.validate_token("different-session", token))
            assert result is False

    def test_validate_nonexistent_session(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            result = asyncio_run(svc.validate_token("nonexistent", "some-token"))
            assert result is False

    def test_token_expiry(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-expired"
            token = asyncio_run(svc.generate_token(session_id))

            lookup = svc._compute_lookup(session_id)
            path = f"{svc.storage_path}/{lookup}.json"
            data = json.loads(svc.fs.cat(path))
            data["expires_at"] = time.time() - 60
            svc.fs.pipe(path, json.dumps(data).encode())

            result = asyncio_run(svc.validate_token(session_id, token))
            assert result is False

    def test_generate_replaces_existing_token(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-replace"
            token1 = asyncio_run(svc.generate_token(session_id))
            token2 = asyncio_run(svc.generate_token(session_id))

            assert token1 != token2
            assert not asyncio_run(svc.validate_token(session_id, token1))
            assert asyncio_run(svc.validate_token(session_id, token2))

    """Security-specific tests for CSRF tokens."""

    def test_token_length_meets_remediation_spec(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            token = svc._new_token()

            decoded_len = len(token)
            assert decoded_len >= 32, (
                f"Token too short: {decoded_len} chars; spec says token_urlsafe(32)"
            )

    def test_token_generated_has_tags_and_signals(self, test_settings):
        from authglow.services.csrf import CSRFTokenService
        import re

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            tokens = [svc._new_token() for _ in range(20)]

            for t in tokens:
                assert not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}", t), (
                    f"Token {t[:8]}... looks like a UUID4 prefix -- "
                    "must use token_urlsafe, not uuid4"
                )

    def test_token_not_empty_string(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            for _ in range(10):
                t = svc._new_token()
                assert t.strip(), "Token must not be empty/whitespace"
                assert "\n" not in t, "Token must not contain newlines"
                assert "\0" not in t, "Token must not contain null bytes"
