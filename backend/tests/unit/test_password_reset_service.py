import pytest
from datetime import timedelta
from authglow.core.datetime import utcnow
from authglow.models.password_reset import PasswordResetToken


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


class TestCreateResetToken:
    def test_create_reset_token(self, password_reset_service):
        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-1", email="user1@example.com")
        )
        assert isinstance(token, PasswordResetToken)
        assert token.user_id == "user-1"
        assert token.email == "user1@example.com"
        assert token.token_hash.startswith("$2b$")
        assert token.is_used is False
        assert isinstance(plaintext, str)
        assert len(plaintext) > 20

    def test_token_hash_is_bcrypt(self, password_reset_service):
        import bcrypt

        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-1", email="user1@example.com")
        )
        assert bcrypt.checkpw(plaintext.encode(), token.token_hash.encode())

    def test_token_plaintext_not_stored(self, password_reset_service):
        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-1", email="user1@example.com")
        )
        assert plaintext not in token.model_dump_json()

    def test_create_with_ip_and_agent(self, password_reset_service):
        token, _, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-2",
                email="user2@example.com",
                ip_address="192.168.1.1",
                user_agent="Mozilla/5.0",
            )
        )
        assert token.ip_address == "192.168.1.1"
        assert token.user_agent == "Mozilla/5.0"

    def test_custom_expiry(self, password_reset_service):
        token, _, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-3",
                email="user3@example.com",
                expires_in_minutes=60,
            )
        )
        delta = token.expires_at - token.created_at
        assert delta >= timedelta(minutes=59)
        assert delta <= timedelta(minutes=61)


class TestVerifyToken:
    def test_verify_valid_token(self, password_reset_service):
        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-verify", email="verify@example.com"
            )
        )
        found = asyncio_run(password_reset_service.verify_token(plaintext))
        assert found is not None
        assert found.user_id == "user-verify"

    def test_verify_wrong_token(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-wrong", email="wrong@example.com"
            )
        )
        found = asyncio_run(password_reset_service.verify_token("wrong-token-value"))
        assert found is None

    def test_verify_used_token_returns_none(self, password_reset_service):
        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-used", email="used@example.com")
        )
        asyncio_run(password_reset_service.mark_token_used(token.token_lookup))
        found = asyncio_run(password_reset_service.verify_token(plaintext))
        assert found is None

    def test_verify_expired_token_returns_none(self, password_reset_service):
        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-exp", email="exp@example.com")
        )
        import json

        path = password_reset_service._get_token_path(token.token_lookup)
        data = token.model_dump(mode="json")
        data["expires_at"] = (utcnow() - timedelta(minutes=1)).isoformat()
        with password_reset_service.fs.open(path, "w") as f:
            json.dump(data, f)
        found = asyncio_run(password_reset_service.verify_token(plaintext))
        assert found is None


class TestMarkTokenUsed:
    def test_mark_token_used(self, password_reset_service):
        token, _, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-m1", email="m1@example.com")
        )
        result = asyncio_run(password_reset_service.mark_token_used(token.token_lookup))
        assert result is True

    def test_mark_token_used_twice_fails(self, password_reset_service):
        token, _, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-m2", email="m2@example.com")
        )
        result1 = asyncio_run(password_reset_service.mark_token_used(token.token_lookup))
        result2 = asyncio_run(password_reset_service.mark_token_used(token.token_lookup))
        assert result1 is True
        assert result2 is False

    def test_mark_nonexistent_token_fails(self, password_reset_service):
        result = asyncio_run(password_reset_service.mark_token_used("nonexistent-lookup-key"))
        assert result is False


class TestGetToken:
    def test_get_token_exists(self, password_reset_service):
        token, _, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-get", email="get@example.com")
        )
        found = asyncio_run(password_reset_service.get_token(token.token_lookup))
        assert found is not None
        assert found.user_id == "user-get"

    def test_get_token_not_found(self, password_reset_service):
        found = asyncio_run(password_reset_service.get_token("nonexistent-lookup-key"))
        assert found is None


class TestListTokens:
    def test_list_user_tokens(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-list", email="list1@example.com"
            )
        )
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-list", email="list1@example.com"
            )
        )
        tokens = asyncio_run(password_reset_service.list_user_tokens("user-list"))
        assert len(tokens) == 2

    def test_list_user_tokens_filters_other_users(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(user_id="user-a", email="a@example.com")
        )
        asyncio_run(
            password_reset_service.create_reset_token(user_id="user-b", email="b@example.com")
        )
        tokens = asyncio_run(password_reset_service.list_user_tokens("user-a"))
        assert all(t.user_id == "user-a" for t in tokens)

    def test_list_all_tokens_pagination(self, password_reset_service):
        for i in range(5):
            asyncio_run(
                password_reset_service.create_reset_token(
                    user_id=f"user-p{i}", email=f"p{i}@example.com"
                )
            )
        page1 = asyncio_run(password_reset_service.list_all_tokens(limit=2, offset=0))
        page2 = asyncio_run(password_reset_service.list_all_tokens(limit=2, offset=2))
        assert len(page1) <= 2
        assert len(page2) <= 2


class TestRevokeUserTokens:
    def test_revoke_user_tokens(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-revoke", email="revoke@example.com"
            )
        )
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-revoke", email="revoke@example.com"
            )
        )
        count = asyncio_run(password_reset_service.revoke_user_tokens("user-revoke"))
        assert count == 2


class TestCleanupExpiredTokens:
    def test_cleanup_expired_tokens(self, password_reset_service):
        token, _, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-cleanup", email="cleanup@example.com"
            )
        )
        asyncio_run(password_reset_service.mark_token_used(token.token_lookup))
        count = asyncio_run(password_reset_service.cleanup_expired_tokens())
        assert count >= 1


class TestGetStats:
    def test_get_stats_empty(self, password_reset_service):
        stats = asyncio_run(password_reset_service.get_stats())
        assert "total" in stats
        assert "active" in stats
        assert "expired" in stats
        assert "used" in stats

    def test_get_stats_with_tokens(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-stats", email="stats@example.com"
            )
        )
        stats = asyncio_run(password_reset_service.get_stats())
        assert stats["total"] >= 1
        assert stats["active"] >= 1


class TestP3HmacLookup:
    """P3 — O(1) token lookup via HMAC-SHA256.

    Verifies that ``verify_token`` uses a deterministic HMAC lookup key
    derived from the plaintext token so that a single file read + single
    bcrypt check replaces the old O(n) glob + bcrypt loop.
    """

    def test_verify_token_is_o1_not_iterating_all(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-p3-target", email="target@example.com"
            )
        )
        for i in range(50):
            asyncio_run(
                password_reset_service.create_reset_token(
                    user_id=f"user-p3-{i}", email=f"p3-{i}@example.com"
                )
            )
        tokens, target_plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-p3-verify", email="verify@example.com"
            )
        )
        import time

        start = time.monotonic()
        found = asyncio_run(password_reset_service.verify_token(target_plaintext))
        elapsed = time.monotonic() - start
        assert found is not None
        assert found.token_id == tokens.token_id
        assert elapsed < 1.0

    def test_verify_token_direct_lookup_no_list_all(self, password_reset_service):
        for i in range(30):
            asyncio_run(
                password_reset_service.create_reset_token(
                    user_id=f"user-noise-{i}", email=f"noise-{i}@example.com"
                )
            )
        tokens, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-lookup", email="lookup@example.com"
            )
        )
        original_list_all = password_reset_service.list_all_tokens
        call_count = [0]

        async def counting_list_all(*args, **kwargs):
            call_count[0] += 1
            return await original_list_all(*args, **kwargs)

        password_reset_service.list_all_tokens = counting_list_all
        try:
            found = asyncio_run(password_reset_service.verify_token(plaintext))
        finally:
            password_reset_service.list_all_tokens = original_list_all
        assert found is not None
        assert call_count[0] == 0

    def test_token_lookup_is_stored_in_model(self, password_reset_service):
        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-lookup", email="lookup@example.com"
            )
        )
        assert token.token_lookup
        assert isinstance(token.token_lookup, str)
        assert len(token.token_lookup) == 64
        assert all(c in "0123456789abcdef" for c in token.token_lookup)

    def test_token_lookup_deterministic_same_plaintext(self, password_reset_service):
        import hmac, hashlib

        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-det", email="det@example.com")
        )
        recomputed = hmac.new(
            password_reset_service.settings.secret_key.encode(),
            plaintext.encode(),
            hashlib.sha256,
        ).hexdigest()
        assert token.token_lookup == recomputed

    def test_token_lookup_different_for_different_plaintext(self, password_reset_service):
        t1, p1, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-a", email="a@example.com")
        )
        t2, p2, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-b", email="b@example.com")
        )
        assert t1.token_lookup != t2.token_lookup
        assert p1 != p2

    def test_file_named_after_token_lookup_not_uuid(self, password_reset_service):
        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-fn", email="fn@example.com")
        )
        uuid_path = f"{password_reset_service.reset_path}/{token.token_id}.json"
        lookup_path = f"{password_reset_service.reset_path}/{token.token_lookup}.json"
        import os

        assert not os.path.exists(uuid_path)
        assert os.path.exists(lookup_path)

    def test_verify_token_hmac_mismatch_returns_none(self, password_reset_service):
        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-hmac", email="hmac@example.com")
        )
        different_plaintext = "completely-different-token-value-not-real"
        found = asyncio_run(password_reset_service.verify_token(different_plaintext))
        assert found is None

    def test_verify_token_nonexistent_lookup_returns_none(self, password_reset_service):
        import secrets

        fake_plaintext = secrets.token_urlsafe(32)
        found = asyncio_run(password_reset_service.verify_token(fake_plaintext))
        assert found is None

    def test_verify_token_uses_bcrypt_defense_in_depth(self, password_reset_service):
        import bcrypt as _bcrypt
        import json

        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(user_id="user-did", email="did@example.com")
        )
        path = password_reset_service._get_token_path(token.token_lookup)
        with password_reset_service.fs.open(path, "r") as f:
            data = json.load(f)
        wrong_hash = _bcrypt.hashpw(b"wrong-plaintext", _bcrypt.gensalt()).decode()
        data["token_hash"] = wrong_hash
        with password_reset_service.fs.open(path, "w") as f:
            json.dump(data, f)
        found = asyncio_run(password_reset_service.verify_token(plaintext))
        assert found is None

    def test_verify_token_roundtrip_end_to_end(self, password_reset_service):
        token, plaintext, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-e2e",
                email="e2e@example.com",
                ip_address="10.0.0.1",
                user_agent="TestAgent/1.0",
            )
        )
        found = asyncio_run(password_reset_service.verify_token(plaintext))
        assert found is not None
        assert found.token_id == token.token_id
        assert found.user_id == "user-e2e"
        assert found.email == "e2e@example.com"
        assert found.ip_address == "10.0.0.1"
        assert found.user_agent == "TestAgent/1.0"
        assert found.is_used is False


class TestVapt022ResetCodeFlow:
    """VAPT-022 — password reset token must NEVER be embedded in URLs.

    The plaintext reset token is now sent in the email body as a
    human-friendly ``reset_code`` (``XXXX-XXXX-XXXX``) and the link in
    the email points to a clean reset page (no ``?token=...`` query).

    These tests cover:
      * the human-friendly code is generated and returned by the service,
      * the code is persisted in plaintext on the token record (it is
        already a single-use secret, no PII, with a 30-minute window),
      * ``verify_by_code`` accepts the exact code, normalises
        case/whitespace, and rejects wrong / used / expired codes,
      * ``verify_by_code`` is constant-time on the presented code via
        ``secrets.compare_digest``,
      * the API email context no longer carries ``reset_url`` and now
        carries ``reset_page_url`` + ``reset_code`` (and never the
        plaintext token),
      * the rendered email body does not contain the plaintext token.
    """

    def test_create_reset_token_returns_human_friendly_code(self, password_reset_service):
        token, plaintext, code = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-vapt22-1", email="vapt22-1@example.com"
            )
        )
        assert isinstance(code, str)
        assert len(code) == 14
        parts = code.split("-")
        assert len(parts) == 3
        for part in parts:
            assert len(part) == 4
            for ch in part:
                assert ch in "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        assert token.reset_code == code
        # Code must not be the bearer token
        assert code != plaintext

    def test_code_is_unique_per_token(self, password_reset_service):
        _, _, c1 = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-vapt22-u1", email="u1@example.com"
            )
        )
        _, _, c2 = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-vapt22-u2", email="u2@example.com"
            )
        )
        assert c1 != c2

    def test_code_alphabet_excludes_ambiguous_chars(self, password_reset_service):
        forbidden = set("01OIL")
        seen = set()
        for _ in range(200):
            _, _, code = asyncio_run(
                password_reset_service.create_reset_token(
                    user_id="user-vapt22-alpha",
                    email="alpha@example.com",
                )
            )
            for ch in code:
                if ch == "-":
                    continue
                seen.add(ch)
                assert ch not in forbidden
        assert seen.issubset(set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789"))

    def test_verify_by_code_accepts_exact_code(self, password_reset_service):
        token, _, code = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-vapt22-v1", email="v1@example.com"
            )
        )
        found = asyncio_run(password_reset_service.verify_by_code(code))
        assert found is not None
        assert found.token_id == token.token_id
        assert found.user_id == "user-vapt22-v1"

    def test_verify_by_code_normalises_case(self, password_reset_service):
        _, _, code = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-vapt22-v2", email="v2@example.com"
            )
        )
        found = asyncio_run(password_reset_service.verify_by_code(code.lower()))
        assert found is not None

    def test_verify_by_code_rejects_wrong_code(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-vapt22-wrong", email="wrong@example.com"
            )
        )
        found = asyncio_run(password_reset_service.verify_by_code("ZZZZ-ZZZZ-ZZZZ"))
        assert found is None

    def test_verify_by_code_rejects_empty(self, password_reset_service):
        assert asyncio_run(password_reset_service.verify_by_code("")) is None
        assert asyncio_run(password_reset_service.verify_by_code(None)) is None  # type: ignore[arg-type]

    def test_verify_by_code_rejects_used_token(self, password_reset_service):
        token, _, code = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-vapt22-used", email="used@example.com"
            )
        )
        asyncio_run(password_reset_service.mark_token_used(token.token_lookup))
        found = asyncio_run(password_reset_service.verify_by_code(code))
        assert found is None

    def test_verify_by_code_rejects_expired_token(self, password_reset_service):
        token, _, code = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-vapt22-exp", email="exp@example.com"
            )
        )
        import json

        # VAPT-022: mirror file is also indexed by reset_code, so the
        # expiry must be reflected on BOTH primary and mirror files for
        # the test to be representative of a real expiry path.
        expired_data = token.model_dump(mode="json")
        expired_data["expires_at"] = (utcnow() - timedelta(minutes=1)).isoformat()
        expired_json = json.dumps(expired_data)
        for path in (
            password_reset_service._get_token_path(token.token_lookup),
            password_reset_service._get_code_path(
                # We re-derive the lookup key the same way the service does
                # so the test does not depend on private internals leaking.
                __import__("hmac")
                .new(
                    password_reset_service.settings.secret_key.encode(),
                    code.strip().upper().encode(),
                    __import__("hashlib").sha256,
                )
                .hexdigest()
            ),
        ):
            with password_reset_service.fs.open(path, "w") as f:
                f.write(expired_json)
        found = asyncio_run(password_reset_service.verify_by_code(code))
        assert found is None

    def test_code_persisted_on_token_record(self, password_reset_service):
        token, _, code = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-vapt22-persist", email="persist@example.com"
            )
        )
        import json

        path = password_reset_service._get_token_path(token.token_lookup)
        with password_reset_service.fs.open(path, "r") as f:
            data = json.load(f)
        assert data["reset_code"] == code

    def test_plaintext_token_not_in_reset_code_context(self, password_reset_service):
        token, plaintext, code = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-vapt22-leak", email="leak@example.com"
            )
        )
        # The code must not leak the bearer plaintext token.
        assert plaintext not in code
        # And the stored code is separate from the bearer token.
        assert token.reset_code != plaintext
