"""Tests for the ``@functools.lru_cache`` wrappers in :mod:`authglow.core.crypto`.

These wrappers are pure deterministic functions keyed on
``(secret_key, info)`` (for ``_derive_key``) or ``(email)`` /
``(secret_key, code)`` (for the HMAC helpers). The cache is safe
because the process-wide ``secret_key`` is read from the immutable
``Settings`` singleton; test isolation works because every test gets
its own ``test_settings`` instance and the cache key changes with it.
"""

import pytest

from authglow.core import crypto


@pytest.fixture(autouse=True)
def _clear_crypto_caches():
    """Clear the module-level ``lru_cache`` state between tests so
    counters and contents are predictable. Mirrors the
    ``_reset_jwt_singleton`` / ``_reset_http_client`` pattern from
    the JWTService and httpx singletons.
    """
    yield
    crypto._derive_key.cache_clear()
    crypto.hash_index_key.cache_clear()
    crypto.reset_code_lookup_key.cache_clear()
    crypto.verification_code_lookup_key.cache_clear()


class TestDeriveKeyCaching:
    """``_derive_key`` is deterministic in ``(secret_key, info)`` and
    must be cached via :func:`functools.lru_cache`."""

    def test_derive_key_is_deterministic(self):
        k1 = crypto._derive_key(secret_key="s", info=b"x")
        k2 = crypto._derive_key(secret_key="s", info=b"x")
        assert k1 == k2
        assert isinstance(k1, bytes) and len(k1) == 32

    def test_derive_key_distinct_info_produces_distinct_keys(self):
        k1 = crypto._derive_key(secret_key="s", info=b"info-a")
        k2 = crypto._derive_key(secret_key="s", info=b"info-b")
        assert k1 != k2, "HKDF must produce different keys for different info"

    def test_derive_key_distinct_secret_produces_distinct_keys(self):
        k1 = crypto._derive_key(secret_key="secret-A", info=b"x")
        k2 = crypto._derive_key(secret_key="secret-B", info=b"x")
        assert k1 != k2

    def test_derive_key_caches_results(self):
        crypto._derive_key.cache_clear()
        crypto._derive_key(secret_key="cached-secret", info=b"cached-info")
        before = crypto._derive_key.cache_info()
        crypto._derive_key(secret_key="cached-secret", info=b"cached-info")
        after = crypto._derive_key.cache_info()
        assert after.hits == before.hits + 1, "second call must hit the cache"
        assert after.misses == before.misses, "no new entry on cache hit"

    def test_derive_key_default_sentinel_resolves_secret_key(self):
        """``_derive_key()`` with default arg must read the global
        ``Settings.secret_key`` (no error, deterministic across calls)."""
        k1 = crypto._derive_key()
        k2 = crypto._derive_key()
        assert k1 == k2
        assert len(k1) == 32

    def test_derive_key_maxsize_is_8(self):
        crypto._derive_key.cache_clear()
        for i in range(20):
            crypto._derive_key(secret_key=f"secret-{i}", info=b"x")
        info = crypto._derive_key.cache_info()
        assert info.maxsize == 8
        assert info.currsize <= 8, f"lru_cache must evict down to maxsize=8, got {info.currsize}"


class TestDeriveFederationStateKey:
    """``derive_federation_state_key`` is now a thin wrapper over
    ``_derive_key`` (refactored in Tier 1.4 to remove duplication)."""

    def test_uses_user_info_separation(self):
        federation = crypto.derive_federation_state_key(secret_key="s")
        totp = crypto._derive_key(secret_key="s", info=crypto._INFO)
        assert federation != totp, (
            "federation key must be distinct from TOTP key for the same secret"
        )

    def test_deterministic(self):
        k1 = crypto.derive_federation_state_key(secret_key="s")
        k2 = crypto.derive_federation_state_key(secret_key="s")
        assert k1 == k2


class TestHashIndexKeyCaching:
    """``hash_index_key`` is cached; the email is the cache key."""

    def test_deterministic(self):
        h1 = crypto.hash_index_key("user@example.com")
        h2 = crypto.hash_index_key("user@example.com")
        assert h1 == h2
        assert len(h1) == 64, "SHA-256 hex digest must be 64 chars"

    def test_distinct_emails_produce_distinct_keys(self):
        h1 = crypto.hash_index_key("alice@example.com")
        h2 = crypto.hash_index_key("bob@example.com")
        assert h1 != h2

    def test_caches_results(self):
        crypto.hash_index_key.cache_clear()
        crypto.hash_index_key("cached@example.com")
        before = crypto.hash_index_key.cache_info()
        crypto.hash_index_key("cached@example.com")
        after = crypto.hash_index_key.cache_info()
        assert after.hits == before.hits + 1
        assert after.misses == before.misses


class TestResetCodeLookupKeyCaching:
    """``reset_code_lookup_key`` is cached; (secret_key, code) is the key."""

    def test_normalises_code(self):
        k1 = crypto.reset_code_lookup_key("s", "ABCD-EFGH-JKLM")
        k2 = crypto.reset_code_lookup_key("s", " ABCD-EFGH-JKLM ")
        k3 = crypto.reset_code_lookup_key("s", "abcd-efgh-jklm")
        assert k1 == k2 == k3, "whitespace and case must be stripped"

    def test_distinct_secrets_produce_distinct_keys(self):
        k1 = crypto.reset_code_lookup_key("secret-A", "code-1")
        k2 = crypto.reset_code_lookup_key("secret-B", "code-1")
        assert k1 != k2

    def test_caches_results(self):
        crypto.reset_code_lookup_key.cache_clear()
        crypto.reset_code_lookup_key("s", "code-1")
        before = crypto.reset_code_lookup_key.cache_info()
        crypto.reset_code_lookup_key("s", "code-1")
        after = crypto.reset_code_lookup_key.cache_info()
        assert after.hits == before.hits + 1


class TestVerificationCodeLookupKeyCaching:
    """``verification_code_lookup_key`` mirrors the password-reset helper."""

    def test_normalises_code(self):
        k1 = crypto.verification_code_lookup_key("s", "ABCD-EFGH-JKMN")
        k2 = crypto.verification_code_lookup_key("s", " ABCD-EFGH-JKMN ")
        k3 = crypto.verification_code_lookup_key("s", "abcd-efgh-jkmn")
        assert k1 == k2 == k3

    def test_distinct_secrets_produce_distinct_keys(self):
        k1 = crypto.verification_code_lookup_key("secret-A", "code-1")
        k2 = crypto.verification_code_lookup_key("secret-B", "code-1")
        assert k1 != k2

    def test_caches_results(self):
        crypto.verification_code_lookup_key.cache_clear()
        crypto.verification_code_lookup_key("s", "code-1")
        before = crypto.verification_code_lookup_key.cache_info()
        crypto.verification_code_lookup_key("s", "code-1")
        after = crypto.verification_code_lookup_key.cache_info()
        assert after.hits == before.hits + 1


class TestEndToEndRoundtrip:
    """Sanity: the public encrypt/decrypt API still works after the
    ``lru_cache`` wrappers were added (no behaviour regression)."""

    def test_totp_secret_roundtrip(self):
        c = crypto.encrypt_totp_secret("JBSWY3DPEHPK3PXP")
        assert c.startswith("ag1:")
        assert crypto.decrypt_totp_secret(c) == "JBSWY3DPEHPK3PXP"

    def test_field_roundtrip(self):
        c = crypto.encrypt_field("user@example.com")
        assert c.startswith("ag1:")
        assert crypto.decrypt_field(c) == "user@example.com"

    def test_private_key_roundtrip(self):
        plaintext = b"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
        c = crypto.encrypt_private_key(plaintext, secret_key="k")
        assert c.startswith(b"agk1:")
        assert crypto.decrypt_private_key(c, secret_key="k") == plaintext
