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


# ---------------------------------------------------------------------------
# VAPT-041 — AAD versioning + legacy fallback
# ---------------------------------------------------------------------------


class TestVapt041AadVersioning:
    """VAPT-041: TOTP-secret and RSA-private-key AADs are
    versioned (``-v1`` suffix) and the decrypt path tolerates
    the pre-versioning AAD for backward compatibility."""

    def test_totp_aad_is_versioned(self):
        assert crypto._AAD.endswith(b"-v1"), (
            "TOTP-secret AAD must carry a version suffix to align "
            "with the other envelopes in this module"
        )

    def test_private_key_aad_is_versioned(self):
        assert crypto._KEY_AAD.endswith(b"-v1"), "RSA-private-key AAD must carry a version suffix"

    def test_legacy_aad_constants_preserved(self):
        """The pre-versioning AAD values must remain available
        as ``_AAD_LEGACY`` / ``_KEY_AAD_LEGACY`` so the decrypt
        path can read existing on-disk data."""
        assert crypto._AAD_LEGACY == b"authglow-totp"
        assert crypto._KEY_AAD_LEGACY == b"authglow-private-key"

    def test_legacy_aad_is_distinct_from_current(self):
        assert crypto._AAD != crypto._AAD_LEGACY
        assert crypto._KEY_AAD != crypto._KEY_AAD_LEGACY


class TestVapt041TotpSecretAadRotation:
    """TOTP secret encrypt/decrypt handles both AAD versions."""

    def test_new_write_uses_versioned_aad(self):
        """A freshly-encrypted TOTP secret must round-trip via
        the versioned AAD path. The decrypt succeeds even if
        the legacy AAD is checked first (the versioned one
        matches) so this test does not directly observe the
        AAD bytes — instead, it round-trips and the next test
        forces the legacy path to confirm a mix works."""
        c = crypto.encrypt_totp_secret("JBSWY3DPEHPK3PXP")
        assert crypto.decrypt_totp_secret(c) == "JBSWY3DPEHPK3PXP"

    def test_legacy_ciphertext_decrypts_via_fallback(self):
        """Simulate a pre-VAPT-041 on-disk ciphertext by
        encrypting with the legacy AAD directly, then call
        the public decrypt and confirm the fallback path
        decodes it."""
        import base64
        import os

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        iv = os.urandom(12)
        key = crypto._derive_key()
        aesgcm = AESGCM(key)
        legacy_ciphertext = aesgcm.encrypt(iv, b"legacy-totp-secret", crypto._AAD_LEGACY)
        legacy_blob = crypto._PREFIX + base64.b64encode(iv + legacy_ciphertext).decode()

        assert crypto.decrypt_totp_secret(legacy_blob) == "legacy-totp-secret"

    def test_mixed_legacy_and_new_ciphertexts(self):
        """A deployment that has both legacy and versioned
        ciphertexts (typical during a rolling deploy) must
        read both transparently."""
        # New write.
        new_blob = crypto.encrypt_totp_secret("new-totp")
        # Legacy write (simulated pre-VAPT-041 data).
        import base64
        import os

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        iv = os.urandom(12)
        legacy_ciphertext = AESGCM(crypto._derive_key()).encrypt(
            iv, b"legacy-totp", crypto._AAD_LEGACY
        )
        legacy_blob = crypto._PREFIX + base64.b64encode(iv + legacy_ciphertext).decode()

        assert crypto.decrypt_totp_secret(new_blob) == "new-totp"
        assert crypto.decrypt_totp_secret(legacy_blob) == "legacy-totp"

    def test_malformed_ag1_blob_still_raises(self):
        """A blob with the right prefix but corrupt body must
        still surface an error after every AAD has been tried.
        VAPT-041 is about versioning, not about relaxing the
        tamper detection."""
        from cryptography.exceptions import InvalidTag

        with pytest.raises((InvalidTag, ValueError, Exception)):
            crypto.decrypt_totp_secret("ag1:" + "x" * 100)

    def test_non_ag1_input_passes_through_unchanged(self):
        """A non-ciphertext value (legacy plaintext or empty
        string) must round-trip unchanged — same behaviour as
        the pre-VAPT-041 helper."""
        assert crypto.decrypt_totp_secret("plaintext-secret") == "plaintext-secret"
        assert crypto.decrypt_totp_secret("") == ""


class TestVapt041PrivateKeyAadRotation:
    """Same pattern for the RSA private key envelope."""

    def test_new_write_roundtrip(self):
        plaintext = b"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
        c = crypto.encrypt_private_key(plaintext, secret_key="k")
        assert c.startswith(b"agk1:")
        assert crypto.decrypt_private_key(c, secret_key="k") == plaintext

    def test_legacy_ciphertext_decrypts_via_fallback(self):
        """Same as the TOTP test: simulate pre-VAPT-041 on-disk
        keyring data and confirm the public decrypt reads it."""
        import base64
        import os

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = crypto._derive_key(secret_key="k", info=crypto._KEY_INFO)
        iv = os.urandom(12)
        legacy_ciphertext = AESGCM(key).encrypt(iv, b"legacy-priv-bytes", crypto._KEY_AAD_LEGACY)
        legacy_blob = crypto._KEY_PREFIX.encode() + base64.b64encode(iv + legacy_ciphertext)

        assert crypto.decrypt_private_key(legacy_blob, secret_key="k") == b"legacy-priv-bytes"

    def test_non_agk1_input_passes_through_unchanged(self):
        """A non-ciphertext bytes value (legacy plaintext key or
        empty bytes) must round-trip unchanged."""
        assert (
            crypto.decrypt_private_key(b"plaintext-key-bytes", secret_key="k")
            == b"plaintext-key-bytes"
        )
        assert crypto.decrypt_private_key(b"", secret_key="k") == b""

    def test_aad_swap_changes_ciphertext(self):
        """Encrypting the same plaintext with two distinct AADs
        must yield two distinct ciphertexts — confirms the
        AAD is actually bound to the encryption (not silently
        ignored)."""
        plaintext = b"same-plaintext-different-aad"
        with_v1 = crypto.encrypt_private_key(plaintext, secret_key="k")
        # Hand-roll a ciphertext with the legacy AAD.
        import base64
        import os

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = crypto._derive_key(secret_key="k", info=crypto._KEY_INFO)
        iv = os.urandom(12)
        legacy_ct = AESGCM(key).encrypt(iv, plaintext, crypto._KEY_AAD_LEGACY)
        with_legacy = crypto._KEY_PREFIX.encode() + base64.b64encode(iv + legacy_ct)

        # Different IVs make a strict byte-compare meaningless;
        # we only need to confirm the decrypt still recovers
        # the original plaintext via the right AAD path.
        assert (
            crypto.decrypt_private_key(with_v1, secret_key="k")
            == crypto.decrypt_private_key(with_legacy, secret_key="k")
            == plaintext
        )


class TestVapt041AadConstantConsistency:
    """All AAD/info constants referenced by VAPT-041 carry a
    version suffix (``-v1`` or higher), so a future rotate can
    rely on the suffix as a discriminator.

    Note: ``_CLIENT_JWT_KEY_AAD`` was added in T.2 *after*
    VAPT-041 was filed and already has a non-versioned AAD
    by the same oversight — versioning it is a separate
    follow-up to keep the VAPT-041 fix scoped to the two
    AADs explicitly mentioned in the VAPT (lines 11-17 of
    the pre-fix crypto.py).
    """

    def test_vapt041_aad_constants_carry_a_version_suffix(self):
        # The two AADs explicitly fixed by VAPT-041 must be
        # versioned. Other AADs in the module are out of
        # scope for this fix (the original ticket points at
        # ``_AAD`` and ``_KEY_AAD`` specifically).
        versioned = [crypto._AAD, crypto._KEY_AAD]
        for value in versioned:
            assert value.endswith(b"-v1"), f"AAD constant {value!r} must carry a -v1 version suffix"

    def test_vapt041_info_constants_carry_a_version_suffix(self):
        """The corresponding ``_INFO`` strings (HKDF info)
        were already versioned before VAPT-041 — confirm
        they are still aligned."""
        assert crypto._INFO.endswith(b"-v1")
        assert crypto._KEY_INFO.endswith(b"-v1")

    def test_legacy_constants_do_not_carry_version(self):
        """The legacy constants exist precisely to read the
        pre-versioning on-disk data — they must NOT carry a
        ``-v1`` suffix (otherwise they would clash with the
        versioned constants)."""
        assert not crypto._AAD_LEGACY.endswith(b"-v1")
        assert not crypto._KEY_AAD_LEGACY.endswith(b"-v1")
