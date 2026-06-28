"""Tests for ``authglow.core.pii`` — PII masking helpers (VAPT-081)."""


class TestHashPii:
    """``hash_pii`` produces a stable 16-char hex digest keyed with
    the application secret. Not reversible."""

    def test_hash_pii_returns_16_hex_chars(self):
        from authglow.core.pii import hash_pii

        h = hash_pii("john.doe@example.com", "secret-key")
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_pii_deterministic(self):
        """Same input + same key = same hash (so events for the
        same value can be grouped)."""
        from authglow.core.pii import hash_pii

        a = hash_pii("john.doe@example.com", "secret-key")
        b = hash_pii("john.doe@example.com", "secret-key")
        assert a == b

    def test_hash_pii_case_insensitive(self):
        """Email casing is normalized before hashing."""
        from authglow.core.pii import hash_pii

        a = hash_pii("John.Doe@Example.com", "secret-key")
        b = hash_pii("john.doe@example.com", "secret-key")
        assert a == b

    def test_hash_pii_different_keys_different_hash(self):
        from authglow.core.pii import hash_pii

        a = hash_pii("john.doe@example.com", "key-1")
        b = hash_pii("john.doe@example.com", "key-2")
        assert a != b

    def test_hash_pii_empty_returns_empty(self):
        from authglow.core.pii import hash_pii

        assert hash_pii("", "key") == ""
        assert hash_pii(None, "key") == ""


class TestMaskIp:
    """``mask_ip`` truncates IP addresses to ``/24`` (v4) or
    ``/48`` (v6)."""

    def test_mask_ipv4_to_slash_24(self):
        from authglow.core.pii import mask_ip

        assert mask_ip("1.2.3.4") == "1.2.3.0/24"
        assert mask_ip("192.168.1.100") == "192.168.1.0/24"

    def test_mask_ipv6_to_slash_48(self):
        from authglow.core.pii import mask_ip

        result = mask_ip("2001:db8:0:0:0:0:0:1")
        assert result.startswith("2001:db8:")
        assert "/48" in result

    def test_mask_ip_invalid_returns_placeholder(self):
        from authglow.core.pii import mask_ip

        assert mask_ip("not-an-ip") == "[invalid_ip]"

    def test_mask_ip_empty(self):
        """``None`` is returned as-is (caller can distinguish
        "no IP recorded" from "invalid IP"). Empty string is
        also returned as-is.
        """
        from authglow.core.pii import mask_ip

        assert mask_ip("") == ""
        assert mask_ip(None) is None


class TestTruncate:
    """``truncate`` caps string length with a marker."""

    def test_truncate_short_unchanged(self):
        from authglow.core.pii import truncate

        assert truncate("hello") == "hello"

    def test_truncate_long_clipped(self):
        from authglow.core.pii import truncate

        result = truncate("x" * 500)
        assert result.endswith("\u2026[truncated]")
        assert len(result) <= 256

    def test_truncate_hard_when_max_len_smaller_than_marker(self):
        from authglow.core.pii import truncate

        result = truncate("abcdefghij", max_len=5)
        assert result == "abcde"
        assert len(result) == 5

    def test_truncate_non_string_unchanged(self):
        from authglow.core.pii import truncate

        assert truncate(None) is None
        assert truncate(42) == 42
