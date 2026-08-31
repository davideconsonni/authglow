"""Unit tests for the safeword generator."""

from __future__ import annotations

import re

from authglow.core.safeword import (
    _EFF_SHORT_WORDLIST,
    generate_safeword,
)


_SAFEWORD_RE = re.compile(r"^[a-z]+-[a-z]+-[a-z]+-\d{2}$")


class TestWordlist:
    def test_wordlist_size_is_251(self):
        """The entropy calculation depends on 251 entries."""
        assert len(_EFF_SHORT_WORDLIST) == 251

    def test_wordlist_entries_are_unique(self):
        assert len(set(_EFF_SHORT_WORDLIST)) == len(_EFF_SHORT_WORDLIST)

    def test_wordlist_entries_are_lowercase_letters_only(self):
        for word in _EFF_SHORT_WORDLIST:
            assert re.match(r"^[a-z]+$", word), f"Bad entry: {word!r}"


class TestGenerateSafeword:
    def test_format_matches_expected_pattern(self):
        word = generate_safeword()
        assert _SAFEWORD_RE.match(word), f"Safeword {word!r} does not match the pattern"

    def test_each_token_comes_from_wordlist_or_is_two_digits(self):
        word = generate_safeword()
        tokens = word.split("-")
        assert len(tokens) == 4
        assert tokens[0] in _EFF_SHORT_WORDLIST
        assert tokens[1] in _EFF_SHORT_WORDLIST
        assert tokens[2] in _EFF_SHORT_WORDLIST
        assert tokens[3].isdigit() and len(tokens[3]) == 2

    def test_two_consecutive_calls_produce_different_values(self):
        # 50 iterations is a sanity check; with ~67 bits of entropy
        # the collision probability is negligible.
        for _ in range(50):
            a = generate_safeword()
            b = generate_safeword()
            assert a != b, "Safeword generator returned duplicates"

    def test_bulk_uniqueness(self):
        # 1000 unique values exercises the 67-bit entropy range.
        results = {generate_safeword() for _ in range(1000)}
        assert len(results) == 1000

    def test_digits_are_zero_padded(self):
        # We can't easily force ``secrets.randbelow(100)`` to return
        # 5, but we can run the generator many times and check that
        # the last token is always 2 characters wide.
        for _ in range(100):
            word = generate_safeword()
            digits = word.split("-")[3]
            assert len(digits) == 2
