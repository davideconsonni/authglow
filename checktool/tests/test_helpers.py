"""Unit tests for the pure checktool helpers."""

from checktool.helpers import extract_code, items_of, mask_secret, newest_email_code


class TestMaskSecret:
    def test_keeps_short_prefix(self):
        assert mask_secret("supersecretvalue") == "supers…***"

    def test_short_value_fully_masked(self):
        assert mask_secret("abc") == "***"

    def test_custom_visible(self):
        assert mask_secret("abcdefgh", visible=2) == "ab…***"


class TestExtractCode:
    def test_extracts_human_friendly_code(self):
        assert extract_code("Your code is 7F3K-9PQR-2MTX to continue") == "7F3K-9PQR-2MTX"

    def test_lowercase_is_normalised(self):
        assert extract_code("code: 7f3k-9pqr-2mtx") == "7F3K-9PQR-2MTX"

    def test_absent_returns_none(self):
        assert extract_code("no code here") is None
        assert extract_code("") is None
        assert extract_code(None) is None

    def test_ignores_wrong_shape(self):
        assert extract_code("1234-5678") is None
        assert extract_code("ABCD-EFGH-IJKL-MNOP") is None


class TestNewestEmailCode:
    def test_picks_newest_email_with_a_code(self):
        body = {
            "emails": [
                {"body_text": "header only, no code"},
                {"body_text": "verify with 2ABC-3DEF-4GHJ now"},
                {"body_text": "older 5KLM-6NPQ-7RST code"},
            ]
        }
        assert newest_email_code(body) == "2ABC-3DEF-4GHJ"

    def test_missing_shape_returns_none(self):
        assert newest_email_code({}) is None
        assert newest_email_code({"emails": []}) is None
        assert newest_email_code({"emails": [{"body_text": "none"}]}) is None
        assert newest_email_code("not a dict") is None


class TestItemsOf:
    def test_paginated_envelope(self):
        assert items_of({"items": [{"id": "1"}, {"id": "2"}], "total": 2}) == [
            {"id": "1"},
            {"id": "2"},
        ]

    def test_bare_list(self):
        assert items_of([{"id": "1"}]) == [{"id": "1"}]

    def test_junk_returns_empty(self):
        assert items_of(None) == []
        assert items_of({"items": "nope"}) == []
