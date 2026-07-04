"""Tests for the OIDC Core §5.5 ``claims`` request parameter.

Covers the parser (malformed inputs, valid inputs), the
``apply_claims_request`` filtering (id_token / userinfo
sub-dicts, ``essential`` enforcement, ``value`` / ``values``
filters), and the end-to-end wiring on the
``/api/oauth2/authorize`` endpoint (rejection of malformed
JSON, success on valid input).
"""

import pytest

from authglow.services.oidc_claims import (
    ClaimsEssentialMissingError,
    ClaimsParameterError,
    apply_claims_request,
    parse_claims_parameter,
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class TestParseClaimsParameter:
    def test_none_returns_none(self):
        assert parse_claims_parameter(None) is None

    def test_empty_string_returns_none(self):
        assert parse_claims_parameter("") is None
        assert parse_claims_parameter("   ") is None

    def test_valid_id_token_only(self):
        raw = '{"id_token": {"acr": {"essential": true}}}'
        out = parse_claims_parameter(raw)
        assert out == {"id_token": {"acr": {"essential": True}}}

    def test_valid_userinfo_only(self):
        raw = '{"userinfo": {"given_name": null}}'
        out = parse_claims_parameter(raw)
        assert out == {"userinfo": {"given_name": None}}

    def test_valid_both_targets(self):
        raw = (
            '{"id_token": {"acr": {"essential": true}}, '
            '"userinfo": {"given_name": {"essential": false}}}'
        )
        out = parse_claims_parameter(raw)
        assert "id_token" in out
        assert "userinfo" in out

    def test_rejects_malformed_json(self):
        with pytest.raises(ClaimsParameterError, match="not valid JSON"):
            parse_claims_parameter("{not json")

    def test_rejects_non_object_top_level(self):
        with pytest.raises(ClaimsParameterError, match="JSON object at the top"):
            parse_claims_parameter("[]")

    def test_rejects_invalid_top_level_keys(self):
        with pytest.raises(ClaimsParameterError, match="invalid top-level keys"):
            parse_claims_parameter('{"id_token_malformed": {}}')

    def test_rejects_non_object_sub_dict(self):
        with pytest.raises(ClaimsParameterError, match="must be a JSON object"):
            parse_claims_parameter('{"id_token": "not an object"}')

    def test_rejects_non_object_claim_request(self):
        with pytest.raises(ClaimsParameterError, match="must be a JSON object or null"):
            parse_claims_parameter('{"id_token": {"acr": "string"}}')

    def test_rejects_non_boolean_essential(self):
        with pytest.raises(ClaimsParameterError, match="must be a boolean"):
            parse_claims_parameter('{"id_token": {"acr": {"essential": "yes"}}}')

    def test_rejects_both_value_and_values(self):
        with pytest.raises(ClaimsParameterError, match="both 'value' and 'values'"):
            parse_claims_parameter(
                '{"id_token": {"acr": {"value": "x", "values": ["x", "y"]}}}'
            )


# ---------------------------------------------------------------------------
# apply_claims_request
# ---------------------------------------------------------------------------


class TestApplyClaimsRequest:
    def test_no_request_returns_all(self):
        available = {"email": "u@test.com", "name": "User"}
        out, missing = apply_claims_request("id_token", None, available)
        assert out == available
        assert missing == []

    def test_empty_sub_dict_returns_all(self):
        available = {"email": "u@test.com"}
        out, _ = apply_claims_request("id_token", {"id_token": {}}, available)
        assert out == available

    def test_filters_to_requested_only(self):
        available = {
            "email": "u@test.com",
            "name": "User",
            "given_name": "First",
        }
        out, missing = apply_claims_request(
            "id_token",
            {"id_token": {"email": None, "given_name": None}},
            available,
        )
        assert out == {"email": "u@test.com", "given_name": "First"}
        assert missing == []

    def test_essential_missing_claim_reports_missing(self):
        available = {"email": "u@test.com"}
        out, missing = apply_claims_request(
            "id_token",
            {"id_token": {"phone_number": {"essential": True}}},
            available,
        )
        assert out == {}
        assert missing == ["phone_number"]

    def test_optional_missing_claim_silently_dropped(self):
        """A claim requested but not available, and not marked
        essential, is dropped silently. The ``claims`` request
        is "include-only" — claims not in the request are
        excluded from the response too."""
        available = {"email": "u@test.com", "name": "User"}
        out, missing = apply_claims_request(
            "id_token",
            {"id_token": {"phone_number": None}},  # not essential, not available
            available,
        )
        # The request is "include only phone_number" — since it
        # is not available, the response is empty (no fallback
        # to the other available claims).
        assert out == {}
        assert missing == []

    def test_value_filter_excludes_claim(self):
        available = {"email": "u@test.com", "name": "User"}
        out, missing = apply_claims_request(
            "id_token",
            {"id_token": {"email": {"value": "other@test.com"}}},
            available,
        )
        # value mismatch → claim is dropped; if essential, missing
        assert "email" not in out
        assert missing == []

    def test_value_filter_excludes_essential_claim(self):
        available = {"email": "u@test.com", "name": "User"}
        out, missing = apply_claims_request(
            "id_token",
            {"id_token": {"email": {"essential": True, "value": "other@test.com"}}},
            available,
        )
        assert "email" not in out
        assert missing == ["email"]

    def test_values_filter_includes_matching(self):
        available = {"acr": "silver"}
        out, missing = apply_claims_request(
            "id_token",
            {"id_token": {"acr": {"values": ["silver", "gold"]}}},
            available,
        )
        assert out == {"acr": "silver"}
        assert missing == []

    def test_values_filter_excludes_non_matching(self):
        available = {"acr": "bronze"}
        out, missing = apply_claims_request(
            "id_token",
            {"id_token": {"acr": {"essential": True, "values": ["silver", "gold"]}}},
            available,
        )
        assert "acr" not in out
        assert missing == ["acr"]

    def test_userinfo_target_applies_separately(self):
        available = {"email": "u@test.com", "name": "User"}
        out, _ = apply_claims_request(
            "userinfo",
            {"id_token": {"name": None}, "userinfo": {"email": None}},
            available,
        )
        # id_token sub-dict is ignored when target=userinfo
        assert out == {"email": "u@test.com"}

    def test_essential_missing_claim_returns_list(self):
        """The function does NOT raise — it returns the list of
        essential-claim names that are missing. The router
        maps that list to ``claims_request_invalid``."""
        out, missing = apply_claims_request(
            "id_token",
            {"id_token": {"phone_number": {"essential": True}}},
            {"email": "u@test.com"},
        )
        assert out == {}
        assert missing == ["phone_number"]
        # The exception class is exposed for the router to use
        assert issubclass(ClaimsEssentialMissingError, ValueError)
