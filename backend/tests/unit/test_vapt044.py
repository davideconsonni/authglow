"""VAPT-044: unit tests for the ``_validate_state`` helper that
guards the OAuth 2.0 authorization endpoint.

These tests target the regex / length checks in isolation;
the integration-level behaviour (HTTP 400 from the endpoint)
is covered in ``tests/integration/test_state_param.py``.
"""

import secrets

from authglow.api.auth import _MIN_STATE_LEN, _validate_state


class TestVapt044ValidateState:
    def test_none_input_returns_none(self):
        assert _validate_state(None) is None

    def test_empty_string_returns_none(self):
        assert _validate_state("") is None

    def test_short_value_below_floor_rejected(self):
        # 15 chars — one below the 16-char floor.
        assert _validate_state("a" * 15) is None

    def test_at_floor_accepted(self):
        # Exactly 16 chars (the floor) is accepted — this is
        # the boundary the VAPT-044 fix is gating on.
        state = "a" * _MIN_STATE_LEN
        assert _validate_state(state) == state

    def test_uuid4_hex_accepted(self):
        state = "abc123def456789012345678901234ab"  # 32 hex chars
        assert _validate_state(state) == state

    def test_token_urlsafe_output_accepted(self):
        # ``secrets.token_urlsafe(32)`` is the canonical
        # recommendation in the OAuth 2.0 Security BCP —
        # 43 base64url chars, 192 bits of entropy.
        state = secrets.token_urlsafe(32)
        assert len(state) == 43
        assert _validate_state(state) == state

    def test_oversized_above_cap_rejected(self):
        # 513 chars — one over the 512-char defensive cap.
        assert _validate_state("a" * 513) is None

    def test_at_cap_accepted(self):
        # Exactly 512 chars (the defensive cap) is accepted.
        state = "a" * 512
        assert _validate_state(state) == state

    def test_log_injection_with_newline_rejected(self):
        # The state is echoed in the redirect URL AND logged
        # in the audit trail. A newline in the value would
        # let an attacker inject extra URL parameters or
        # log lines.
        assert _validate_state("goodstate-good\nFAKE") is None

    def test_log_injection_with_carriage_return_rejected(self):
        assert _validate_state("goodstate-good\rFAKE") is None

    def test_log_injection_with_tab_rejected(self):
        assert _validate_state("goodstate\tgoodgood") is None

    def test_space_in_state_rejected(self):
        assert _validate_state("goodstate goodgood") is None

    def test_shell_metachars_rejected(self):
        # The state will be URL-encoded in the redirect. Most
        # metachars would survive the encoding, so the
        # server-side rejection is the only defense.
        assert _validate_state("goodstate|whoami") is None
        assert _validate_state("goodstate&exit") is None
        assert _validate_state("goodstate;rm -rf /") is None

    def test_quote_in_state_rejected(self):
        # Quotes / angle brackets would break out of HTML
        # contexts the client renders the state in.
        assert _validate_state('goodstate"goodgood') is None
        assert _validate_state("goodstate<goodgood") is None

    def test_hash_in_state_rejected(self):
        # ``#`` in the state would be interpreted as a URL
        # fragment in the redirect — the server would echo
        # only the part before ``#`` back to the client.
        assert _validate_state("goodstate#goodgood") is None

    def test_passthrough_does_not_mutate_value(self):
        # Compose-friendly: the validator returns the input
        # unchanged on the happy path (same pattern as
        # :func:`authglow.core.password.check_password_byte_length`).
        state = "abc123def4567890"  # exactly 16 chars
        assert _validate_state(state) is state
