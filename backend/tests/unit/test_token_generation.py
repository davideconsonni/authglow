import pytest
import secrets
import re
from authglow.core.datetime import utcnow


class TestTokenGenerationSecurity:
    def test_authorization_code_uses_secrets_not_uuid4(self):
        from authglow.models.token import AuthorizationCode
        from datetime import timedelta
        import re

        code_instance = AuthorizationCode(
            client_id="test",
            user_id="test",
            redirect_uri="http://localhost/callback",
            scope="read",
            expires_at=utcnow() + timedelta(minutes=10),
        )
        uuid4_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        assert not uuid4_pattern.match(code_instance.code), (
            "Authorization codes should use secrets.token_urlsafe() instead of uuid4() "
            "for cryptographic security. UUID4 is predictable and not suitable for bearer tokens."
        )

    def test_authorization_code_has_sufficient_entropy(self):
        from authglow.models.token import AuthorizationCode
        from datetime import timedelta

        code_instance = AuthorizationCode(
            client_id="test",
            user_id="test",
            redirect_uri="http://localhost/callback",
            scope="read",
            expires_at=utcnow() + timedelta(minutes=10),
        )
        assert len(code_instance.code) >= 32, (
            "Authorization codes should have at least 256 bits of entropy. "
            f"Code length is {len(code_instance.code)}, expected at least 32 chars from token_urlsafe."
        )
        uuid4_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        assert not uuid4_pattern.match(code_instance.code), (
            "Authorization codes should use secrets.token_urlsafe() instead of uuid4() "
            "for cryptographic security. UUID4 is predictable and not suitable for bearer tokens."
        )

    def test_refresh_token_uses_secrets_not_uuid4(self):
        from authglow.models.refresh_token import RefreshToken
        from datetime import timedelta

        rt = RefreshToken(
            user_id="test",
            client_id="test",
            scopes=["read"],
            expires_at=utcnow() + timedelta(days=30),
        )
        uuid4_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        assert not uuid4_pattern.match(rt.token), (
            "Refresh tokens should use secrets.token_urlsafe() instead of uuid4() "
            "for cryptographic security."
        )

    def test_refresh_token_has_sufficient_entropy(self):
        from authglow.models.refresh_token import RefreshToken
        from datetime import timedelta

        rt = RefreshToken(
            user_id="test",
            client_id="test",
            scopes=["read"],
            expires_at=utcnow() + timedelta(days=30),
        )
        assert len(rt.token) >= 32, (
            "Refresh tokens should have at least 256 bits of entropy. "
            f"Token length is {len(rt.token)}, expected at least 32 chars from token_urlsafe."
        )

    def test_email_verification_token_uses_secrets_not_uuid4(self):
        from authglow.models.email_verification import EmailVerificationToken

        token = EmailVerificationToken(user_id="test", email="test@example.com")
        uuid4_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        assert not uuid4_pattern.match(token.verification_code), (
            "Email verification codes should be the human-friendly XXXX-XXXX-XXXX format "
            "(VAPT-022 alignment), not UUID4. UUID4 is predictable and not suitable as a "
            "credential. The token_id field IS a UUID4 (intentionally) because it is a "
            "non-secret correlation identifier used for audit joinability."
        )

    def test_secrets_token_urlsafe_produces_non_uuid(self):
        token = secrets.token_urlsafe(32)
        uuid4_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        assert not uuid4_pattern.match(token)
        assert len(token) >= 32

    def test_mfa_session_token_uses_secrets_not_uuid4(self):
        from authglow.models.session import MFASession
        from datetime import timedelta

        session = MFASession(
            user_id="test",
            client_id="test",
            redirect_uri="http://localhost/callback",
            scope="read",
            expires_at=utcnow() + timedelta(minutes=5),
        )
        uuid4_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        assert not uuid4_pattern.match(session.session_token), (
            "MFA session tokens should use secrets.token_urlsafe() instead of uuid4() "
            "for cryptographic security."
        )

    def test_mfa_session_token_has_sufficient_entropy(self):
        from authglow.models.session import MFASession
        from datetime import timedelta

        session = MFASession(
            user_id="test",
            client_id="test",
            redirect_uri="http://localhost/callback",
            scope="read",
            expires_at=utcnow() + timedelta(minutes=5),
        )
        assert len(session.session_token) >= 32, (
            "MFA session tokens should have at least 256 bits of entropy. "
            f"Token length is {len(session.session_token)}, expected at least 32 chars from token_urlsafe."
        )

    def test_refresh_token_id_uses_secrets_not_uuid4(self):
        from authglow.models.refresh_token import RefreshToken
        from datetime import timedelta

        rt = RefreshToken(
            user_id="test",
            client_id="test",
            scopes=["read"],
            expires_at=utcnow() + timedelta(days=30),
        )
        uuid4_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        assert not uuid4_pattern.match(rt.token_id), (
            "Refresh token IDs should use secrets.token_urlsafe() instead of uuid4() "
            "for cryptographic security."
        )

    def test_refresh_token_id_has_sufficient_entropy(self):
        from authglow.models.refresh_token import RefreshToken
        from datetime import timedelta

        rt = RefreshToken(
            user_id="test",
            client_id="test",
            scopes=["read"],
            expires_at=utcnow() + timedelta(days=30),
        )
        assert len(rt.token_id) >= 32, (
            "Refresh token IDs should have at least 256 bits of entropy. "
            f"ID length is {len(rt.token_id)}, expected at least 32 chars from token_urlsafe."
        )
