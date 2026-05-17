import pytest
import secrets
import re


class TestTokenGenerationSecurity:
    def test_authorization_code_uses_secrets_not_uuid4(self):
        from authglow.models.token import AuthorizationCode
        from datetime import datetime, timedelta, timezone
        import re

        code_instance = AuthorizationCode(
            client_id="test",
            user_id="test",
            redirect_uri="http://localhost/callback",
            scope="read",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
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
        from datetime import datetime, timedelta, timezone

        code_instance = AuthorizationCode(
            client_id="test",
            user_id="test",
            redirect_uri="http://localhost/callback",
            scope="read",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
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

    def test_authorization_code_has_sufficient_entropy(self):
        from authglow.models.token import AuthorizationCode

        code_instance = AuthorizationCode(
            client_id="test",
            user_id="test",
            redirect_uri="http://localhost/callback",
            scope="read",
            expires_at=None,
        )
        assert len(code_instance.code) >= 32, (
            "Authorization codes should have at least 256 bits of entropy. "
            f"Code length is {len(code_instance.code)}, expected at least 32 chars from token_urlsafe."
        )

    def test_refresh_token_uses_secrets_not_uuid4(self):
        from authglow.models.refresh_token import RefreshToken
        from datetime import datetime, timedelta

        rt = RefreshToken(
            user_id="test",
            client_id="test",
            scopes=["read"],
            expires_at=datetime.utcnow() + timedelta(days=30),
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
        from datetime import datetime, timedelta

        rt = RefreshToken(
            user_id="test",
            client_id="test",
            scopes=["read"],
            expires_at=datetime.utcnow() + timedelta(days=30),
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
        assert not uuid4_pattern.match(token.token), (
            "Email verification tokens should use secrets.token_urlsafe() instead of uuid4() "
            "for cryptographic security."
        )

    def test_secrets_token_urlsafe_produces_non_uuid(self):
        token = secrets.token_urlsafe(32)
        uuid4_pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        assert not uuid4_pattern.match(token)
        assert len(token) >= 32
