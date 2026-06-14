"""Unit tests for OAuth2 client request models.

Covers the fix for the admin "New OAuth Client" 422 bug:
``redirect_uris`` is OPTIONAL in general (RFC 7591 §2) but REQUIRED when
``authorization_code`` is in ``grant_types``.
"""

import pytest
from pydantic import ValidationError

from authglow.models.oauth_client import OAuth2ClientCreate, OAuth2ClientUpdate


class TestOAuth2ClientCreateRedirectUris:
    """OAuth2ClientCreate: redirect_uris is optional except with authorization_code."""

    def test_client_credentials_grant_does_not_require_redirect_uris(self):
        """The 'Service / API' template use case: no auth code, no URIs needed."""
        client = OAuth2ClientCreate(
            client_name="My Service",
            grant_types=["client_credentials", "refresh_token"],
        )
        assert client.redirect_uris == []

    def test_client_credentials_grant_with_empty_redirect_uris_works(self):
        client = OAuth2ClientCreate(
            client_name="My Service",
            grant_types=["client_credentials"],
            redirect_uris=[],
        )
        assert client.redirect_uris == []

    def test_authorization_code_grant_with_redirect_uris_works(self):
        client = OAuth2ClientCreate(
            client_name="My Web App",
            grant_types=["authorization_code", "refresh_token"],
            redirect_uris=["https://app.example.com/cb"],
        )
        assert client.redirect_uris == ["https://app.example.com/cb"]

    def test_authorization_code_grant_with_empty_redirect_uris_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            OAuth2ClientCreate(
                client_name="My Web App",
                grant_types=["authorization_code"],
                redirect_uris=[],
            )
        assert "redirect_uris" in str(exc_info.value)
        assert "authorization_code" in str(exc_info.value)

    def test_authorization_code_grant_without_redirect_uris_field_rejected(self):
        """The original bug: the field is omitted entirely on POST."""
        with pytest.raises(ValidationError) as exc_info:
            OAuth2ClientCreate(
                client_name="My Web App",
                grant_types=["authorization_code"],
            )
        assert "redirect_uris" in str(exc_info.value)

    def test_mixed_grants_with_authorization_code_require_redirect_uris(self):
        """Authorization code mixed with other grants still requires URIs."""
        with pytest.raises(ValidationError):
            OAuth2ClientCreate(
                client_name="Hybrid",
                grant_types=["authorization_code", "client_credentials"],
            )


class TestOAuth2ClientUpdateRedirectUris:
    """OAuth2ClientUpdate: redirect_uris can be cleared only when authorization_code is off."""

    def test_update_without_touching_redirect_uris_is_allowed(self):
        update = OAuth2ClientUpdate(client_name="Renamed App")
        assert update.redirect_uris is None
        assert update.grant_types is None

    def test_update_clearing_redirect_uris_with_auth_code_disabled_is_allowed(self):
        update = OAuth2ClientUpdate(
            grant_types=["client_credentials"],
            redirect_uris=[],
        )
        assert update.redirect_uris == []
        assert "authorization_code" not in update.grant_types

    def test_update_clearing_redirect_uris_while_auth_code_enabled_is_rejected(self):
        with pytest.raises(ValidationError) as exc_info:
            OAuth2ClientUpdate(
                grant_types=["authorization_code", "refresh_token"],
                redirect_uris=[],
            )
        assert "redirect_uris" in str(exc_info.value)

    def test_update_setting_authorization_code_with_omitted_redirect_uris_is_allowed(self):
        """Caller is not changing the URI list — leave it alone. Only the
        'redirect_uris=[] + authorization_code on' combination is rejected.
        """
        update = OAuth2ClientUpdate(grant_types=["authorization_code"])
        assert update.redirect_uris is None
        assert update.grant_types == ["authorization_code"]
