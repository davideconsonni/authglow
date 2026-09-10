"""Unit tests for the email provider registry.

Covers the config-driven selector in
``authglow.services.email.factory``: default resolution from
``Settings.email_backend``, explicit ``provider_name=`` /
``settings=`` overrides, fail-fast on unknown backends, and
``register_email_provider()`` for out-of-tree providers.
"""

from unittest.mock import MagicMock

import pytest

from authglow.services.email import factory
from authglow.services.email.base import EmailProvider
from authglow.services.email.console import ConsoleEmailProvider
from authglow.services.email.factory import create_email_provider, register_email_provider


class TestRegistryResolution:
    def test_default_backend_from_settings(self, test_settings):
        provider = create_email_provider(settings=test_settings)
        assert isinstance(provider, EmailProvider)

    def test_provider_name_override(self, test_settings):
        settings = test_settings.model_copy(update={"demo_mode": False})
        provider = create_email_provider("console", settings=settings)
        assert isinstance(provider, ConsoleEmailProvider)

    def test_all_builtin_backends_resolve(self, test_settings):
        for name in (
            "console",
            "file_storage",
            "smtp",
            "sendgrid",
            "mailgun",
            "resend",
        ):
            provider = create_email_provider(name, settings=test_settings)
            assert isinstance(provider, EmailProvider), name
            assert provider.get_provider_name() in factory._PROVIDERS, name

    def test_unknown_backend_raises_with_available_names(self, test_settings):
        with pytest.raises(ValueError, match="Unsupported EMAIL_BACKEND 'nope'"):
            create_email_provider("nope", settings=test_settings)
        try:
            create_email_provider("nope", settings=test_settings)
        except ValueError as exc:
            assert "console" in str(exc)


class TestRegisterEmailProvider:
    def test_custom_provider_resolves(self, test_settings):
        settings = test_settings.model_copy(update={"demo_mode": False})
        sentinel = MagicMock(spec=EmailProvider)

        def _fake_builder(resolved):
            assert resolved is settings
            return sentinel

        register_email_provider("fake", _fake_builder)
        try:
            assert create_email_provider("fake", settings=settings) is sentinel
        finally:
            factory._PROVIDERS.pop("fake", None)

    def test_custom_provider_overrides_builtin_temporarily(self, test_settings):
        settings = test_settings.model_copy(update={"demo_mode": False})
        sentinel = MagicMock(spec=EmailProvider)
        original = factory._PROVIDERS["console"]
        register_email_provider("console", lambda resolved: sentinel)
        try:
            assert create_email_provider("console", settings=settings) is sentinel
        finally:
            register_email_provider("console", original)

    def test_unregistered_after_removal_raises(self, test_settings):
        register_email_provider("ephemeral", lambda settings: MagicMock(spec=EmailProvider))
        factory._PROVIDERS.pop("ephemeral", None)
        with pytest.raises(ValueError, match="Unsupported EMAIL_BACKEND"):
            create_email_provider("ephemeral", settings=test_settings)
