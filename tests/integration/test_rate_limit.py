"""Test that SlowAPI rate limiter is properly wired to the app."""

import pytest
from unittest.mock import patch


class TestRateLimiterWiring:
    """H2: Verify that SlowAPI limiter is instantiated once and connected to
    app.state via SlowAPIMiddleware so that @limiter.limit() decorators work."""

    def test_central_limiter_singleton_importable(self):
        """The central limiter module must be importable and provide a Limiter."""
        from authglow.core.rate_limit import limiter

        assert limiter is not None
        from slowapi import Limiter

        assert isinstance(limiter, Limiter)

    def test_api_modules_use_central_limiter(self):
        """All API modules with @limiter.limit() must import from core.rate_limit
        instead of creating their own Limiter instance."""
        from authglow.core import rate_limit as central

        modules_with_limiter = [
            "authglow.api.auth",
            "authglow.api.password_reset",
            "authglow.api.passkey",
            "authglow.api.oauth_consent_handler",
            "authglow.api.oauth_client",
            "authglow.api.oauth2_advanced",
            "authglow.api.email_verification",
            "authglow.api.admin",
            "authglow.api.api_key",
        ]

        for mod_name in modules_with_limiter:
            import importlib

            mod = importlib.import_module(mod_name)
            assert mod.limiter is central.limiter, (
                f"{mod_name}.limiter is not the central singleton — "
                f"rate-limit decorators in that module will not be connected to the app."
            )

    @patch("authglow.core.config.get_settings")
    @patch("authglow.core.config.Settings")
    def test_app_state_has_limiter(
        self, mock_settings_cls, mock_get_settings, test_settings
    ):
        """app.state.limiter must be set to the central limiter instance."""
        mock_get_settings.return_value = test_settings
        mock_settings_cls.return_value = test_settings

        import importlib
        import main as main_module

        importlib.reload(main_module)
        app = main_module.app

        from authglow.core.rate_limit import limiter

        assert hasattr(app.state, "limiter"), (
            "H2 Bug: app.state.limiter is not set — SlowAPI cannot find the limiter."
        )
        assert app.state.limiter is limiter, (
            "H2 Bug: app.state.limiter is not the central singleton."
        )

    @patch("authglow.core.config.get_settings")
    @patch("authglow.core.config.Settings")
    def test_slowapi_middleware_registered(
        self, mock_settings_cls, mock_get_settings, test_settings
    ):
        """SlowAPIMiddleware must be added to the app middleware stack."""
        mock_get_settings.return_value = test_settings
        mock_settings_cls.return_value = test_settings

        import importlib
        import main as main_module

        importlib.reload(main_module)
        app = main_module.app

        from slowapi.middleware import SlowAPIMiddleware

        middleware_classes = [m.cls for m in app.user_middleware]
        assert SlowAPIMiddleware in middleware_classes, (
            "H2 Bug: SlowAPIMiddleware is not registered in the app middleware stack."
        )
