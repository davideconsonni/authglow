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
            "authglow.api.setup",
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


class TestSetupRateLimit:
    """H4: Verify that setup endpoints have rate-limit decorators."""

    def test_setup_module_uses_central_limiter(self):
        """authglow.api.setup must use the central limiter singleton."""
        from authglow.api.setup import limiter as setup_limiter
        from authglow.core.rate_limit import limiter as central_limiter

        assert setup_limiter is central_limiter, (
            "H4 Bug: setup.py imports its own Limiter instead of the central singleton."
        )

    def _get_rate_limits_for(self, func, limiter):
        """Return all SlowAPI rate-limit strings registered for a function."""
        key = f"{func.__module__}.{func.__name__}"
        limits = limiter._route_limits.get(key, [])
        return [str(limit_obj.limit) for limit_obj in limits]

    def test_create_admin_has_rate_limit(self):
        """POST /api/setup/create-admin must have a @limiter.limit() decorator."""
        from authglow.api.setup import create_admin_user
        from authglow.core.rate_limit import limiter

        limits = self._get_rate_limits_for(create_admin_user, limiter)
        assert len(limits) > 0, (
            "H4 Bug: create_admin_user has no rate-limit decorator — "
            "brute force / race condition possible."
        )

    def test_check_setup_has_rate_limit(self):
        """GET /api/setup/check must have a @limiter.limit() decorator."""
        from authglow.api.setup import check_setup_needed
        from authglow.core.rate_limit import limiter

        limits = self._get_rate_limits_for(check_setup_needed, limiter)
        assert len(limits) > 0, (
            "H4 Bug: check_setup_needed has no rate-limit decorator."
        )

    def test_setup_page_has_rate_limit(self):
        """GET /setup must have a @limiter.limit() decorator."""
        from authglow.api.setup import setup_page
        from authglow.core.rate_limit import limiter

        limits = self._get_rate_limits_for(setup_page, limiter)
        assert len(limits) > 0, "H4 Bug: setup_page has no rate-limit decorator."
