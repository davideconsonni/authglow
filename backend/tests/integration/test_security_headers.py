"""Integration tests for security headers middleware.

Verifies security headers are present on actual HTTP responses
from a FastAPI app that includes the middleware.
"""

import pytest
from unittest.mock import patch


@pytest.fixture
def client_with_test_settings():
    from starlette.testclient import TestClient
    from authglow.middleware.security_headers import SecurityHeadersMiddleware
    from fastapi import FastAPI

    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    @app.get("/")
    async def root():
        return "OK"

    return TestClient(app)


class TestSecurityHeadersOnHealth:
    def test_content_security_policy(self, client_with_test_settings):
        response = client_with_test_settings.get("/health")
        assert (
            response.headers.get("content-security-policy")
            == "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'"
        )

    def test_x_frame_options_deny(self, client_with_test_settings):
        response = client_with_test_settings.get("/health")
        assert response.headers.get("x-frame-options") == "DENY"

    def test_x_content_type_options_nosniff(self, client_with_test_settings):
        response = client_with_test_settings.get("/health")
        assert response.headers.get("x-content-type-options") == "nosniff"

    def test_referrer_policy(self, client_with_test_settings):
        response = client_with_test_settings.get("/health")
        assert response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_x_xss_protection(self, client_with_test_settings):
        response = client_with_test_settings.get("/health")
        assert response.headers.get("x-xss-protection") == "0"

    def test_x_permitted_cross_domain_policies(self, client_with_test_settings):
        response = client_with_test_settings.get("/health")
        assert response.headers.get("x-permitted-cross-domain-policies") == "none"

    def test_no_permissions_policy_by_default(self, client_with_test_settings):
        response = client_with_test_settings.get("/health")
        assert "permissions-policy" not in response.headers

    def test_no_hsts_in_development(self, client_with_test_settings):
        response = client_with_test_settings.get("/health")
        assert "strict-transport-security" not in response.headers


class TestSecurityHeadersOnRoot:
    def test_headers_on_html_page(self, client_with_test_settings):
        response = client_with_test_settings.get("/")
        assert response.headers.get("x-frame-options") == "DENY"
        assert response.headers.get("x-content-type-options") == "nosniff"


class TestHSTSInProduction:
    @pytest.fixture
    def prod_client(self):
        from starlette.testclient import TestClient
        from authglow.middleware.security_headers import SecurityHeadersMiddleware
        from fastapi import FastAPI
        from authglow.core.config import Settings as RealSettings

        settings = _make_prod_settings()
        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware, settings=settings)

        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        return TestClient(app)

    def test_hsts_present_in_production(self, prod_client):
        response = prod_client.get("/health")
        assert "strict-transport-security" in response.headers
        assert "max-age=31536000" in response.headers["strict-transport-security"]
        assert "includeSubDomains" in response.headers["strict-transport-security"]

    def test_all_security_headers_present_in_production(self, prod_client):
        response = prod_client.get("/health")
        assert response.headers.get("x-frame-options") == "DENY"
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
        assert response.headers.get("x-xss-protection") == "0"


class TestCustomSettings:
    @pytest.fixture
    def custom_client(self):
        from starlette.testclient import TestClient
        from authglow.middleware.security_headers import SecurityHeadersMiddleware
        from fastapi import FastAPI

        settings = _make_prod_settings()
        settings.csp_header = "default-src https:; script-src 'self'"
        settings.referrer_policy = "no-referrer"
        settings.permissions_policy = "camera=()"

        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware, settings=settings)

        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        return TestClient(app)

    def test_custom_csp_reflected(self, custom_client):
        response = custom_client.get("/health")
        assert "default-src https:" in response.headers["content-security-policy"]

    def test_custom_referrer_policy_reflected(self, custom_client):
        response = custom_client.get("/health")
        assert response.headers["referrer-policy"] == "no-referrer"

    def test_permissions_policy_included(self, custom_client):
        response = custom_client.get("/health")
        assert response.headers["permissions-policy"] == "camera=()"

    def test_hsts_respects_custom_max_age(self, custom_client):
        response = custom_client.get("/health")
        assert "max-age=31536000" in response.headers["strict-transport-security"]


class TestHeadersNotOverridden:
    @pytest.fixture
    def app_with_existing_headers(self):
        from starlette.testclient import TestClient
        from authglow.middleware.security_headers import SecurityHeadersMiddleware
        from fastapi import FastAPI
        from starlette.responses import Response

        app = FastAPI()
        app.add_middleware(SecurityHeadersMiddleware)

        @app.get("/custom")
        async def custom():
            return Response(
                content="OK",
                headers={
                    "x-frame-options": "ALLOW-FROM https://trusted.example.com",
                    "content-security-policy": "default-src https:",
                },
            )

        return TestClient(app)

    def test_overridden_csp_respected(self, app_with_existing_headers):
        response = app_with_existing_headers.get("/custom")
        assert response.headers["content-security-policy"] == "default-src https:"

    def test_overridden_x_frame_options_respected(self, app_with_existing_headers):
        response = app_with_existing_headers.get("/custom")
        assert response.headers["x-frame-options"] == "ALLOW-FROM https://trusted.example.com"


def _make_prod_settings():
    settings = _FakeSettings()
    settings.app_env = "production"
    settings.csp_header = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    )
    settings.x_frame_options = "DENY"
    settings.x_content_type_options = "nosniff"
    settings.referrer_policy = "strict-origin-when-cross-origin"
    settings.x_permitted_cross_domain_policies = "none"
    settings.permissions_policy = ""
    settings.hsts_max_age = 31536000
    settings.hsts_include_subdomains = True
    return settings


class _FakeSettings:
    pass
