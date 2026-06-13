"""Integration tests for HTTPS enforcement middleware.

Verifies HTTP→HTTPS redirect behavior on actual HTTP responses
from a FastAPI app that includes the middleware.
"""

import pytest


class _FakeSettings:
    pass


def _make_settings(**overrides) -> object:
    defaults = {
        "app_env": "development",
        "enforce_https": True,
        "https_redirect_status": 301,
        "trusted_proxies": "",
    }
    settings = _FakeSettings()
    for key, value in {**defaults, **overrides}.items():
        setattr(settings, key, value)
    settings.is_production = settings.app_env.lower() == "production"
    settings.get_trusted_proxies = lambda: [
        addr.strip() for addr in settings.trusted_proxies.split(",") if addr.strip()
    ]
    return settings


class TestNoRedirectInDevelopment:
    @pytest.fixture
    def dev_client(self):
        from starlette.testclient import TestClient
        from authglow.middleware.https_enforcement import (
            HttpsEnforcementMiddleware,
        )
        from fastapi import FastAPI

        settings = _make_settings(app_env="development")
        app = FastAPI()
        app.add_middleware(HttpsEnforcementMiddleware, settings=settings)

        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        @app.get("/")
        async def root():
            return "OK"

        @app.post("/post-test")
        async def post_test():
            return {"received": True}

        return TestClient(app)

    def test_health_returns_200(self, dev_client):
        response = dev_client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_root_returns_200(self, dev_client):
        response = dev_client.get("/")
        assert response.status_code == 200

    def test_no_redirect_header(self, dev_client):
        response = dev_client.get("/health", follow_redirects=False)
        assert response.status_code == 200
        assert "location" not in response.headers

    def test_post_request_works(self, dev_client):
        response = dev_client.post("/post-test", json={"key": "value"})
        assert response.status_code == 200


class TestRedirectInProduction:
    @pytest.fixture
    def prod_client(self):
        from starlette.testclient import TestClient
        from authglow.middleware.https_enforcement import (
            HttpsEnforcementMiddleware,
        )
        from fastapi import FastAPI

        settings = _make_settings(app_env="production")
        app = FastAPI()
        app.add_middleware(HttpsEnforcementMiddleware, settings=settings)

        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        @app.get("/test/path")
        async def test_path():
            return "test"

        return TestClient(app)

    def test_redirect_301_on_http(self, prod_client):
        response = prod_client.get("/health", follow_redirects=False)
        assert response.status_code == 301
        assert "location" in response.headers

    def test_redirect_to_https(self, prod_client):
        response = prod_client.get("/health", follow_redirects=False)
        location = response.headers["location"]
        assert location.startswith("https://")

    def test_redirect_preserves_path(self, prod_client):
        response = prod_client.get("/test/path", follow_redirects=False)
        location = response.headers["location"]
        assert "https://testserver/test/path" in location or "/test/path" in location

    def test_redirect_empty_body(self, prod_client):
        response = prod_client.get("/health", follow_redirects=False)
        assert response.content == b"" or response.text == ""

    def test_post_also_redirected(self, prod_client):
        response = prod_client.post("/health", json={"k": "v"}, follow_redirects=False)
        assert response.status_code == 301

    def test_https_requests_not_redirected(self, prod_client):
        response = prod_client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}

    def test_redirect_302_when_configured(self):
        from starlette.testclient import TestClient
        from authglow.middleware.https_enforcement import (
            HttpsEnforcementMiddleware,
        )
        from fastapi import FastAPI

        settings = _make_settings(app_env="production", https_redirect_status=302)
        app = FastAPI()
        app.add_middleware(HttpsEnforcementMiddleware, settings=settings)

        @app.get("/")
        async def root():
            return "OK"

        client = TestClient(app)
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 302


class TestHttpsEnforcementDisabled:
    @pytest.fixture
    def disabled_client(self):
        from starlette.testclient import TestClient
        from authglow.middleware.https_enforcement import (
            HttpsEnforcementMiddleware,
        )
        from fastapi import FastAPI

        settings = _make_settings(app_env="production", enforce_https=False)
        app = FastAPI()
        app.add_middleware(HttpsEnforcementMiddleware, settings=settings)

        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        return TestClient(app)

    def test_no_redirect_when_disabled(self, disabled_client):
        response = disabled_client.get("/health", follow_redirects=False)
        assert response.status_code == 200
        assert "location" not in response.headers


class TestXForwardedProtoHeader:
    @pytest.fixture
    def proxy_client(self):
        from starlette.testclient import TestClient
        from authglow.middleware.https_enforcement import (
            HttpsEnforcementMiddleware,
        )
        from fastapi import FastAPI

        settings = _make_settings(app_env="production", trusted_proxies="testclient")
        app = FastAPI()
        app.add_middleware(HttpsEnforcementMiddleware, settings=settings)

        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        return TestClient(app)

    def test_x_forwarded_proto_https_no_redirect(self, proxy_client):
        response = proxy_client.get(
            "/health",
            headers={"X-Forwarded-Proto": "https"},
            follow_redirects=False,
        )
        assert response.status_code == 200

    def test_x_forwarded_proto_http_redirects(self, proxy_client):
        response = proxy_client.get(
            "/health",
            headers={"X-Forwarded-Proto": "http"},
            follow_redirects=False,
        )
        assert response.status_code == 301

    def test_x_forwarded_proto_case_sensitive(self, proxy_client):
        response = proxy_client.get(
            "/health",
            headers={"x-forwarded-proto": "https"},
            follow_redirects=False,
        )
        assert response.status_code == 200


class TestProductionCaseInsensitive:
    def test_production_uppercase_redirects(self):
        from starlette.testclient import TestClient
        from authglow.middleware.https_enforcement import (
            HttpsEnforcementMiddleware,
        )
        from fastapi import FastAPI

        settings = _make_settings(app_env="Production")
        app = FastAPI()
        app.add_middleware(HttpsEnforcementMiddleware, settings=settings)

        @app.get("/")
        async def root():
            return "OK"

        client = TestClient(app)
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 301
