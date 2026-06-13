"""Integration tests for ProxyHeadersMiddleware (VAPT-025).

Verifies X-Forwarded-For handling with a real FastAPI app and rate limiter.
"""

import pytest


class _FakeSettings:
    pass


def _make_settings(**overrides) -> object:
    defaults: dict[str, object] = {
        "trusted_proxies": "",
    }
    settings = _FakeSettings()
    for key, value in {**defaults, **overrides}.items():
        setattr(settings, key, value)
    settings.get_trusted_proxies = lambda: [
        addr.strip() for addr in settings.trusted_proxies.split(",") if addr.strip()
    ]
    return settings


class TestRealIpPassedToRateLimiter:
    """Verify rate limiter sees real client IP when proxy is trusted."""

    @pytest.fixture
    def app_with_proxy(self):
        from starlette.testclient import TestClient
        from fastapi import FastAPI, Request
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        from slowapi.middleware import SlowAPIMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1, testclient")
        limiter = Limiter(key_func=get_remote_address)

        app = FastAPI()
        app.state.limiter = limiter
        app.add_middleware(ProxyHeadersMiddleware, settings=settings)
        app.add_middleware(SlowAPIMiddleware)

        @app.get("/client-ip")
        async def client_ip(request: Request):
            return {"ip": request.client.host if request.client else "none"}

        return TestClient(app)

    def test_real_ip_seen_when_proxy_trusted(self, app_with_proxy):
        response = app_with_proxy.get(
            "/client-ip",
            headers={"X-Forwarded-For": "1.2.3.4"},
        )
        assert response.status_code == 200
        assert response.json()["ip"] == "1.2.3.4"

    def test_peer_ip_seen_when_proxy_not_trusted(self):
        from starlette.testclient import TestClient
        from fastapi import FastAPI, Request
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        from slowapi.middleware import SlowAPIMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.99")
        limiter = Limiter(key_func=get_remote_address)

        app = FastAPI()
        app.state.limiter = limiter
        app.add_middleware(ProxyHeadersMiddleware, settings=settings)
        app.add_middleware(SlowAPIMiddleware)

        @app.get("/client-ip")
        async def client_ip(request: Request):
            return {"ip": request.client.host if request.client else "none"}

        client = TestClient(app)
        response = client.get(
            "/client-ip",
            headers={"X-Forwarded-For": "1.2.3.4"},
        )
        assert response.status_code == 200
        assert response.json()["ip"] == "testclient"


class TestUntrustedProxyUsesPeerIp:
    """Verify peer IP is used when proxy is not trusted."""

    @pytest.fixture
    def app_no_trusted(self):
        from starlette.testclient import TestClient
        from fastapi import FastAPI, Request
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="")
        app = FastAPI()
        app.add_middleware(ProxyHeadersMiddleware, settings=settings)

        @app.get("/client-ip")
        async def client_ip(request: Request):
            return {"ip": request.client.host if request.client else "none"}

        return TestClient(app)

    def test_xff_ignored_when_no_trusted_proxies(self, app_no_trusted):
        response = app_no_trusted.get(
            "/client-ip",
            headers={"X-Forwarded-For": "1.2.3.4"},
        )
        assert response.status_code == 200
        assert response.json()["ip"] == "testclient"

    def test_no_xff_header_works(self, app_no_trusted):
        response = app_no_trusted.get("/client-ip")
        assert response.status_code == 200
        assert response.json()["ip"] == "testclient"


class TestEndpointWorksWithLimiter:
    """Verify endpoints with @limiter.limit still work correctly."""

    def test_rate_limited_endpoint_returns_200(self):
        from starlette.testclient import TestClient
        from fastapi import FastAPI, Request
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        from slowapi.middleware import SlowAPIMiddleware

        settings = _make_settings(trusted_proxies="testclient")
        limiter = Limiter(key_func=get_remote_address)

        app = FastAPI()
        app.state.limiter = limiter
        app.add_middleware(ProxyHeadersMiddleware, settings=settings)
        app.add_middleware(SlowAPIMiddleware)

        @app.get("/limited")
        @limiter.limit("10/minute")
        async def limited(request: Request):
            return {"ip": request.client.host if request.client else "none", "ok": True}

        client = TestClient(app)
        response = client.get(
            "/limited",
            headers={"X-Forwarded-For": "5.5.5.5"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["ok"] is True
        assert data["ip"] == "5.5.5.5"


class TestDifferentXffSeparateBuckets:
    """Verify different X-Forwarded-For values get separate rate limit buckets."""

    def test_different_ips_different_buckets(self):
        from starlette.testclient import TestClient
        from fastapi import FastAPI, Request
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        from slowapi.middleware import SlowAPIMiddleware

        settings = _make_settings(trusted_proxies="testclient")
        limiter = Limiter(key_func=get_remote_address)

        app = FastAPI()
        app.state.limiter = limiter
        app.add_middleware(ProxyHeadersMiddleware, settings=settings)
        app.add_middleware(SlowAPIMiddleware)

        @app.get("/strict")
        @limiter.limit("1/minute")
        async def strict(request: Request):
            return {"ip": request.client.host if request.client else "none"}

        client = TestClient(app)
        response1 = client.get("/strict", headers={"X-Forwarded-For": "10.0.0.1"})
        assert response1.status_code == 200

        response2 = client.get("/strict", headers={"X-Forwarded-For": "10.0.0.2"})
        assert response2.status_code == 200
