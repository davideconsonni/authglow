"""Unit tests for SecurityHeadersMiddleware.

Tests the header construction logic and conditional HSTS behaviour
without requiring a running FastAPI application.
"""

import pytest


class _FakeSend:
    def __init__(self):
        self.messages: list[dict] = []

    async def __call__(self, message):
        self.messages.append(message)


class _FakeReceive:
    async def __call__(self):
        return {"type": "http.request", "body": b""}


class _FakeApp:
    """ASGI app that returns a 200 response with optional custom headers."""

    def __init__(self, extra_headers: list[tuple[str, str]] = None):
        self.extra_headers = extra_headers or []

    async def __call__(self, scope, receive, send):
        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
        ]
        for name, value in self.extra_headers:
            headers.append((name.encode(), value.encode()))
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": headers,
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"status":"ok"}',
            }
        )


def _http_scope(path: str = "/health") -> dict:
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": path,
        "headers": [],
    }


def _ws_scope() -> dict:
    return {
        "type": "websocket",
        "path": "/ws",
        "headers": [],
    }


def _headers_dict(message: dict) -> dict[str, str]:
    return {
        h[0].decode("latin-1").lower(): h[1].decode("latin-1")
        for h in message.get("headers", [])
    }


class TestSecurityHeadersMiddleware:
    def test_all_security_headers_present(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings()
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        response_start = send.messages[0]
        assert response_start["type"] == "http.response.start"
        hdrs = _headers_dict(response_start)

        assert (
            hdrs.get("content-security-policy")
            == "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self'"
        )
        assert hdrs.get("x-frame-options") == "DENY"
        assert hdrs.get("x-content-type-options") == "nosniff"
        assert hdrs.get("referrer-policy") == "strict-origin-when-cross-origin"
        assert hdrs.get("x-xss-protection") == "0"
        assert hdrs.get("x-permitted-cross-domain-policies") == "none"

    def test_hsts_not_included_in_development(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings(app_env="development")
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert "strict-transport-security" not in hdrs

    def test_hsts_included_in_production(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings(app_env="production")
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert (
            hdrs.get("strict-transport-security")
            == "max-age=31536000; includeSubDomains"
        )

    def test_hsts_without_subdomains(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings(app_env="production", hsts_include_subdomains=False)
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("strict-transport-security") == "max-age=31536000"

    def test_hsts_included_in_production_case_insensitive(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings(app_env="Production")
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert "strict-transport-security" in hdrs

    def test_websocket_scope_ignored(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings()
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_ws_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert "x-frame-options" not in hdrs

    def test_app_headers_not_overridden(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings()
        app = _FakeApp(extra_headers=[("x-frame-options", "SAMEORIGIN")])
        mw = SecurityHeadersMiddleware(app, settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("x-frame-options") == "SAMEORIGIN", (
            "Middleware must not override headers already set by the application"
        )

    def test_custom_csp_value_reflected(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings(csp_header="default-src https:")
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("content-security-policy") == "default-src https:"

    def test_empty_csp_skipped(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings(csp_header="")
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert "content-security-policy" not in hdrs

    def test_permissions_policy_skipped_when_empty(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings(permissions_policy="")
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert "permissions-policy" not in hdrs

    def test_permissions_policy_included_when_set(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        policy = "camera=(), microphone=()"
        settings = _make_settings(permissions_policy=policy)
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("permissions-policy") == policy

    def test_custom_hsts_max_age(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings(
            app_env="production", hsts_max_age=63072000, hsts_include_subdomains=False
        )
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("strict-transport-security") == "max-age=63072000"

    def test_custom_referrer_policy(self):
        from authglow.middleware.security_headers import SecurityHeadersMiddleware

        settings = _make_settings(referrer_policy="no-referrer")
        mw = SecurityHeadersMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("referrer-policy") == "no-referrer"


def _make_settings(**overrides) -> object:
    settings = _FakeSettings()
    settings.app_env = "development"
    settings.csp_header = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'self'"
    )
    settings.x_frame_options = "DENY"
    settings.x_content_type_options = "nosniff"
    settings.referrer_policy = "strict-origin-when-cross-origin"
    settings.x_permitted_cross_domain_policies = "none"
    settings.permissions_policy = ""
    settings.hsts_max_age = 31536000
    settings.hsts_include_subdomains = True
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


class _FakeSettings:
    pass
