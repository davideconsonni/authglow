"""Unit tests for HttpsEnforcementMiddleware.

Tests the HTTP→HTTPS redirect logic without requiring a running FastAPI application.
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
    async def __call__(self, scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b'{"status":"ok"}'})


def _http_scope(path: str = "/test", headers: list = None) -> dict:
    default_host = [(b"host", b"example.com")]
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "query_string": b"",
        "headers": headers if headers is not None else default_host,
    }


def _ws_scope() -> dict:
    return {"type": "websocket", "path": "/ws", "headers": []}


def _headers_dict(message: dict) -> dict[str, str]:
    return {
        h[0].decode("latin-1").lower(): h[1].decode("latin-1")
        for h in message.get("headers", [])
    }


class TestHttpEnforcementRedirect:
    def test_redirect_301_in_production(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        assert send.messages[0]["status"] == 301
        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("location") == "https://example.com/test"

    def test_redirect_302_custom_status(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production", https_redirect_status=302)
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        assert send.messages[0]["status"] == 302

    def test_no_redirect_in_development(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="development")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        assert send.messages[0]["status"] == 200

    def test_no_redirect_when_enforce_https_false(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production", enforce_https=False)
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        assert send.messages[0]["status"] == 200

    def test_no_redirect_when_already_https_scheme(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        scope = _http_scope()
        scope["scheme"] = "https"
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert send.messages[0]["status"] == 200

    def test_no_redirect_when_x_forwarded_proto_https(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-proto", b"https"),
        ]
        scope = _http_scope(headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert send.messages[0]["status"] == 200

    def test_redirect_when_x_forwarded_proto_http(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-proto", b"http"),
        ]
        scope = _http_scope(headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert send.messages[0]["status"] == 301
        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("location") == "https://example.com/test"

    def test_x_forwarded_proto_wins_over_scheme(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-proto", b"https"),
        ]
        scope = _http_scope(headers=headers)
        scope["scheme"] = "http"
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert send.messages[0]["status"] == 200

    def test_preserves_path_in_redirect(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        scope = _http_scope(path="/some/deep/path")
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("location") == "https://example.com/some/deep/path"

    def test_preserves_query_string_in_redirect(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        scope = _http_scope(path="/oauth2/authorize")
        scope["query_string"] = b"client_id=abc&redirect_uri=/cb"
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert "https://example.com/oauth2/authorize" in hdrs.get("location", "")
        assert "client_id=abc" in hdrs.get("location", "")
        assert "redirect_uri=/cb" in hdrs.get("location", "")

    def test_websocket_scope_ignored(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_ws_scope(), _FakeReceive(), send))

        assert send.messages[0]["status"] == 200

    def test_production_case_insensitive(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="Production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(), _FakeReceive(), send))

        assert send.messages[0]["status"] == 301

    def test_lifespan_scope_passes_through(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        lifespan_scope = {"type": "lifespan"}
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(lifespan_scope, _FakeReceive(), send))

        assert send.messages[0]["status"] == 200

    def test_empty_host_header_redirects_safely(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        scope = _http_scope(headers=[(b"host", b"")])
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert send.messages[0]["status"] == 301
        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("location") == "https:///test"

    def test_missing_host_header_still_redirects(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        scope = _http_scope(headers=[])
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert send.messages[0]["status"] == 301

    def test_root_path_redirects(self):
        from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware

        settings = _make_settings(app_env="production")
        mw = HttpsEnforcementMiddleware(_FakeApp(), settings=settings)

        scope = _http_scope(path="/")
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        hdrs = _headers_dict(send.messages[0])
        assert hdrs.get("location") == "https://example.com/"


def _make_settings(**overrides) -> object:
    defaults = {
        "app_env": "development",
        "enforce_https": True,
        "https_redirect_status": 301,
    }
    settings = _FakeSettings()
    for key, value in {**defaults, **overrides}.items():
        setattr(settings, key, value)
    settings.is_production = settings.app_env.lower() == "production"
    return settings


class _FakeSettings:
    pass
