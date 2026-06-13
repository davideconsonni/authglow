"""Unit tests for ProxyHeadersMiddleware (VAPT-025).

Verifies that X-Forwarded-For is only honored when the connecting
peer is in the trusted_proxies allowlist.
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
    def __init__(self):
        self.last_scope: dict = {}

    async def __call__(self, scope, receive, send):
        self.last_scope = dict(scope)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b'{"status":"ok"}'})


def _http_scope(client: tuple = ("192.0.2.1", 54321), headers: list = None) -> dict:
    default_host = [(b"host", b"example.com")]
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/test",
        "query_string": b"",
        "headers": list(headers) if headers is not None else list(default_host),
        "client": client,
    }


def _ws_scope() -> dict:
    return {"type": "websocket", "path": "/ws", "headers": []}


class TestVapt025TrustedProxyXForwardedFor:
    """VAPT-025: X-Forwarded-For only honored from trusted proxy IPs."""

    def test_xff_trusted_ip_updates_client(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"1.2.3.4"),
        ]
        scope = _http_scope(client=("10.0.0.1", 443), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("1.2.3.4", 443)

    def test_xff_untrusted_ip_ignored(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"1.2.3.4"),
        ]
        scope = _http_scope(client=("192.0.2.99", 54321), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("192.0.2.99", 54321)

    def test_no_xff_header_unchanged(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        scope = _http_scope(client=("10.0.0.1", 443))
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("10.0.0.1", 443)

    def test_xff_multiple_ips_takes_leftmost(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"1.2.3.4, 5.6.7.8, 9.10.11.12"),
        ]
        scope = _http_scope(client=("10.0.0.1", 443), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("1.2.3.4", 443)

    def test_cidr_range_trusted(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.0/24")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"1.2.3.4"),
        ]
        scope = _http_scope(client=("10.0.0.42", 443), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("1.2.3.4", 443)

    def test_cidr_range_outside_ignored(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.0/24")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"1.2.3.4"),
        ]
        scope = _http_scope(client=("10.0.1.1", 54321), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("10.0.1.1", 54321)

    def test_hostname_trusted(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="testclient")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"1.2.3.4"),
        ]
        scope = _http_scope(client=("testclient", 50000), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("1.2.3.4", 50000)

    def test_empty_trusted_proxies_ignores_xff(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"1.2.3.4"),
        ]
        scope = _http_scope(client=("192.0.2.1", 54321), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("192.0.2.1", 54321)

    def test_xff_whitespace_trimmed(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"  1.2.3.4  "),
        ]
        scope = _http_scope(client=("10.0.0.1", 443), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("1.2.3.4", 443)

    def test_xff_non_routable_ip_still_honored(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"10.0.0.42"),
        ]
        scope = _http_scope(client=("10.0.0.1", 443), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("10.0.0.42", 443)

    def test_websocket_scope_passthrough(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_ws_scope(), _FakeReceive(), send))

        assert send.messages[0]["status"] == 200

    def test_lifespan_scope_passthrough(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(mw({"type": "lifespan"}, _FakeReceive(), send))

        assert send.messages[0]["status"] == 200

    def test_multiple_trusted_proxies_comma_separated(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1, 192.168.0.0/16")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"1.2.3.4"),
        ]
        scope = _http_scope(client=("192.168.1.1", 443), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("1.2.3.4", 443)

    def test_xff_invalid_ip_preserves_client(self):
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware

        settings = _make_settings(trusted_proxies="10.0.0.1")
        fake_app = _FakeApp()
        mw = ProxyHeadersMiddleware(fake_app, settings=settings)

        headers = [
            (b"host", b"example.com"),
            (b"x-forwarded-for", b"not-an-ip"),
        ]
        scope = _http_scope(client=("10.0.0.1", 443), headers=headers)
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(scope, _FakeReceive(), send))

        assert fake_app.last_scope["client"] == ("10.0.0.1", 443)


def _make_settings(**overrides) -> object:
    defaults = {
        "trusted_proxies": "",
    }
    settings = _FakeSettings()
    for key, value in {**defaults, **overrides}.items():
        setattr(settings, key, value)
    settings.get_trusted_proxies = lambda: [
        addr.strip() for addr in settings.trusted_proxies.split(",") if addr.strip()
    ]
    return settings


class _FakeSettings:
    pass
