"""Unit tests for MaxBodySizeMiddleware.

Tests body size enforcement logic using pure ASGI fakes
without requiring a running FastAPI application.
"""

import pytest


class _FakeSend:
    def __init__(self):
        self.messages: list[dict] = []

    async def __call__(self, message):
        self.messages.append(message)


class _FakeReceive:
    def __init__(
        self,
        body: bytes,
        chunk_size: int = 0,
        include_disconnect: bool = False,
    ):
        self.body = body
        self.chunk_size = chunk_size
        self.include_disconnect = include_disconnect
        self._consumed = False

    async def __call__(self):
        if self._consumed:
            return {"type": "http.request", "body": b"", "more_body": False}
        self._consumed = True

        if self.include_disconnect:
            return {"type": "http.disconnect"}

        if not self.body:
            return {"type": "http.request", "body": b"", "more_body": False}

        if self.chunk_size > 0 and len(self.body) > self.chunk_size:
            chunk = self.body[: self.chunk_size]
            remaining = self.body[self.chunk_size :]
            self.body = remaining
            self._consumed = False
            return {"type": "http.request", "body": chunk, "more_body": True}
        else:
            more = False
            return {"type": "http.request", "body": self.body, "more_body": more}


class _FakeChunkedReceive:
    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks
        self.index = 0

    async def __call__(self):
        if self.index >= len(self.chunks):
            return {"type": "http.request", "body": b"", "more_body": False}
        chunk = self.chunks[self.index]
        self.index += 1
        more = self.index < len(self.chunks)
        return {"type": "http.request", "body": chunk, "more_body": more}


class _FakeApp:
    async def __call__(self, scope, receive, send):
        body_chunks = []
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.request":
                body_chunks.append(message.get("body", b""))
                more_body = message.get("more_body", False)

        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"status":"ok"}',
            }
        )


def _http_scope(path: str = "/test", headers: list = None) -> dict:
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": path,
        "headers": headers or [],
    }


def _ws_scope() -> dict:
    return {"type": "websocket", "path": "/ws", "headers": []}


class TestContentLengthRejection:
    def test_over_limit_rejected_413(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        headers = [(b"content-length", b"2097153")]  # 2 MB + 1 byte
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(headers=headers), _FakeReceive(b""), send))

        assert send.messages[0]["status"] == 413
        body = send.messages[1]["body"]
        assert b"413" not in body  # status code is in the message field, not body
        assert b"exceeds" in body

    def test_under_limit_passes_200(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        headers = [(b"content-length", b"512")]  # 512 bytes
        send = _FakeSend()
        body = b"x" * 512
        import asyncio

        asyncio.run(mw(_http_scope(headers=headers), _FakeReceive(body=body), send))

        assert send.messages[0]["status"] == 200

    def test_exactly_at_limit_passes_200(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        limit = 1 * 1024 * 1024
        headers = [(b"content-length", str(limit).encode())]
        send = _FakeSend()
        import asyncio

        asyncio.run(
            mw(
                _http_scope(headers=headers),
                _FakeReceive(body=b"x" * limit),
                send,
            )
        )

        assert send.messages[0]["status"] == 200

    def test_custom_limit_from_settings(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=5)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        # 4 MB under 5 MB limit
        limit = 4 * 1024 * 1024
        headers = [(b"content-length", str(limit).encode())]
        send = _FakeSend()
        import asyncio

        asyncio.run(
            mw(
                _http_scope(headers=headers),
                _FakeReceive(body=b"x" * limit),
                send,
            )
        )

        assert send.messages[0]["status"] == 200

        # 6 MB over 5 MB limit
        send2 = _FakeSend()
        headers2 = [(b"content-length", str(6 * 1024 * 1024).encode())]
        asyncio.run(mw(_http_scope(headers=headers2), _FakeReceive(b""), send2))

        assert send2.messages[0]["status"] == 413

    def test_zero_limit_rejects_everything(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=0)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        headers = [(b"content-length", b"1")]
        send = _FakeSend()
        import asyncio

        asyncio.run(mw(_http_scope(headers=headers), _FakeReceive(b""), send))

        assert send.messages[0]["status"] == 413


class TestChunkedEncoding:
    def test_chunked_under_limit_passes_200(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        chunks = [b"x" * 100] * 5  # 500 bytes total, well under 1 MB
        send = _FakeSend()
        import asyncio

        asyncio.run(
            mw(
                _http_scope(headers=[]),
                _FakeChunkedReceive(chunks),
                send,
            )
        )

        assert send.messages[0]["status"] == 200

    def test_chunked_over_limit_rejected_413(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        limit = 1 * 1024 * 1024
        chunks = [b"x" * limit, b"x" * 10]  # over limit
        send = _FakeSend()
        import asyncio

        asyncio.run(
            mw(
                _http_scope(headers=[]),
                _FakeChunkedReceive(chunks),
                send,
            )
        )

        assert send.messages[0]["status"] == 413

    def test_chunked_empty_body_passes_200(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(
            mw(
                _http_scope(headers=[]),
                _FakeChunkedReceive([]),
                send,
            )
        )

        assert send.messages[0]["status"] == 200


class TestEdgeCases:
    def test_websocket_scope_ignored(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        huge_body = b"x" * (2 * 1024 * 1024)  # 2 MB, over 1 MB limit
        asyncio.run(mw(_ws_scope(), _FakeReceive(body=huge_body), send))

        assert send.messages[0]["status"] == 200

    def test_garbage_content_length_treated_as_none(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        headers = [(b"content-length", b"not-a-number")]
        send = _FakeSend()
        import asyncio

        asyncio.run(
            mw(
                _http_scope(headers=headers),
                _FakeReceive(body=b"tiny body"),
                send,
            )
        )

        assert send.messages[0]["status"] == 200

    def test_negative_content_length_treated_as_under_limit(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        headers = [(b"content-length", b"-1")]
        send = _FakeSend()
        import asyncio

        asyncio.run(
            mw(
                _http_scope(headers=headers),
                _FakeReceive(body=b"tiny body"),
                send,
            )
        )

        assert send.messages[0]["status"] == 200

    def test_body_exceeds_limit_when_content_length_under_declared(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        limit = 1 * 1024 * 1024
        headers = [(b"content-length", b"100")]  # claims 100 bytes
        actual_body = b"x" * (limit + 1)  # actually sends > 1 MB
        send = _FakeSend()
        import asyncio

        asyncio.run(
            mw(
                _http_scope(headers=headers),
                _FakeReceive(body=actual_body),
                send,
            )
        )

        assert send.messages[0]["status"] == 413

    def test_no_headers_passes_small_body(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(
            mw(
                _http_scope(headers=[]),
                _FakeReceive(body=b"small body"),
                send,
            )
        )

        assert send.messages[0]["status"] == 200

    def test_disconnect_during_body_read_passes(self):
        from authglow.middleware.request_body_size import MaxBodySizeMiddleware

        settings = _make_settings(max_request_body_size_mb=1)
        mw = MaxBodySizeMiddleware(_FakeApp(), settings=settings)

        send = _FakeSend()
        import asyncio

        asyncio.run(
            mw(
                _http_scope(headers=[]),
                _FakeReceive(body=b"", include_disconnect=True),
                send,
            )
        )

        assert send.messages[0]["status"] == 200


def _make_settings(**overrides) -> object:
    defaults = {"max_request_body_size_mb": 10}
    settings = _FakeSettings()
    for key, value in {**defaults, **overrides}.items():
        setattr(settings, key, value)
    return settings


class _FakeSettings:
    pass
