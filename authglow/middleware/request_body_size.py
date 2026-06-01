"""Request body size limiter middleware for AuthGlow.

Rejects HTTP requests whose body exceeds a configurable maximum size.
Uses Content-Length header for fast pre-flight rejection and pre-reads
the body to enforce the limit for chunked transfer-encoding.
"""

from typing import Optional

from authglow.core.config import Settings


class MaxBodySizeMiddleware:
    def __init__(self, app, settings: Optional[Settings] = None):
        self.app = app
        self._settings = settings

    def _get_settings(self) -> Settings:
        if self._settings is not None:
            return self._settings
        from authglow.core.config import get_settings

        return get_settings()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = self._get_settings()
        max_bytes = settings.max_request_body_size_mb * 1024 * 1024

        content_length = self._get_content_length(scope)
        if content_length is not None and content_length > max_bytes:
            await self._send_413(send, max_bytes)
            return

        body_chunks: list[bytes] = []
        body_total = 0
        more_body = True

        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            body_total += len(chunk)
            more_body = message.get("more_body", False)

            if body_total > max_bytes:
                while more_body:
                    message = await receive()
                    more_body = message.get("more_body", False)
                await self._send_413(send, max_bytes)
                return

            body_chunks.append(chunk)

        chunk_index = 0

        async def _replay_receive():
            nonlocal chunk_index
            if chunk_index >= len(body_chunks):
                return {"type": "http.request", "body": b"", "more_body": False}
            chunk = body_chunks[chunk_index]
            chunk_index += 1
            more = chunk_index < len(body_chunks)
            return {"type": "http.request", "body": chunk, "more_body": more}

        await self.app(scope, _replay_receive, send)

    @staticmethod
    def _get_content_length(scope) -> Optional[int]:
        for header_name, header_value in scope.get("headers", []):
            if header_name == b"content-length":
                try:
                    return int(header_value.decode())
                except (ValueError, UnicodeDecodeError):
                    return None
        return None

    @staticmethod
    async def _send_413(send, max_bytes: int):
        body = (
            b'{"detail":"Request body exceeds maximum allowed size of '
            + str(max_bytes).encode()
            + b' bytes"}'
        )
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )
