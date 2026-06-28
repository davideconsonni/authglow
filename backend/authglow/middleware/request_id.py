"""Request-ID correlation middleware for AuthGlow (VAPT-042).

For every HTTP request the middleware:

1. Reads the inbound ``X-Request-ID`` header (if the caller
   supplied one — common when chaining AuthGlow behind another
   service that already generates IDs).
2. Validates the inbound value: must be a printable ASCII
   string of at most 128 characters with no control chars
   or shell metacharacters. Anything that fails validation
   is discarded and replaced with a fresh UUID4 — the goal
   is to prevent log-injection via a malicious
   ``X-Request-ID`` header.
3. Binds the chosen value to ``structlog.contextvars`` under
   the key ``request_id`` so every subsequent
   :func:`structlog.get_logger().info(...)` call (including
   the audit service) automatically carries the correlation
   ID without the call sites having to thread it manually.
4. Adds the same value to the outbound response headers so
   the client can correlate their own logs with ours.
5. Unbinds the contextvar in a ``finally`` block so the
   request_id does not leak to other coroutines that share
   the same asyncio task after the response is sent.

The middleware is registered **last** in ``main.py`` so it
is the outermost wrapper: the contextvar is set before any
other middleware (CORS, security headers, rate limit, etc.)
or the application code runs, and the response header is
appended after the downstream stack has had a chance to
write its own headers (the existing
``SecurityHeadersMiddleware`` pattern is mirrored).
"""

import re
import secrets
from typing import Optional

from structlog.contextvars import bind_contextvars, unbind_contextvars

# Printable ASCII, 1..128 chars, no whitespace, no control
# chars, no shell metacharacters. The character set is a
# conservative superset of "anything a UUID, KSUID, or ULID
# might look like" plus the hyphen / colon separators some
# tracing systems use.
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9_\-:.]{1,128}\Z")

_HEADER_NAME = "x-request-id"
_HEADER_NAME_BYTES = _HEADER_NAME.encode("latin-1")


def _generate_request_id() -> str:
    """Return a fresh correlation ID (UUID4 hex)."""
    return secrets.token_hex(16)


def _sanitize_inbound(value: Optional[str]) -> Optional[str]:
    """Validate an inbound ``X-Request-ID`` header.

    Returns the value unchanged if it matches the safe
    character set, or ``None`` if the value is missing or
    fails validation. The caller is expected to fall back
    to a generated UUID4 when ``None`` is returned.
    """
    if not value:
        return None
    if not _VALID_REQUEST_ID.match(value):
        return None
    return value


class RequestIDMiddleware:
    """ASGI middleware that correlates every request with a
    stable identifier via ``X-Request-ID`` and
    ``structlog.contextvars``."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. Read inbound header.
        inbound: Optional[str] = None
        for name, value in scope.get("headers", []):
            if name == _HEADER_NAME_BYTES:
                try:
                    inbound = value.decode("latin-1")
                except UnicodeDecodeError:
                    inbound = None
                break

        # 2. Sanitise — drop anything that does not look like
        # a correlation ID. This blocks log-injection via a
        # malicious header (e.g. ``X-Request-ID: foo\nFAKE LOG
        # ENTRY {"event_type": "user_deleted"}``).
        request_id = _sanitize_inbound(inbound) or _generate_request_id()

        # 3. Bind to structlog contextvars. ``bind_contextvars``
        # accepts kwargs and merges them into the current
        # context — every subsequent log line carries
        # ``request_id`` automatically.
        bind_contextvars(request_id=request_id)

        # 4. Inject the response header on the way out. We
        # wrap ``send`` so the header is added to the
        # ``http.response.start`` message regardless of what
        # downstream middleware does.
        async def _send(message):
            if message["type"] == "http.response.start":
                # Avoid duplicating the header if a downstream
                # middleware already added it (defensive — the
                # SecurityHeadersMiddleware uses the same
                # pattern).
                existing = message.get("headers", [])
                if not any(name == _HEADER_NAME_BYTES for name, _value in existing):
                    message["headers"] = list(existing) + [
                        (_HEADER_NAME_BYTES, request_id.encode("latin-1"))
                    ]
            await send(message)

        try:
            await self.app(scope, receive, _send)
        finally:
            # 5. Unbind so the contextvar does not leak to
            # other coroutines that share the same asyncio
            # task after the response is sent.
            try:
                unbind_contextvars("request_id")
            except Exception:
                # ``unbind_contextvars`` raises if the key is
                # not bound (e.g. on exception paths) — swallow
                # to keep the middleware idempotent.
                pass
