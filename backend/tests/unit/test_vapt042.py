"""VAPT-042: RequestIDMiddleware generates / propagates
``X-Request-ID`` and binds it to ``structlog.contextvars`` so
audit log entries (and any other structlog logger) carry the
correlation ID across the request lifecycle.

Tested invariants:

* inbound ``X-Request-ID`` is propagated unchanged to the
  response (when the value passes the safety filter);
* the middleware generates a UUID4 hex value when the
  inbound header is missing;
* the inbound value is sanitised (log-injection via a
  malicious header is rejected);
* the structlog contextvar is bound for the lifetime of the
  request and unbound after the response is sent;
* non-HTTP scopes (websocket, lifespan) are passed through
  untouched.
"""

import re
from typing import List, Tuple

import pytest
from structlog.contextvars import get_contextvars

from authglow.middleware.request_id import (
    RequestIDMiddleware,
    _generate_request_id,
    _sanitize_inbound,
)

# ---------------------------------------------------------------------------
# Helpers — build ASGI scope / receive / send stubs
# ---------------------------------------------------------------------------


def _build_scope(headers: List[Tuple[str, str]] = None) -> dict:
    """Return a minimal ``http`` ASGI scope with the given headers."""
    asgi_headers = [
        (name.lower().encode("latin-1"), value.encode("latin-1")) for name, value in (headers or [])
    ]
    return {
        "type": "http",
        "method": "GET",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": asgi_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }


class _SendCapture:
    """Captures the ASGI messages a middleware emits."""

    def __init__(self) -> None:
        self.messages: List[dict] = []

    async def __call__(self, message: dict) -> None:
        self.messages.append(message)


class _ReceiveOnce:
    """Returns a single ``http.request`` message (the ASGI
    request body, which the test app does not consume)."""

    def __init__(self) -> None:
        self.delivered = False

    async def __call__(self) -> dict:
        if not self.delivered:
            self.delivered = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}


async def _run_middleware(app, scope, headers_in_response=None):
    """Run the middleware stack with a downstream app that
    returns a fixed body and (optionally) pre-set headers."""
    send = _SendCapture()
    receive = _ReceiveOnce()

    async def downstream_app(scope_, receive_, send_):
        if headers_in_response is not None:
            await send_(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": list(headers_in_response),
                }
            )
        else:
            await send_(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [],
                }
            )
        await send_({"type": "http.response.body", "body": b"ok"})
        return None

    wrapped = RequestIDMiddleware(downstream_app)
    await wrapped(scope, receive, send)
    return send


def _response_header_value(send: _SendCapture, name: str) -> str:
    """Return the value of the named response header, or ``None``."""
    for message in send.messages:
        if message["type"] == "http.response.start":
            for hdr_name, hdr_value in message.get("headers", []):
                if hdr_name.decode("latin-1").lower() == name.lower():
                    return hdr_value.decode("latin-1")
    return None  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Sanitiser — unit tests
# ---------------------------------------------------------------------------


class TestVapt042SanitizeInbound:
    def test_none_input_returns_none(self):
        assert _sanitize_inbound(None) is None

    def test_empty_string_returns_none(self):
        assert _sanitize_inbound("") is None

    def test_uuid_hex_passes_through(self):
        assert _sanitize_inbound("abc123def456") == "abc123def456"

    def test_uuid_with_hyphens_passes_through(self):
        assert (
            _sanitize_inbound("550e8400-e29b-41d4-a716-446655440000")
            == "550e8400-e29b-41d4-a716-446655440000"
        )

    def test_ksuid_format_passes_through(self):
        assert _sanitize_inbound("1eyM55Ez9koX5D4N9k1Hg") == "1eyM55Ez9koX5D4N9k1Hg"

    def test_colon_separator_passes_through(self):
        # Some tracing systems use ``trace:span`` style IDs.
        assert _sanitize_inbound("trace:span:42") == "trace:span:42"

    def test_log_injection_with_newline_rejected(self):
        # A header with a newline would let the attacker inject
        # extra JSON log lines; the sanitiser must reject it.
        assert _sanitize_inbound("good\nFAKE LOG ENTRY") is None

    def test_log_injection_with_carriage_return_rejected(self):
        assert _sanitize_inbound("good\rFAKE") is None

    def test_oversized_value_rejected(self):
        # 129 chars exceeds the 128-char cap.
        assert _sanitize_inbound("a" * 129) is None

    def test_exactly_128_chars_passes_through(self):
        # Boundary case.
        assert _sanitize_inbound("a" * 128) == "a" * 128

    def test_whitespace_rejected(self):
        # Spaces / tabs would split log entries.
        assert _sanitize_inbound("abc 123") is None
        assert _sanitize_inbound("abc\t123") is None

    def test_control_chars_rejected(self):
        assert _sanitize_inbound("abc\x00def") is None

    def test_shell_metachars_rejected(self):
        # A header containing shell redirection would not
        # directly break the audit log (it's JSON-encoded
        # anyway) but it could break downstream consumers that
        # grep the logs — reject by default.
        assert _sanitize_inbound("abc;rm -rf /") is None
        assert _sanitize_inbound("abc|whoami") is None
        assert _sanitize_inbound("abc&exit") is None

    def test_generate_request_id_is_uuid4_hex(self):
        rid = _generate_request_id()
        # UUID4 hex = 32 lowercase hex chars.
        assert re.fullmatch(r"[0-9a-f]{32}", rid)


# ---------------------------------------------------------------------------
# Middleware — ASGI roundtrip
# ---------------------------------------------------------------------------


class TestVapt042MiddlewareHttp:
    @pytest.mark.asyncio
    async def test_generates_request_id_when_header_missing(self):
        scope = _build_scope(headers=[])
        send = await _run_middleware(None, scope)
        rid = _response_header_value(send, "X-Request-ID")
        assert rid is not None
        assert re.fullmatch(r"[0-9a-f]{32}", rid), (
            f"Generated request_id must be UUID4 hex, got {rid!r}"
        )

    @pytest.mark.asyncio
    async def test_propagates_inbound_request_id(self):
        scope = _build_scope(headers=[("X-Request-ID", "client-supplied-id-1234")])
        send = await _run_middleware(None, scope)
        assert _response_header_value(send, "X-Request-ID") == "client-supplied-id-1234"

    @pytest.mark.asyncio
    async def test_discards_unsafe_inbound_and_generates_fresh(self):
        scope = _build_scope(headers=[("X-Request-ID", "bad\nvalue")])
        send = await _run_middleware(None, scope)
        rid = _response_header_value(send, "X-Request-ID")
        assert rid != "bad\nvalue"
        # A fresh UUID4 hex is generated instead.
        assert re.fullmatch(r"[0-9a-f]{32}", rid)

    @pytest.mark.asyncio
    async def test_discards_oversized_inbound(self):
        scope = _build_scope(headers=[("X-Request-ID", "x" * 200)])
        send = await _run_middleware(None, scope)
        rid = _response_header_value(send, "X-Request-ID")
        assert rid != "x" * 200
        assert re.fullmatch(r"[0-9a-f]{32}", rid)

    @pytest.mark.asyncio
    async def test_header_lookup_is_case_insensitive(self):
        # ASGI normalises header names to lowercase; the
        # middleware must still match if a proxy forwards
        # an oddly-cased header. We can only test the
        # normalised form, but the request must also work
        # when the lowercase ``x-request-id`` is sent.
        scope = _build_scope(headers=[("x-request-id", "lowercase-id-abc")])
        send = await _run_middleware(None, scope)
        assert _response_header_value(send, "X-Request-ID") == "lowercase-id-abc"

    @pytest.mark.asyncio
    async def test_does_not_duplicate_header_when_app_sets_one(self):
        """If the downstream app already emitted a
        ``x-request-id`` header (e.g. via a test fixture), the
        middleware must not double-set it."""
        existing = [
            ("content-type".encode("latin-1"), b"text/plain"),
            ("x-request-id".encode("latin-1"), b"app-supplied-id"),
        ]
        scope = _build_scope(headers=[("X-Request-ID", "inbound-id")])
        send = await _run_middleware(None, scope, headers_in_response=existing)
        # The app's header is preserved unchanged.
        assert _response_header_value(send, "X-Request-ID") == "app-supplied-id"


class TestVapt042MiddlewareNonHttp:
    @pytest.mark.asyncio
    async def test_non_http_scope_passes_through(self):
        send = _SendCapture()
        receive = _ReceiveOnce()

        async def downstream_app(scope_, receive_, send_):
            await send_({"type": "websocket.connect"})
            return None

        wrapped = RequestIDMiddleware(downstream_app)
        scope = {"type": "websocket", "path": "/ws"}
        await wrapped(scope, receive, send)
        # The downstream message is delivered unchanged — no
        # X-Request-ID was added (websocket frames don't carry
        # HTTP headers in the same way).
        assert len(send.messages) == 1
        assert send.messages[0]["type"] == "websocket.connect"
        # And the contextvar is NOT bound (we never ran the
        # http branch).
        assert "request_id" not in get_contextvars()


class TestVapt042ContextvarLifecycle:
    @pytest.mark.asyncio
    async def test_contextvar_is_bound_during_request(self):
        scope = _build_scope(headers=[("X-Request-ID", "trace-12345")])
        observed: List[dict] = []

        async def downstream_app(scope_, receive_, send_):
            # Capture the contextvar while the request is in
            # flight — this is what the audit service sees.
            observed.append(dict(get_contextvars()))
            await send_({"type": "http.response.start", "status": 200, "headers": []})
            await send_({"type": "http.response.body", "body": b"ok"})

        receive = _ReceiveOnce()
        send = _SendCapture()
        await RequestIDMiddleware(downstream_app)(scope, receive, send)

        assert len(observed) == 1
        assert observed[0].get("request_id") == "trace-12345"

    @pytest.mark.asyncio
    async def test_contextvar_is_unbound_after_request(self):
        scope = _build_scope(headers=[("X-Request-ID", "trace-12345")])

        async def downstream_app(scope_, receive_, send_):
            await send_({"type": "http.response.start", "status": 200, "headers": []})
            await send_({"type": "http.response.body", "body": b"ok"})

        receive = _ReceiveOnce()
        send = _SendCapture()
        await RequestIDMiddleware(downstream_app)(scope, receive, send)

        # After the request is done, the contextvar must be
        # unbound — otherwise a subsequent coroutine sharing
        # the same asyncio task would see a stale request_id.
        assert "request_id" not in get_contextvars()

    @pytest.mark.asyncio
    async def test_contextvar_unbinding_works_even_on_exception(self):
        scope = _build_scope(headers=[("X-Request-ID", "trace-error")])

        async def downstream_app(scope_, receive_, send_):
            raise RuntimeError("downstream blew up")

        receive = _ReceiveOnce()
        send = _SendCapture()
        with pytest.raises(RuntimeError, match="downstream blew up"):
            await RequestIDMiddleware(downstream_app)(scope, receive, send)

        # Even on the exception path, the contextvar is cleaned up.
        assert "request_id" not in get_contextvars()


class TestVapt042HeaderPassthrough:
    @pytest.mark.asyncio
    async def test_body_message_passes_through_untouched(self):
        """The middleware must not interfere with the body
        frames of the response — only the start frame is
        rewritten to add the header."""
        scope = _build_scope(headers=[])

        async def downstream_app(scope_, receive_, send_):
            await send_({"type": "http.response.start", "status": 200, "headers": []})
            await send_(
                {
                    "type": "http.response.body",
                    "body": b"hello world",
                    "more_body": False,
                }
            )

        receive = _ReceiveOnce()
        send = _SendCapture()
        await RequestIDMiddleware(downstream_app)(scope, receive, send)

        # Two messages: start + body. The start has the
        # X-Request-ID header; the body is the original.
        assert [m["type"] for m in send.messages] == [
            "http.response.start",
            "http.response.body",
        ]
        assert send.messages[1]["body"] == b"hello world"


class TestVapt042MiddlewareAuditServiceIntegration:
    """End-to-end: the middleware binds the request_id to the
    contextvar, the audit service picks it up automatically
    (no explicit threading)."""

    @pytest.mark.asyncio
    async def test_audit_event_picks_up_inbound_request_id(self):
        from structlog.contextvars import clear_contextvars

        from authglow.services.audit import AuditService

        clear_contextvars()
        scope = _build_scope(headers=[("X-Request-ID", "trace-end-to-end-12345")])

        captured: dict = {}

        async def downstream_app(scope_, receive_, send_):
            # The audit service reads the contextvar that the
            # middleware just bound — this is the integration
            # we are testing.
            entry = await AuditService().log_event(
                event_type="test_event",
                user_id="u-1",
            )
            captured["request_id"] = entry.request_id
            await send_({"type": "http.response.start", "status": 200, "headers": []})
            await send_({"type": "http.response.body", "body": b"ok"})

        receive = _ReceiveOnce()
        send = _SendCapture()
        await RequestIDMiddleware(downstream_app)(scope, receive, send)

        # The audit entry's request_id is exactly the inbound
        # X-Request-ID — no explicit threading required.
        assert captured["request_id"] == "trace-end-to-end-12345"
        # And the response carries the same header.
        assert _response_header_value(send, "X-Request-ID") == "trace-end-to-end-12345"

    @pytest.mark.asyncio
    async def test_audit_event_picks_up_generated_request_id(self):
        from structlog.contextvars import clear_contextvars

        from authglow.services.audit import AuditService

        clear_contextvars()
        scope = _build_scope(headers=[])  # no inbound header

        captured: dict = {}

        async def downstream_app(scope_, receive_, send_):
            entry = await AuditService().log_event(
                event_type="test_event",
                user_id="u-1",
            )
            captured["request_id"] = entry.request_id
            await send_({"type": "http.response.start", "status": 200, "headers": []})
            await send_({"type": "http.response.body", "body": b"ok"})

        receive = _ReceiveOnce()
        send = _SendCapture()
        await RequestIDMiddleware(downstream_app)(scope, receive, send)

        # The generated request_id is a UUID4 hex.
        assert captured["request_id"] is not None
        assert re.fullmatch(r"[0-9a-f]{32}", captured["request_id"])
        # And it matches the response header.
        assert _response_header_value(send, "X-Request-ID") == captured["request_id"]
