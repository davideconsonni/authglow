"""Integration tests for the global unhandled-exception handler.

VAPT-074: an unexpected exception must answer with a stable generic
500 — no internals (library messages, paths, tracebacks) in the body —
while the audit stream receives the event for SIEM correlation.
"""

from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app():
    from authglow.api.error_handlers import register_global_error_handler

    app = FastAPI()
    register_global_error_handler(app)

    @app.get("/boom")
    async def boom():
        raise RuntimeError("secret internal detail /tmp/db.json")

    return app


def _build_app_with_request_id():
    from authglow.api.error_handlers import register_global_error_handler
    from authglow.middleware.request_id import RequestIDMiddleware

    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)
    register_global_error_handler(app)

    @app.get("/boom")
    async def boom():
        raise RuntimeError("secret internal detail /tmp/db.json")

    return app


def test_unhandled_exception_returns_generic_500():
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/boom")

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "secret internal detail" not in response.text
    assert "RuntimeError" not in response.text


def test_unhandled_exception_is_audited():
    app = _build_app()
    client = TestClient(app, raise_server_exceptions=False)

    with patch("authglow.api.error_handlers.AuditService") as mock_audit_cls:
        audit = mock_audit_cls.return_value
        audit.log_event = AsyncMock()
        response = client.get("/boom")

    assert response.status_code == 500
    audit.log_event.assert_awaited_once()
    kwargs = audit.log_event.await_args.kwargs
    assert kwargs["event_type"] == "unhandled_exception"
    assert kwargs["severity"] == "error"
    assert kwargs["metadata"]["error_class"] == "RuntimeError"
    assert kwargs["metadata"]["path"] == "/boom"
    assert kwargs["metadata"]["method"] == "GET"


def test_unhandled_exception_body_carries_request_id_matching_header():
    """ZAP-003: the generic 500 body echoes the request correlation id.

    The ``request_id`` in the body must match the ``X-Request-ID``
    response header and the audit entry so the client can reference
    server logs/audit, while the body itself stays free of internals.
    """
    app = _build_app_with_request_id()
    client = TestClient(app, raise_server_exceptions=False)

    with patch("authglow.api.error_handlers.AuditService") as mock_audit_cls:
        audit = mock_audit_cls.return_value
        audit.log_event = AsyncMock()
        response = client.get("/boom")

    assert response.status_code == 500
    body = response.json()
    assert body["detail"] == "Internal server error"
    assert body["request_id"] == response.headers["x-request-id"]
    assert "secret internal detail" not in response.text
    assert "RuntimeError" not in response.text
    kwargs = audit.log_event.await_args.kwargs
    assert kwargs["request_id"] == response.headers["x-request-id"]


def test_unhandled_exception_body_echoes_valid_inbound_request_id():
    """A valid inbound ``X-Request-ID`` is echoed in the 500 body."""
    app = _build_app_with_request_id()
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/boom", headers={"X-Request-ID": "support-ticket-123"})

    assert response.status_code == 500
    assert response.json()["request_id"] == "support-ticket-123"
    assert response.headers["x-request-id"] == "support-ticket-123"
