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
