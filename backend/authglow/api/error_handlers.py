"""Global application error handlers.

``register_global_error_handler`` installs the catch-all for unhandled
exceptions (VAPT-074): never leak internals to the client — answer with
a stable generic 500 and leave the details (traceback + request_id
correlation via structlog contextvars, VAPT-131) in the audit stream.
Wired once per application in ``backend/main.py``.
"""

from typing import Any, Dict, Optional

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from structlog.contextvars import get_contextvars

from authglow.middleware.request_id import REQUEST_ID_SCOPE_KEY
from authglow.services.audit import AuditService

_logger = structlog.get_logger("authglow.audit")


def register_global_error_handler(app: FastAPI) -> None:
    """Register the catch-all handler for unhandled exceptions."""

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # ZAP-003: echo the request correlation id in the generic body so
        # the client can reference it against the server logs/audit. The
        # id is already sanitised by RequestIDMiddleware (VAPT-042) and is
        # never derived from the exception, so no internals can leak
        # through it.
        #
        # NOTE: Starlette installs an ``Exception`` handler on the
        # outermost ServerErrorMiddleware (``build_middleware_stack``),
        # i.e. OUTSIDE RequestIDMiddleware — by the time we run, the
        # structlog contextvar is already unbound (middleware ``finally``)
        # and only the shared ASGI scope still carries the id. Hence scope
        # first, contextvars as fallback. Without the middleware (e.g. bare
        # test apps) there is no id and the body keeps its historic shape.
        request_id = request.scope.get(REQUEST_ID_SCOPE_KEY)
        if not request_id:
            try:
                request_id = get_contextvars().get("request_id")
            except Exception:
                request_id = None
        body: Dict[str, Any] = {"detail": "Internal server error"}
        headers: Optional[Dict[str, str]] = None
        if request_id:
            body["request_id"] = request_id
            # The middleware already exited, so it cannot append its
            # header itself — set it here to keep header/body/audit aligned.
            headers = {"x-request-id": request_id}
        await AuditService().log_event(
            event_type="unhandled_exception",
            severity="error",
            request_id=request_id,
            metadata={
                "path": request.url.path,
                "method": request.method,
                "error_class": type(exc).__name__,
            },
        )
        _logger.error(
            "unhandled_exception_traceback",
            path=request.url.path,
            method=request.method,
            exc_info=exc,
        )
        return JSONResponse(status_code=500, content=body, headers=headers)
