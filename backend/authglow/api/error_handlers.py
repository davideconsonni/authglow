"""Global application error handlers.

``register_global_error_handler`` installs the catch-all for unhandled
exceptions (VAPT-074): never leak internals to the client — answer with
a stable generic 500 and leave the details (traceback + request_id
correlation via structlog contextvars, VAPT-131) in the audit stream.
Wired once per application in ``backend/main.py``.
"""

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from authglow.services.audit import AuditService

_logger = structlog.get_logger("authglow.audit")


def register_global_error_handler(app: FastAPI) -> None:
    """Register the catch-all handler for unhandled exceptions."""

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        await AuditService().log_event(
            event_type="unhandled_exception",
            severity="error",
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
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
