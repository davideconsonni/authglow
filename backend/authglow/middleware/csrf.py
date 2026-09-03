"""Global CSRF protection for cookie-authenticated state changes."""

from fastapi import Request
from fastapi.responses import JSONResponse

from authglow.core.config import get_settings
from authglow.services.audit import AuditService
from authglow.services.csrf import (
    SESSION_ID_COOKIE,
    CSRFTokenService,
    get_or_create_session_id,
)

_EXEMPT_PATHS = {"/api/oauth2/csrf-token"}


class CSRFMiddleware:
    """Require a CSRF token for cookie-carrying state mutations.

    T0-1 (VAPT-066): the gate covers every unsafe request that
    presents any of the ambient session cookies — access, refresh, or
    the CSRF session id itself (so the first-party login POST, which
    runs before the access cookie exists, is covered too). Requests
    carrying explicit credentials (``Authorization`` / ``X-API-Key``
    headers) bypass the gate: a cross-site request cannot attach
    attacker-chosen custom headers (CORS preflight), so those callers
    are CSRF-immune by construction. Validations are non-consuming so
    parallel in-flight requests and any endpoint-level double-check
    cannot strand a token.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        settings = get_settings()
        unsafe = request.method in {"POST", "PUT", "PATCH", "DELETE"}
        cookies = request.cookies
        has_session_cookie = bool(
            cookies.get(settings.auth_cookie_access_name)
            or cookies.get(settings.auth_cookie_refresh_name)
            or cookies.get(SESSION_ID_COOKIE)
        )
        has_explicit_credentials = bool(
            request.headers.get("authorization") or request.headers.get("x-api-key")
        )
        if (
            not unsafe
            or not has_session_cookie
            or has_explicit_credentials
            or request.url.path in _EXEMPT_PATHS
        ):
            await self.app(scope, receive, send)
            return

        origin = request.headers.get("origin")
        allowed_origins = set(settings.get_cors_origins())
        if origin and origin not in allowed_origins:
            await self._reject(
                scope, receive, send, request, "untrusted_origin", "Untrusted request origin"
            )
            return

        csrf_token = request.headers.get("x-csrf-token")
        session_id = get_or_create_session_id(request)
        if not csrf_token or not await CSRFTokenService(settings=settings).validate_token(
            session_id, csrf_token
        ):
            await self._reject(
                scope,
                receive,
                send,
                request,
                "csrf_token_missing_or_invalid",
                "CSRF token required",
            )
            return

        await self.app(scope, receive, send)

    async def _reject(
        self, scope, receive, send, request: Request, reason: str, detail: str
    ) -> None:
        """Audit the rejection (SIEM-visible trail) and answer 403."""
        try:
            await AuditService().log_event(
                event_type="csrf_token_mismatch",
                ip_address=request.client.host if request.client else None,
                severity="warning",
                metadata={
                    "reason": reason,
                    "path": request.url.path,
                    "origin": request.headers.get("origin"),
                },
            )
        except Exception:
            pass
        response = JSONResponse(status_code=403, content={"detail": detail})
        await response(scope, receive, send)
