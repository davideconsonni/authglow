"""Global CSRF protection for cookie-authenticated state changes."""

from fastapi import Request
from fastapi.responses import JSONResponse

from authglow.core.config import get_settings
from authglow.services.csrf import CSRFTokenService, get_or_create_session_id


class CSRFMiddleware:
    """Require a one-time CSRF token for authenticated cookie mutations."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        settings = get_settings()
        unsafe = request.method in {"POST", "PUT", "PATCH", "DELETE"}
        has_access_cookie = bool(request.cookies.get(settings.auth_cookie_access_name))
        if not unsafe or not has_access_cookie or request.url.path == "/api/oauth2/csrf-token":
            await self.app(scope, receive, send)
            return

        origin = request.headers.get("origin")
        allowed_origins = set(settings.get_cors_origins())
        if origin and origin not in allowed_origins:
            response = JSONResponse(status_code=403, content={"detail": "Untrusted request origin"})
            await response(scope, receive, send)
            return

        csrf_token = request.headers.get("x-csrf-token")
        session_id = get_or_create_session_id(request)
        if not csrf_token or not await CSRFTokenService(settings=settings).validate_token(session_id, csrf_token):
            response = JSONResponse(status_code=403, content={"detail": "CSRF token required"})
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
