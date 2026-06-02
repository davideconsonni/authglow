"""Security headers middleware for AuthGlow.

Adds OWASP-recommended security headers to every HTTP response.
HSTS is only applied when APP_ENV=production.
"""

from typing import Optional

from authglow.core.config import Settings


def _add_header(headers: list, name: str, value: Optional[str]) -> None:
    if value:
        headers.append((name.lower(), value))


class SecurityHeadersMiddleware:
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
        is_production = settings.app_env.lower() == "production"
        path = scope.get("path", "")

        headers_to_add: list[tuple[str, str]] = []

        if path in ("/docs", "/redoc"):
            _add_header(
                headers_to_add,
                "content-security-policy",
                "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net "
                "https://fastapi.tiangolo.com; img-src 'self' https://fastapi.tiangolo.com data:;",
            )
        else:
            _add_header(headers_to_add, "content-security-policy", settings.csp_header)
        _add_header(headers_to_add, "x-frame-options", settings.x_frame_options)
        _add_header(headers_to_add, "x-content-type-options", settings.x_content_type_options)
        _add_header(headers_to_add, "referrer-policy", settings.referrer_policy)
        _add_header(headers_to_add, "x-xss-protection", "0")
        _add_header(
            headers_to_add,
            "x-permitted-cross-domain-policies",
            settings.x_permitted_cross_domain_policies,
        )
        if settings.permissions_policy:
            _add_header(headers_to_add, "permissions-policy", settings.permissions_policy)

        if is_production:
            hsts = f"max-age={settings.hsts_max_age}"
            if settings.hsts_include_subdomains:
                hsts += "; includeSubDomains"
            _add_header(headers_to_add, "strict-transport-security", hsts)

        if not headers_to_add:
            await self.app(scope, receive, send)
            return

        headers_to_add_bytes = [
            (name.encode("latin-1"), value.encode("latin-1")) for name, value in headers_to_add
        ]

        async def _send(message):
            if message["type"] == "http.response.start":
                existing = message.get("headers", [])
                existing_names = {h[0].decode("latin-1").lower() for h in existing}
                new_headers = [
                    (name, value)
                    for name, value in headers_to_add_bytes
                    if name.decode("latin-1").lower() not in existing_names
                ]
                message["headers"] = existing + new_headers
            await send(message)

        await self.app(scope, receive, _send)
