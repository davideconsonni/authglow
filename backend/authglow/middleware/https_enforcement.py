"""HTTPS enforcement middleware for AuthGlow.

Redirects HTTP requests to HTTPS in production. Only active when
APP_ENV=production and ENFORCE_HTTPS=true.

Handles both direct connections (checking request.url.scheme) and
reverse-proxy scenarios (checking X-Forwarded-Proto header). The
X-Forwarded-Proto header is only honored when the connecting client
IP is in the trusted_proxies allowlist (VAPT-024).
"""

import ipaddress
from typing import Optional
from urllib.parse import urlunsplit

from authglow.core.config import Settings


class HttpsEnforcementMiddleware:
    def __init__(self, app, settings: Optional[Settings] = None):
        self.app = app
        self._settings = settings

    def _get_settings(self) -> Settings:
        if self._settings is not None:
            return self._settings
        from authglow.core.config import get_settings

        return get_settings()

    def _is_trusted_proxy(self, scope: dict, trusted: list) -> bool:
        client_ip = (scope.get("client") or (None, None))[0]
        if client_ip is None:
            return False
        try:
            client_addr = ipaddress.ip_address(client_ip)
        except ValueError:
            client_addr = None
        for entry in trusted:
            entry = entry.strip()
            try:
                network = ipaddress.ip_network(entry, strict=False)
                if client_addr is not None and client_addr in network:
                    return True
            except ValueError:
                pass
            if client_addr is None and str(client_ip) == entry:
                return True
        return False

    def _is_https(self, scope: dict) -> bool:
        settings = self._get_settings()
        trusted = settings.get_trusted_proxies()
        if trusted and self._is_trusted_proxy(scope, trusted):
            for name, value in scope.get("headers", []):
                header_name: str = name.decode("latin-1").lower()
                if header_name == "x-forwarded-proto":
                    return str(value.decode("latin-1")) == "https"
        scheme: str = str(scope.get("scheme", "http"))
        return scheme == "https"

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = self._get_settings()

        if not (settings.is_production and settings.enforce_https):
            await self.app(scope, receive, send)
            return

        if self._is_https(scope):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "/")
        query_string = scope.get("query_string", b"").decode("latin-1")
        host = ""
        for name, value in scope.get("headers", []):
            if name.decode("latin-1").lower() == "host":
                host = value.decode("latin-1")
                break

        location = urlunsplit(("https", host, path, query_string, ""))
        status = settings.https_redirect_status

        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"location", location.encode("latin-1")),
                    (b"content-length", b"0"),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b"",
            }
        )
