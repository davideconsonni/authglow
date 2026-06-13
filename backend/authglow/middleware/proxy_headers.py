"""Proxy-headers middleware for AuthGlow.

Rewrites scope["client"] from the X-Forwarded-For header when the
connecting peer is in the trusted_proxies allowlist, so that rate
limiting and audit logging see the real client IP instead of the
reverse proxy's IP (VAPT-025).
"""

import ipaddress
from typing import Optional

from authglow.core.config import Settings


class ProxyHeadersMiddleware:
    def __init__(self, app, settings: Optional[Settings] = None):
        self.app = app
        self._settings = settings

    def _get_settings(self) -> Settings:
        if self._settings is not None:
            return self._settings
        from authglow.core.config import get_settings

        return get_settings()

    def _is_trusted_proxy(self, client_ip: Optional[str], trusted: list) -> bool:
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
            if client_addr is None and client_ip == entry:
                return True
        return False

    def _extract_forwarded_client(self, xff_value: str) -> Optional[str]:
        parts = [p.strip() for p in xff_value.split(",") if p.strip()]
        if not parts:
            return None
        leftmost = parts[0]
        try:
            ipaddress.ip_address(leftmost)
            return leftmost
        except ValueError:
            return None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        settings = self._get_settings()
        trusted = settings.get_trusted_proxies()
        if not trusted:
            await self.app(scope, receive, send)
            return

        peer_ip = (scope.get("client") or (None, None))[0]
        if not self._is_trusted_proxy(peer_ip, trusted):
            await self.app(scope, receive, send)
            return

        xff_value: Optional[str] = None
        for name, value in scope.get("headers", []):
            header_name: str = name.decode("latin-1").lower()
            if header_name == "x-forwarded-for":
                xff_value = value.decode("latin-1")
                break

        if not xff_value:
            await self.app(scope, receive, send)
            return

        real_ip = self._extract_forwarded_client(xff_value)
        if real_ip is None:
            await self.app(scope, receive, send)
            return

        original_port = (scope.get("client") or (None, 0))[1] or 0
        scope["client"] = (real_ip, original_port)

        await self.app(scope, receive, send)
