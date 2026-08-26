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

    def _extract_forwarded_client(self, xff_value: str, trusted: list) -> Optional[str]:
        """Return the client IP from an X-Forwarded-For chain, anti-spoofing safe.

        Appending proxies (nginx/haproxy default) ADD the caller's IP to the
        RIGHT side of the header, so anything to its LEFT is client-controlled
        and must never be trusted. The walk therefore starts from the
        RIGHTMOST entry and returns the first hop that is NOT a trusted
        proxy ("rightmost-untrusted"). Only when every valid entry belongs
        to the trusted chain do we fall back to the leftmost one — meaning
        the request traversed proxies end-to-end and the originator itself
        is a trusted proxy.
        """
        parts = [p.strip() for p in xff_value.split(",") if p.strip()]
        for part in reversed(parts):
            try:
                ipaddress.ip_address(part)
            except ValueError:
                continue
            if self._is_trusted_proxy(part, trusted):
                continue
            return part
        for part in parts:
            try:
                ipaddress.ip_address(part)
                return part
            except ValueError:
                continue
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

        real_ip = self._extract_forwarded_client(xff_value, trusted)
        if real_ip is None:
            await self.app(scope, receive, send)
            return

        original_port = (scope.get("client") or (None, 0))[1] or 0
        scope["client"] = (real_ip, original_port)

        await self.app(scope, receive, send)
