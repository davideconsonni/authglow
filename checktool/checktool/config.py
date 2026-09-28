"""Runtime configuration for the checktool."""

from __future__ import annotations

import ipaddress
import secrets
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

DEFAULT_BASE_URL = "http://127.0.0.1:8001"

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


@dataclass
class CheckConfig:
    """Everything the run needs, resolved once in ``cli.main``."""

    base_url: str = DEFAULT_BASE_URL
    email: Optional[str] = None
    password: Optional[str] = None
    setup_token: Optional[str] = None
    yes: bool = False
    verbose: bool = False
    timeout: float = 20.0
    relax_rate_limits: bool = False
    report_path: Optional[str] = None
    interactive: bool = False
    show_curl: bool = False
    show_secrets: bool = True
    curl_shell: Optional[str] = None
    run_id: str = field(default_factory=lambda: secrets.token_hex(3))

    @property
    def namespace(self) -> str:
        """Unique per-run prefix used to name every created fixture."""
        return f"ct-{self.run_id}"

    @property
    def normalized_url(self) -> str:
        return self.base_url.rstrip("/")

    @property
    def host(self) -> str:
        return urlparse(self.normalized_url).hostname or ""

    @property
    def is_local(self) -> bool:
        """True for loopback targets (localhost/127.0.0.1/::1/0.0.0.0)."""
        host = self.host
        if host in _LOOPBACK_HOSTS:
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    @property
    def mode(self) -> str:
        return "local" if self.is_local else "remote"
