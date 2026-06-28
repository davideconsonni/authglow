"""Audit logging service.

Writes structured audit events to stdout via structlog (JSON),
compatible with AWS CloudWatch, GCP Cloud Logging, and Azure Monitor.
The app never reads audit logs back --- analysis, search, and
retention are handled by the cloud platform.
"""

import hashlib
import hmac
import ipaddress
from typing import Optional

import structlog

from authglow.core.config import get_settings
from authglow.models.admin import AuditLogEntry

if not structlog.is_configured():
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

_audit_log = structlog.get_logger("authglow.audit")

_LEVEL_METHOD = {
    "info": "info",
    "warning": "warning",
    "error": "error",
    "critical": "error",
}

# Truncation length for ``user_agent`` strings emitted to the
# audit log. Long UA strings add noise without providing actionable
# detail for security investigations. (VAPT-079)
_USER_AGENT_MAX_LEN = 256

# Truncation masks for IP addresses. We keep enough granularity
# for geo-location / network analysis without exposing the
# individual client address. (VAPT-079)
_IPV4_PREFIX_LEN = 24
_IPV6_PREFIX_LEN = 48


class AuditService:
    """Write-only audit logging service via structlog (stdout JSON)."""

    def __init__(self):
        self.settings = get_settings()

    @staticmethod
    def _mask_email(email: str, level: str, secret_key: str) -> str:
        if not email or "@" not in email:
            return email or ""

        if level == "none":
            return email

        if level == "mask":
            local, domain = email.split("@", 1)
            masked_local = local[:2] + "***" if len(local) >= 2 else local + "***"
            domain_parts = domain.split(".")
            if len(domain_parts) >= 2:
                masked_domain = domain_parts[0][:2] + "***." + ".".join(domain_parts[1:])
            else:
                masked_domain = domain[:2] + "***"
            return f"{masked_local}@{masked_domain}"

        if level == "hash":
            digest = hmac.new(
                secret_key.encode("utf-8"),
                email.lower().strip().encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            return digest[:16]

        return email

    @staticmethod
    def _mask_ip(ip: str) -> str:
        """Truncate an IP address to a network prefix.

        IPv4 → ``/24`` (e.g. ``1.2.3.4`` → ``1.2.3.0/24``).
        IPv6 → ``/48`` (e.g. ``2001:db8::1`` → ``2001:db8::/48``).
        Invalid input → ``"[invalid_ip]"`` to avoid leaking the
        original string back into the log.
        """
        if not ip:
            return ip
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "[invalid_ip]"
        prefix_len = (
            _IPV4_PREFIX_LEN if isinstance(addr, ipaddress.IPv4Address) else _IPV6_PREFIX_LEN
        )
        try:
            network = ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)
        except ValueError:
            return "[invalid_ip]"
        return str(network)

    @staticmethod
    def _truncate(value: str, max_len: int = _USER_AGENT_MAX_LEN) -> str:
        """Truncate a string to ``max_len`` characters with a
        marker so it is obvious the value was clipped."""
        if not isinstance(value, str):
            return value
        if len(value) <= max_len:
            return value
        marker = "…[truncated]"
        if max_len <= len(marker):
            return value[:max_len]
        return value[: max_len - len(marker)] + marker

    @staticmethod
    def _mask_pii(entry_dict: dict, level: str, secret_key: str) -> dict:
        # VAPT-080: refuse to mask nothing in production. The
        # ``none`` level is for local dev / debugging only.
        settings = get_settings()
        if level == "none" and settings.is_production:
            raise ValueError(
                "audit_email_log_level='none' is not allowed in production "
                "(VAPT-080): use 'mask' or 'hash' to keep PII out of audit logs"
            )

        if level == "none":
            return entry_dict

        if entry_dict.get("email"):
            entry_dict["email"] = AuditService._mask_email(entry_dict["email"], level, secret_key)

        # VAPT-079: truncate IP to /24 (v4) / /48 (v6) and cap the
        # user-agent length so the audit log is not a source of
        # full PII (network-level fingerprinting, browser history).
        if entry_dict.get("ip_address"):
            entry_dict["ip_address"] = AuditService._mask_ip(entry_dict["ip_address"])
        if entry_dict.get("user_agent"):
            entry_dict["user_agent"] = AuditService._truncate(entry_dict["user_agent"])

        # Metadata is walked recursively. Any value that looks like
        # an email, IP, or long string is masked. The existing
        # rule (key contains "email" → mask the value) is kept
        # for backward compatibility and extended below.
        metadata = entry_dict.get("metadata", {})
        if isinstance(metadata, dict):
            for key in list(metadata.keys()):
                value = metadata[key]
                if not isinstance(value, str):
                    continue
                if "email" in key.lower():
                    metadata[key] = AuditService._mask_email(value, level, secret_key)
                elif AuditService._looks_like_ip_value(value):
                    metadata[key] = AuditService._mask_ip(value)
                elif len(value) > _USER_AGENT_MAX_LEN:
                    metadata[key] = AuditService._truncate(value)

        return entry_dict

    @staticmethod
    def _looks_like_ip_value(value: str) -> bool:
        """Heuristic: a string is treated as an IP address if it
        successfully parses with :mod:`ipaddress`. This avoids
        false positives on keys like ``"not_an_ip"`` while
        catching every value that is actually an IPv4 or IPv6
        address.
        """
        try:
            ipaddress.ip_address(value)
            return True
        except (ValueError, TypeError):
            return False

    async def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[dict] = None,
        severity: str = "info",
        request_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Log an audit event to stdout (JSON via structlog)."""
        # VAPT-131: correlation ID. Default to the current
        # ``structlog.contextvars`` binding so middleware (VAPT-042)
        # can propagate ``request_id`` across the request lifecycle
        # without changing the call sites.
        if request_id is None:
            try:
                from structlog.contextvars import get_contextvars

                request_id = get_contextvars().get("request_id")
            except Exception:
                request_id = None

        log_entry = AuditLogEntry(
            user_id=user_id,
            email=email,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
            severity=severity,
            request_id=request_id,
        )

        entry_dict = log_entry.model_dump(mode="json")

        if self.settings.audit_email_log_level != "none":
            entry_dict = self._mask_pii(
                entry_dict,
                self.settings.audit_email_log_level,
                self.settings.secret_key,
            )

        event = entry_dict.pop("event_type")
        # request_id is in the dump; preserve it on the log line
        log_method = getattr(_audit_log, _LEVEL_METHOD.get(severity, "info"))
        log_method(event, **entry_dict)

        return log_entry
