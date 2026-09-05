"""Audit logging service.

Writes structured audit events to stdout via structlog (JSON),
compatible with AWS CloudWatch, GCP Cloud Logging, and Azure Monitor.
The app never reads audit logs back --- analysis, search, and
retention are handled by the cloud platform.
"""

import ipaddress
import random
from typing import Any, Dict, Optional, Union

import structlog

from authglow.core.config import get_settings
from authglow.core.pii import hash_pii, mask_ip, truncate
from authglow.models.admin import AuditLogEntry
from authglow.models.audit_events import AuditEventType
from authglow.models.audit_metadata import BaseAuditMetadata, validate_metadata

if not structlog.is_configured():
    structlog.configure(
        processors=[
            # VAPT-042: ``merge_contextvars`` propagates the
            # ``request_id`` (and any other contextvar-bound
            # field) set by :class:`RequestIDMiddleware` into
            # every JSON log line, so any structlog logger
            # (not just the audit service) carries the
            # correlation ID without explicit threading.
            structlog.contextvars.merge_contextvars,
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
            # VAPT-081: reuse the centralised PII helper so the
            # same hash format is produced by the audit log and
            # the three persistent record services.
            return hash_pii(email, secret_key)

        return email

    @staticmethod
    def _mask_ip(ip: Optional[str]) -> Optional[str]:
        """Backwards-compatible thin wrapper around
        :func:`authglow.core.pii.mask_ip`."""
        return mask_ip(ip)

    @staticmethod
    def _truncate(value: str, max_len: int = _USER_AGENT_MAX_LEN) -> str:
        """Backwards-compatible thin wrapper around
        :func:`authglow.core.pii.truncate`."""
        return truncate(value, max_len=max_len)

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
            entry_dict["ip_address"] = mask_ip(entry_dict["ip_address"])
        if entry_dict.get("user_agent"):
            entry_dict["user_agent"] = truncate(entry_dict["user_agent"])

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
                    # Honour the chosen ``level`` (mask / hash /
                    # none) so the existing ``mask`` contract is
                    # preserved for callers that use it.
                    metadata[key] = AuditService._mask_email(value, level, secret_key)
                elif AuditService._looks_like_ip_value(value):
                    metadata[key] = mask_ip(value)
                elif len(value) > _USER_AGENT_MAX_LEN:
                    metadata[key] = truncate(value)

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
        event_type: Union[str, AuditEventType],
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Union[Dict[str, Any], BaseAuditMetadata]] = None,
        severity: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        client_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> AuditLogEntry:
        """Log an audit event to stdout (JSON via structlog).

        Args:
            event_type: Event type (string or AuditEventType enum)
            user_id: User ID associated with the event
            email: User email (will be masked per config)
            ip_address: Client IP (will be truncated to /24 or /48)
            user_agent: User agent (will be truncated to 256 chars)
            metadata: Event metadata (dict or typed Pydantic model)
            severity: Override default severity (info, warning, error, critical)
            request_id: Correlation ID from request context
            session_id: Session ID for session-scoped events
            client_id: OAuth2 client ID for client-scoped events
            correlation_id: Cross-request correlation ID (e.g., auth_code -> token)
        """
        # Handle enum event_type
        if isinstance(event_type, AuditEventType):
            event_type_str = event_type.value
            event_category = event_type.category
            default_severity = event_type.default_severity
        else:
            event_type_str = event_type
            # Infer category from event_type string
            from authglow.models.audit_events import AuditEventType as _AuditEventType
            try:
                event_category = _AuditEventType(event_type_str).category
                default_severity = _AuditEventType(event_type_str).default_severity
            except ValueError:
                event_category = "unknown"
                default_severity = "info"

        # Use provided severity or default from enum
        final_severity = severity or default_severity

        # Sampling for high-volume events
        sample_rate = getattr(self.settings, "audit_sample_rate", 1.0)
        if sample_rate < 1.0 and random.random() > sample_rate:
            # Return a dummy entry without logging (sampling)
            return AuditLogEntry(
                user_id=user_id,
                email=email,
                event_type=event_type_str,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata=metadata.model_dump(mode="json", exclude_none=True) if isinstance(metadata, BaseAuditMetadata) else (metadata or {}),
                severity=final_severity,
                request_id=request_id,
                session_id=session_id,
                client_id=client_id,
                correlation_id=correlation_id,
                event_category=event_category,
            )

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

        # Handle typed metadata
        if isinstance(metadata, BaseAuditMetadata):
            metadata_dict = metadata.model_dump(mode="json", exclude_none=True)
        else:
            metadata_dict = metadata or {}

        # Validate metadata against schema if available
        metadata_dict = validate_metadata(event_type_str, metadata_dict)

        log_entry = AuditLogEntry(
            user_id=user_id,
            email=email,
            event_type=event_type_str,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata_dict,
            severity=final_severity,
            request_id=request_id,
            session_id=session_id,
            client_id=client_id,
            correlation_id=correlation_id,
            event_category=event_category,
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
        log_method = getattr(_audit_log, _LEVEL_METHOD.get(final_severity, "info"))
        log_method(event, **entry_dict)

        return log_entry
