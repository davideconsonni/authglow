"""Audit logging service.

Writes structured audit events to stdout via structlog (JSON),
compatible with AWS CloudWatch, GCP Cloud Logging, and Azure Monitor.
The app never reads audit logs back --- analysis, search, and
retention are handled by the cloud platform.
"""

import hashlib
import hmac
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
    def _mask_pii(entry_dict: dict, level: str, secret_key: str) -> dict:
        if level == "none":
            return entry_dict

        if entry_dict.get("email"):
            entry_dict["email"] = AuditService._mask_email(entry_dict["email"], level, secret_key)

        metadata = entry_dict.get("metadata", {})
        if isinstance(metadata, dict):
            for key in list(metadata.keys()):
                if "email" in key.lower() and isinstance(metadata[key], str):
                    metadata[key] = AuditService._mask_email(metadata[key], level, secret_key)

        return entry_dict

    async def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[dict] = None,
        severity: str = "info",
    ) -> AuditLogEntry:
        """Log an audit event to stdout (JSON via structlog)."""
        log_entry = AuditLogEntry(
            user_id=user_id,
            email=email,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
            severity=severity,
        )

        entry_dict = log_entry.model_dump(mode="json")

        if self.settings.audit_email_log_level != "none":
            entry_dict = self._mask_pii(
                entry_dict,
                self.settings.audit_email_log_level,
                self.settings.secret_key,
            )

        event = entry_dict.pop("event_type")
        log_method = getattr(_audit_log, _LEVEL_METHOD.get(severity, "info"))
        log_method(event, **entry_dict)

        return log_entry
