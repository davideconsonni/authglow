"""Audit logging service.

Writes structured audit events to storage. The app never reads audit logs
back --- analysis, search, and retention are handled by external log
shipping (CloudWatch, ELK, Datadog, etc.).

Lightweight aggregate stats are written to a separate ``stats/`` directory
for the admin dashboard, independent of the full audit trail.
"""

import hashlib
import hmac
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import fsspec

from authglow.core.config import get_settings
from authglow.core.async_io import AsyncFileSystem
from authglow.core.datetime import utcnow
from authglow.models.admin import AuditLogEntry


class AuditService:
    """Write-only audit logging service."""

    def __init__(self):
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/audit_logs"
        self.stats_path = f"{self.settings.storage_path}/stats"
        self.storage_options = self.settings.get_storage_options()

        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            os.makedirs(self.stats_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend, **self.storage_options
            )

        self._afs = AsyncFileSystem(self.fs)

    def _get_log_path(self, log_id: str) -> str:
        now = utcnow()
        year_month = now.strftime("%Y/%m")
        directory = f"{self.storage_path}/{year_month}"
        if self.settings.storage_backend == "file":
            os.makedirs(directory, exist_ok=True)
        return f"{directory}/{log_id}.json"

    @staticmethod
    def _mask_email(email: str, level: str, secret_key: str) -> str:
        """Mask an email address based on the configured level.

        Levels:
          - ``"mask"``  → ``jo***@ex***.com`` (first 2 chars local + domain prefix)
          - ``"hash"``  → HMAC-SHA256 deterministic hash (16 hex chars)
          - ``"none"``  → returned unchanged
        """
        if not email or "@" not in email:
            return email or ""

        if level == "none":
            return email

        if level == "mask":
            local, domain = email.split("@", 1)
            masked_local = local[:2] + "***" if len(local) >= 2 else local + "***"
            domain_parts = domain.split(".")
            if len(domain_parts) >= 2:
                masked_domain = (
                    domain_parts[0][:2] + "***." + ".".join(domain_parts[1:])
                )
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
        """Mask PII fields in an audit-entry dict *before* persisting."""
        if level == "none":
            return entry_dict

        if entry_dict.get("email"):
            entry_dict["email"] = AuditService._mask_email(
                entry_dict["email"], level, secret_key
            )

        metadata = entry_dict.get("metadata", {})
        if isinstance(metadata, dict):
            for key in list(metadata.keys()):
                if "email" in key.lower() and isinstance(metadata[key], str):
                    metadata[key] = AuditService._mask_email(
                        metadata[key], level, secret_key
                    )

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
        """Log an audit event (write-only)."""
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

        path = self._get_log_path(log_entry.id)
        await self._afs.write_json(path, entry_dict)

        await self._update_stats(event_type, severity)

        return log_entry

    async def _update_stats(self, event_type: str, severity: str):
        """Update lightweight daily aggregate counters.

        These stats files are *not* audit logs --- they are a separate,
        tiny, read-efficient data source for the admin dashboard.
        """
        try:
            today = utcnow().strftime("%Y-%m-%d")
            stats_file = f"{self.stats_path}/{today}.json"

            try:
                stats = await self._afs.read_json(stats_file)
            except Exception:
                stats = {}

            stats[event_type] = stats.get(event_type, 0) + 1
            if severity in ("warning", "error", "critical"):
                stats["_security_events"] = stats.get("_security_events", 0) + 1

            await self._afs.write_json(stats_file, stats)
        except Exception:
            pass

    async def get_stats_since(self, since: datetime) -> dict:
        """Return aggregate event counts from daily stats files since *since*."""
        counts: Dict[str, int] = {}
        try:
            pattern = f"{self.stats_path}/*.json"
            files = await self._afs.glob(pattern)
            since_str = since.strftime("%Y-%m-%d")
            for f in sorted(files):
                filename = f.split("/")[-1].replace(".json", "")
                if filename < since_str:
                    continue
                try:
                    data = await self._afs.read_json(f)
                    for key, val in data.items():
                        counts[key] = counts.get(key, 0) + val
                except Exception:
                    continue
        except Exception:
            pass
        return counts

    async def get_stats_timeseries(self, days: int = 30) -> List[dict]:
        """Return per-day stats for the admin chart (from stats files)."""
        result = []
        start_date = utcnow().replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=days - 1)

        for i in range(days):
            date = start_date + timedelta(days=i)
            date_str = date.strftime("%Y-%m-%d")
            entry = {
                "date": date_str,
                "display_date": date.strftime("%m/%d"),
                "total": 0,
                "success": 0,
                "failed": 0,
                "security": 0,
                "new_users": 0,
            }
            stats_file = f"{self.stats_path}/{date_str}.json"
            try:
                data = await self._afs.read_json(stats_file)
                entry["success"] = data.get("login_success", 0)
                entry["failed"] = data.get("login_failed", 0)
                entry["new_users"] = data.get("user_created", 0)
                entry["security"] = data.get("_security_events", 0)
                entry["total"] = sum(
                    v for k, v in data.items() if not k.startswith("_")
                )
            except Exception:
                pass
            result.append(entry)

        return result
