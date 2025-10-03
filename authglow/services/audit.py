"""Audit logging service."""

import json
import os
from datetime import datetime, timedelta
from typing import List, Optional
import fsspec

from authglow.core.config import get_settings
from authglow.models.admin import AuditLogEntry, AuditLogFilter


class AuditService:
    """Service for audit logging."""

    def __init__(self):
        """Initialize audit service with settings."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/audit_logs"
        self.storage_options = self.settings.get_storage_options()

        # Initialize filesystem
        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend,
                **self.storage_options
            )

    def _get_log_path(self, log_id: str) -> str:
        """Get path for a log entry (organized by date)."""
        # Organize logs by year/month for better performance
        now = datetime.utcnow()
        year_month = now.strftime("%Y/%m")
        directory = f"{self.storage_path}/{year_month}"

        # Create directory if it doesn't exist
        if self.settings.storage_backend == "file":
            os.makedirs(directory, exist_ok=True)

        return f"{directory}/{log_id}.json"

    async def log_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        email: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[dict] = None,
        severity: str = "info"
    ) -> AuditLogEntry:
        """Log an audit event."""
        log_entry = AuditLogEntry(
            user_id=user_id,
            email=email,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
            severity=severity
        )

        path = self._get_log_path(log_entry.id)
        with self.fs.open(path, "w") as f:
            json.dump(log_entry.model_dump(mode="json"), f, indent=2, default=str)

        return log_entry

    async def get_logs(
        self,
        filters: Optional[AuditLogFilter] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditLogEntry]:
        """Get audit logs with filtering."""
        logs = []

        try:
            # Get all log files (search recent months first)
            pattern = f"{self.storage_path}/**/*.json"
            files = self.fs.glob(pattern)

            # Sort by modification time (newest first)
            files_with_time = []
            for file_path in files:
                try:
                    info = self.fs.info(file_path)
                    mtime = info.get('mtime', 0)
                    files_with_time.append((file_path, mtime))
                except:
                    files_with_time.append((file_path, 0))

            files_with_time.sort(key=lambda x: x[1], reverse=True)

            # Process files
            for file_path, _ in files_with_time:
                if len(logs) >= limit + offset:
                    break

                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        log_entry = AuditLogEntry(**data)

                        # Apply filters
                        if filters:
                            if filters.user_id and log_entry.user_id != filters.user_id:
                                continue
                            if filters.event_type and filters.event_type.lower() not in log_entry.event_type.lower():
                                continue
                            if filters.severity and log_entry.severity != filters.severity:
                                continue
                            if filters.start_date and log_entry.timestamp < filters.start_date:
                                continue
                            if filters.end_date and log_entry.timestamp > filters.end_date:
                                continue
                            if filters.search:
                                search_lower = filters.search.lower()
                                if not (
                                    (log_entry.email and search_lower in log_entry.email.lower()) or
                                    search_lower in log_entry.event_type.lower() or
                                    search_lower in str(log_entry.metadata).lower()
                                ):
                                    continue

                        logs.append(log_entry)

                except Exception:
                    continue

            # Apply pagination
            return logs[offset:offset + limit]

        except Exception:
            return []

    async def get_event_counts_by_type(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> dict:
        """Get count of events by type."""
        counts = {}

        try:
            pattern = f"{self.storage_path}/**/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        log_entry = AuditLogEntry(**data)

                        # Apply date filters
                        if start_date and log_entry.timestamp < start_date:
                            continue
                        if end_date and log_entry.timestamp > end_date:
                            continue

                        event_type = log_entry.event_type
                        counts[event_type] = counts.get(event_type, 0) + 1

                except Exception:
                    continue

            return counts

        except Exception:
            return {}

    async def get_logs_by_date(
        self,
        days: int = 30
    ) -> List[dict]:
        """Get log counts grouped by date."""
        result = []
        start_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days-1)

        # Initialize result with all dates
        for i in range(days):
            date = start_date + timedelta(days=i)
            result.append({
                "date": date.strftime("%Y-%m-%d"),
                "display_date": date.strftime("%m/%d"),  # For display
                "total": 0,
                "success": 0,
                "failed": 0,
                "security": 0,
                "new_users": 0
            })

        try:
            pattern = f"{self.storage_path}/**/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        log_entry = AuditLogEntry(**data)

                        if log_entry.timestamp < start_date:
                            continue

                        date_str = log_entry.timestamp.strftime("%Y-%m-%d")

                        # Find matching date in result
                        for day_data in result:
                            if day_data["date"] == date_str:
                                day_data["total"] += 1

                                # Count success logins
                                if log_entry.event_type == "login_success":
                                    day_data["success"] += 1

                                # Count failed logins (separate if, not elif)
                                if log_entry.event_type == "login_failed":
                                    day_data["failed"] += 1

                                # Count new users
                                if log_entry.event_type == "user_created":
                                    day_data["new_users"] += 1

                                # Count security events
                                if log_entry.severity in ["warning", "error", "critical"]:
                                    day_data["security"] += 1

                                break

                except Exception:
                    continue

        except Exception:
            pass

        return result

    async def delete_old_logs(self, days: int = 365):
        """Delete logs older than specified days."""
        cutoff_date = datetime.utcnow() - timedelta(days=days)

        try:
            pattern = f"{self.storage_path}/**/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        log_entry = AuditLogEntry(**data)

                        if log_entry.timestamp < cutoff_date:
                            self.fs.rm(file_path)

                except Exception:
                    continue

        except Exception:
            pass
