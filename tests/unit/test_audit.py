import pytest
from datetime import datetime, timedelta, timezone


class TestAuditLogging:
    def test_log_event(self, audit_service):
        import asyncio

        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="login_success",
                user_id="test-user-1",
                email="test@example.com",
            )
        )
        assert entry is not None
        assert entry.event_type == "login_success"
        assert entry.user_id == "test-user-1"

    def test_log_event_with_metadata(self, audit_service):
        import asyncio

        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="api_key_used",
                user_id="test-user-2",
                metadata={"key_id": "ak_12345678"},
                severity="info",
            )
        )
        assert entry.event_type == "api_key_used"
        assert entry.metadata["key_id"] == "ak_12345678"

    def test_log_event_severity(self, audit_service):
        import asyncio

        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(event_type="account_locked", severity="high")
        )
        assert entry.severity == "high"


class TestAuditFiltering:
    def _create_logs(self, audit_service, events):
        import asyncio

        for event_type, user_id, severity in events:
            asyncio.get_event_loop().run_until_complete(
                audit_service.log_event(
                    event_type=event_type, user_id=user_id, severity=severity
                )
            )

    def test_filter_event_type_exact_match(self, audit_service):
        import asyncio

        self._create_logs(
            audit_service,
            [
                ("login_success", "u1", "info"),
                ("login_failed", "u2", "warning"),
                ("login_success_with_mfa", "u3", "info"),
                ("user_created", "u4", "info"),
            ],
        )
        from authglow.models.admin import AuditLogFilter

        logs = asyncio.get_event_loop().run_until_complete(
            audit_service.get_logs(
                filters=AuditLogFilter(event_type="login_success"), limit=100
            )
        )
        assert len(logs) == 1, (
            f"Expected exactly 1 result for 'login_success', "
            f"got {len(logs)}: {[l.event_type for l in logs]}"
        )
        assert logs[0].event_type == "login_success"

    def test_filter_event_type_no_substring_match(self, audit_service):
        import asyncio

        self._create_logs(
            audit_service,
            [
                ("login_failed", "u1", "warning"),
                ("login_success", "u2", "info"),
                ("login_success_with_mfa", "u3", "info"),
            ],
        )
        from authglow.models.admin import AuditLogFilter

        logs = asyncio.get_event_loop().run_until_complete(
            audit_service.get_logs(
                filters=AuditLogFilter(event_type="login"), limit=100
            )
        )
        assert len(logs) == 0, (
            f"Expected 0 results for substring 'login', "
            f"got {len(logs)}: {[l.event_type for l in logs]}"
        )

    def test_filter_event_type_distinct_prefix(self, audit_service):
        import asyncio

        self._create_logs(
            audit_service,
            [
                ("login_failed", "u1", "warning"),
                ("login_success", "u2", "info"),
                ("login_success_with_mfa", "u3", "info"),
                ("password_reset_requested", "u4", "info"),
            ],
        )
        from authglow.models.admin import AuditLogFilter

        logs = asyncio.get_event_loop().run_until_complete(
            audit_service.get_logs(
                filters=AuditLogFilter(event_type="login_failed"), limit=100
            )
        )
        assert len(logs) == 1
        assert logs[0].event_type == "login_failed"

    def test_filter_by_severity(self, audit_service):
        import asyncio

        self._create_logs(
            audit_service,
            [
                ("login_success", "u1", "info"),
                ("login_failed", "u2", "warning"),
                ("account_locked", "u3", "high"),
            ],
        )
        from authglow.models.admin import AuditLogFilter

        logs = asyncio.get_event_loop().run_until_complete(
            audit_service.get_logs(
                filters=AuditLogFilter(severity="warning"), limit=100
            )
        )
        for log in logs:
            assert log.severity == "warning"


class TestAuditCleanup:
    def test_delete_old_logs(self, audit_service):
        import asyncio

        asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(event_type="old_event")
        )
        result = asyncio.get_event_loop().run_until_complete(
            audit_service.delete_old_logs(days=0)
        )
        assert isinstance(result, (int, type(None)))
