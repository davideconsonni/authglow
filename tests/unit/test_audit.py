"""Tests for audit logging service --- structlog-based (stdout JSON)."""

import asyncio
import json
import hmac
import hashlib

import pytest
from unittest.mock import patch, MagicMock


class TestAuditLogging:
    def test_log_event_returns_entry(self, audit_service):
        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="login_success",
                user_id="u1",
                email="test@example.com",
            )
        )
        assert entry is not None
        assert entry.event_type == "login_success"
        assert entry.user_id == "u1"

    def test_log_event_with_metadata(self, audit_service):
        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="api_key_used",
                user_id="u2",
                metadata={"key_id": "ak_12345678"},
                severity="info",
            )
        )
        assert entry.event_type == "api_key_used"
        assert entry.metadata["key_id"] == "ak_12345678"

    def test_log_event_severity(self, audit_service):
        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(event_type="account_locked", severity="high")
        )
        assert entry.severity == "high"


class TestEmailMasking:
    def test_mask_email_top_level(self, audit_service, test_settings):
        """Masked email is passed to structlog, original preserved on return."""
        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="login_success",
                user_id="u1",
                email="john.doe@example.com",
            )
        )
        assert entry.email == "john.doe@example.com"

    def test_mask_email_metadata(self, test_settings):
        """Metadata fields with 'email' are masked."""
        from authglow.services.audit import AuditService

        asvc = AuditService()
        entry_dict = {
            "email": "admin@company.com",
            "event_type": "user_updated",
            "metadata": {
                "target_user_email": "alice@example.org",
                "target_user_id": "u2",
            },
        }
        masked = AuditService._mask_pii(
            dict(entry_dict),
            "mask",
            test_settings.secret_key,
        )
        assert masked["email"] == "ad***@co***.com"
        assert masked["metadata"]["target_user_email"] == "al***@ex***.org"
        assert masked["metadata"]["target_user_id"] == "u2"

    def test_mask_email_deterministic(self, test_settings):
        from authglow.services.audit import AuditService

        a = AuditService._mask_email(
            "john@example.com", "mask", test_settings.secret_key
        )
        b = AuditService._mask_email(
            "john@example.com", "mask", test_settings.secret_key
        )
        assert a == b
        assert a == "jo***@ex***.com"

    def test_hash_level_deterministic(self, test_settings):
        from authglow.services.audit import AuditService

        a = AuditService._mask_email(
            "john@example.com", "hash", test_settings.secret_key
        )
        b = AuditService._mask_email(
            "john@example.com", "hash", test_settings.secret_key
        )
        assert a == b
        assert len(a) == 16
        assert "@" not in a

    def test_none_level_preserves_email(self, test_settings):
        from authglow.services.audit import AuditService

        result = AuditService._mask_email(
            "john@example.com", "none", test_settings.secret_key
        )
        assert result == "john@example.com"

    def test_mask_short_email(self, test_settings):
        from authglow.services.audit import AuditService

        result = AuditService._mask_email("a@b.com", "mask", test_settings.secret_key)
        assert result == "a***@b***.com"

    def test_log_event_respects_config_level(
        self, monkeypatch, tmp_path, test_settings
    ):
        from authglow.services.audit import AuditService

        test_settings.audit_email_log_level = "none"
        monkeypatch.setattr(
            "authglow.services.audit.get_settings", lambda: test_settings
        )
        svc = AuditService()

        entry = asyncio.get_event_loop().run_until_complete(
            svc.log_event(
                event_type="login",
                user_id="u1",
                email="plain@example.com",
            )
        )
        assert entry.email == "plain@example.com"


class TestWriteOnlyArchitecture:
    def test_no_file_io_methods_exposed(self):
        """AuditService must not expose any read, delete, or filesystem methods."""
        from authglow.services.audit import AuditService

        forbidden = {
            "get_logs",
            "get_user_login_counts",
            "get_event_counts_by_type",
            "get_logs_by_date",
            "delete_old_logs",
            "get_stats_since",
            "get_stats_timeseries",
            "get_stats_for_date",
            "_get_log_path",
        }
        available = set(AuditService.__dict__.keys())
        assert forbidden.isdisjoint(available), (
            f"AuditService still exposes forbidden methods: {forbidden & available}"
        )

    def test_no_fsspec_dependency(self):
        """AuditService must not import fsspec or AsyncFileSystem."""
        import ast
        import inspect
        from authglow.services.audit import AuditService

        source = inspect.getsource(AuditService)
        tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module)
        assert "fsspec" not in imports
        assert "async_io" not in imports

    def test_structlog_logger_exists(self):
        """Module-level _audit_log logger is configured."""
        from authglow.services.audit import _audit_log

        assert _audit_log is not None
        assert hasattr(_audit_log, "info")
        assert hasattr(_audit_log, "warning")
        assert hasattr(_audit_log, "error")

    def test_log_event_emits_to_structlog(self):
        """Logging emits structured JSON to stdout via structlog."""
        from authglow.services.audit import AuditService, _audit_log

        svc = AuditService()
        with patch.object(_audit_log, "info", wraps=_audit_log.info) as mock_info:
            asyncio.get_event_loop().run_until_complete(
                svc.log_event(
                    event_type="login_success",
                    user_id="u1",
                    email="john@example.com",
                    ip_address="1.2.3.4",
                    severity="info",
                )
            )
            mock_info.assert_called_once()
            call_kwargs = mock_info.call_args[1]
            assert call_kwargs["user_id"] == "u1"
            assert call_kwargs["severity"] == "info"
            assert call_kwargs["ip_address"] == "1.2.3.4"

    def test_warning_severity_uses_warning_method(self):
        from authglow.services.audit import AuditService, _audit_log

        svc = AuditService()
        with patch.object(_audit_log, "warning", wraps=_audit_log.warning) as mock_warn:
            asyncio.get_event_loop().run_until_complete(
                svc.log_event(
                    event_type="login_failed",
                    severity="warning",
                )
            )
            mock_warn.assert_called_once()

    def test_error_severity_uses_error_method(self):
        from authglow.services.audit import AuditService, _audit_log

        svc = AuditService()
        with patch.object(_audit_log, "error", wraps=_audit_log.error) as mock_err:
            asyncio.get_event_loop().run_until_complete(
                svc.log_event(
                    event_type="account_locked",
                    severity="critical",
                )
            )
            mock_err.assert_called_once()
