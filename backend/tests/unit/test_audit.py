"""Tests for audit logging service --- structlog-based (stdout JSON)."""

import asyncio
from unittest.mock import patch

import pytest


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

        a = AuditService._mask_email("john@example.com", "mask", test_settings.secret_key)
        b = AuditService._mask_email("john@example.com", "mask", test_settings.secret_key)
        assert a == b
        assert a == "jo***@ex***.com"

    def test_hash_level_deterministic(self, test_settings):
        from authglow.services.audit import AuditService

        a = AuditService._mask_email("john@example.com", "hash", test_settings.secret_key)
        b = AuditService._mask_email("john@example.com", "hash", test_settings.secret_key)
        assert a == b
        assert len(a) == 16
        assert "@" not in a

    def test_none_level_preserves_email(self, test_settings):
        from authglow.services.audit import AuditService

        result = AuditService._mask_email("john@example.com", "none", test_settings.secret_key)
        assert result == "john@example.com"

    def test_mask_short_email(self, test_settings):
        from authglow.services.audit import AuditService

        result = AuditService._mask_email("a@b.com", "mask", test_settings.secret_key)
        assert result == "a***@b***.com"

    def test_log_event_respects_config_level(self, monkeypatch, tmp_path, test_settings):
        from authglow.services.audit import AuditService

        test_settings.audit_email_log_level = "none"
        monkeypatch.setattr("authglow.services.audit.get_settings", lambda: test_settings)
        svc = AuditService()

        entry = asyncio.get_event_loop().run_until_complete(
            svc.log_event(
                event_type="login",
                user_id="u1",
                email="plain@example.com",
            )
        )
        assert entry.email == "plain@example.com"


class TestRequestIdPropagation:
    """VAPT-131 — ``request_id`` correlation field on audit entries."""

    def test_log_event_accepts_explicit_request_id(self, monkeypatch, audit_service, test_settings):
        """Caller can pass ``request_id`` explicitly; the entry
        records it verbatim."""
        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="login_success",
                user_id="u1",
                request_id="req-abc-123",
            )
        )
        assert entry.request_id == "req-abc-123"

    def test_log_event_inherits_request_id_from_contextvars(self, monkeypatch, test_settings):
        """When no explicit ``request_id`` is passed, the value is
        pulled from ``structlog.contextvars`` (set by the future
        request-id middleware, VAPT-042)."""
        from structlog.contextvars import bind_contextvars, clear_contextvars

        from authglow.services.audit import AuditService

        bind_contextvars(request_id="req-ctx-xyz")
        try:
            svc = AuditService()
            entry = asyncio.get_event_loop().run_until_complete(
                svc.log_event(event_type="login_success", user_id="u1")
            )
            assert entry.request_id == "req-ctx-xyz"
        finally:
            clear_contextvars()

    def test_log_event_no_request_id_when_unset(self, monkeypatch, test_settings):
        """No contextvar binding and no explicit arg → ``None``,
        not an error."""
        from structlog.contextvars import clear_contextvars

        from authglow.services.audit import AuditService

        clear_contextvars()
        svc = AuditService()
        entry = asyncio.get_event_loop().run_until_complete(
            svc.log_event(event_type="login_success", user_id="u1")
        )
        assert entry.request_id is None


class TestIpMasking:
    """VAPT-079 — IP truncation to network prefix."""

    def test_mask_ipv4_to_slash_24(self):
        from authglow.services.audit import AuditService

        assert AuditService._mask_ip("1.2.3.4") == "1.2.3.0/24"
        assert AuditService._mask_ip("192.168.1.100") == "192.168.1.0/24"

    def test_mask_ipv6_to_slash_48(self):
        from authglow.services.audit import AuditService

        result = AuditService._mask_ip("2001:db8:0:0:0:0:0:1")
        assert result.startswith("2001:db8:")
        assert "/48" in result

    def test_mask_ip_invalid_returns_placeholder(self):
        """Invalid IP must not leak back into the log."""
        from authglow.services.audit import AuditService

        assert AuditService._mask_ip("not-an-ip") == "[invalid_ip]"
        assert AuditService._mask_ip("") == ""

    def test_mask_ip_none_safe(self):
        from authglow.services.audit import AuditService

        # ``None`` would happen only if a caller bypassed the
        # Pydantic type; treat as empty string.
        assert AuditService._mask_ip(None) is None  # type: ignore[arg-type]


class TestUserAgentTruncation:
    """VAPT-079 — user-agent length cap."""

    def test_short_user_agent_unchanged(self):
        from authglow.services.audit import AuditService

        ua = "Mozilla/5.0 (short)"
        assert AuditService._truncate(ua) == ua

    def test_long_user_agent_truncated_with_marker(self):
        from authglow.services.audit import AuditService

        ua = "x" * 500
        result = AuditService._truncate(ua)
        assert result.endswith("…[truncated]")
        assert len(result) <= 256

    def test_truncate_hard_when_marker_too_long(self):
        """When ``max_len`` is smaller than the truncation marker,
        the value is hard-truncated to fit ``max_len`` (no marker,
        because the marker itself would overflow the budget)."""
        from authglow.services.audit import AuditService

        result = AuditService._truncate("abcdefghij", max_len=5)
        assert result == "abcde"
        assert len(result) == 5

    def test_truncate_non_string_unchanged(self):
        from authglow.services.audit import AuditService

        assert AuditService._truncate(None) is None  # type: ignore[arg-type]
        assert AuditService._truncate(42) == 42  # type: ignore[arg-type]


class TestMaskPiiExtended:
    """VAPT-079 — end-to-end PII masking in ``log_event``."""

    def test_log_event_masks_ip_and_user_agent(self, monkeypatch, test_settings):
        from authglow.services.audit import AuditService, _audit_log

        test_settings.audit_email_log_level = "hash"
        monkeypatch.setattr("authglow.services.audit.get_settings", lambda: test_settings)
        svc = AuditService()
        with patch.object(_audit_log, "info", wraps=_audit_log.info) as mock_info:
            asyncio.get_event_loop().run_until_complete(
                svc.log_event(
                    event_type="login_success",
                    user_id="u1",
                    email="john@example.com",
                    ip_address="1.2.3.4",
                    user_agent="x" * 500,
                )
            )
            kwargs = mock_info.call_args[1]
            assert kwargs["ip_address"] == "1.2.3.0/24"
            assert kwargs["user_agent"].endswith("…[truncated]")

    def test_log_event_masks_metadata_ip_keys(self, test_settings):
        """Metadata keys containing ``ip`` are masked at the value
        level."""
        from authglow.services.audit import AuditService

        entry_dict = {
            "email": "x@y.com",
            "metadata": {
                "client_ip": "10.0.0.5",
                "registered_ip": "2001:db8::1",
                "not_an_ip": "leave-me-alone",
            },
        }
        masked = AuditService._mask_pii(dict(entry_dict), "hash", test_settings.secret_key)
        assert masked["metadata"]["client_ip"] == "10.0.0.0/24"
        assert masked["metadata"]["registered_ip"].endswith("/48")
        assert masked["metadata"]["not_an_ip"] == "leave-me-alone"

    def test_log_event_masks_long_metadata_strings(self, test_settings):
        """Strings in metadata > 256 chars are truncated."""
        from authglow.services.audit import AuditService

        entry_dict = {
            "email": "x@y.com",
            "metadata": {"long_note": "y" * 1000},
        }
        masked = AuditService._mask_pii(dict(entry_dict), "hash", test_settings.secret_key)
        assert masked["metadata"]["long_note"].endswith("…[truncated]")


class TestProductionGuard:
    """VAPT-080 — refuse to mask nothing in production."""

    def test_default_level_is_hash(self, test_settings):
        """Settings default flipped to ``hash`` (VAPT-080)."""
        assert test_settings.audit_email_log_level == "hash"

    def test_none_rejected_in_production(self, monkeypatch, test_settings):
        from authglow.services.audit import AuditService

        test_settings.app_env = "production"
        test_settings.audit_email_log_level = "none"
        monkeypatch.setattr("authglow.services.audit.get_settings", lambda: test_settings)
        with pytest.raises(ValueError, match="not allowed in production"):
            AuditService._mask_pii({"email": "x@y.com"}, "none", test_settings.secret_key)

    def test_none_allowed_in_development(self, monkeypatch, test_settings):
        """Outside production, ``none`` is still permitted (dev
        debug convenience)."""
        from authglow.services.audit import AuditService

        test_settings.app_env = "development"
        test_settings.audit_email_log_level = "none"
        monkeypatch.setattr("authglow.services.audit.get_settings", lambda: test_settings)
        entry = {"email": "x@y.com"}
        masked = AuditService._mask_pii(dict(entry), "none", test_settings.secret_key)
        assert masked == entry  # nothing changed


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
        """Logging emits structured JSON to stdout via structlog.

        VAPT-079: ``ip_address`` is truncated to /24 by default.
        VAPT-080: ``email`` is hashed (16 hex chars) by default.
        """
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
            assert call_kwargs["ip_address"] == "1.2.3.0/24"
            assert "@" not in call_kwargs["email"]
            assert len(call_kwargs["email"]) == 16

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
