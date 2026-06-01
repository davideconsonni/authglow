"""Tests for audit logging service — write-only with email masking."""

import asyncio
import json
import os
import hmac
import hashlib

import pytest


class TestAuditLogging:
    def test_log_event(self, audit_service):
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
        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(event_type="account_locked", severity="high")
        )
        assert entry.severity == "high"


class TestEmailMasking:
    def test_mask_email_top_level(self, audit_service, test_settings):
        """Email is masked at 'mask' level before writing to disk."""
        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="login_success",
                user_id="u1",
                email="john.doe@example.com",
            )
        )
        path = audit_service._get_log_path(entry.id)
        raw = asyncio.get_event_loop().run_until_complete(
            audit_service._afs.read_json(path)
        )
        assert raw["email"] == "jo***@ex***.com"

    def test_mask_email_metadata(self, audit_service, test_settings):
        """Metadata fields containing 'email' are also masked."""
        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="user_updated",
                user_id="admin-1",
                email="admin@company.com",
                metadata={
                    "target_user_email": "alice@example.org",
                    "target_user_id": "u2",
                },
            )
        )
        path = audit_service._get_log_path(entry.id)
        raw = asyncio.get_event_loop().run_until_complete(
            audit_service._afs.read_json(path)
        )
        assert raw["email"] == "ad***@co***.com"
        assert raw["metadata"]["target_user_email"] == "al***@ex***.org"
        assert raw["metadata"]["target_user_id"] == "u2"

    def test_mask_email_deterministic(self, test_settings):
        """Same input always produces the same masked output."""
        from authglow.services.audit import AuditService

        a = AuditService._mask_email(
            "john@example.com", "mask", test_settings.secret_key
        )
        b = AuditService._mask_email(
            "john@example.com", "mask", test_settings.secret_key
        )
        assert a == b
        assert a == "jo***@ex***.com"

    def test_mask_email_different_inputs(self, test_settings):
        """Different emails produce different masked outputs."""
        from authglow.services.audit import AuditService

        a = AuditService._mask_email(
            "alice@example.com", "mask", test_settings.secret_key
        )
        b = AuditService._mask_email(
            "bob@example.com", "mask", test_settings.secret_key
        )
        assert a != b
        assert a == "al***@ex***.com"
        assert b == "bo***@ex***.com"

    def test_hash_level_deterministic(self, test_settings):
        """Hash level produces deterministic HMAC output."""
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

    def test_hash_level_different_inputs(self, test_settings):
        """Different emails produce different hashes."""
        from authglow.services.audit import AuditService

        a = AuditService._mask_email("alice@a.com", "hash", test_settings.secret_key)
        b = AuditService._mask_email("bob@b.com", "hash", test_settings.secret_key)
        assert a != b

    def test_none_level_preserves_email(self, test_settings):
        """None level returns the email unchanged."""
        from authglow.services.audit import AuditService

        result = AuditService._mask_email(
            "john@example.com", "none", test_settings.secret_key
        )
        assert result == "john@example.com"

    def test_mask_short_email(self, test_settings):
        """Short local parts (1 char) are handled gracefully."""
        from authglow.services.audit import AuditService

        result = AuditService._mask_email("a@b.com", "mask", test_settings.secret_key)
        assert "@" in result
        assert result == "a***@b***.com"

    def test_log_event_respects_config_level(
        self, monkeypatch, tmp_path, test_settings
    ):
        """Config audit_email_log_level='none' skips masking."""
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
        path = svc._get_log_path(entry.id)
        raw = asyncio.get_event_loop().run_until_complete(svc._afs.read_json(path))
        assert raw["email"] == "plain@example.com"

    def test_no_plaintext_pii_on_disk(self, audit_service, test_settings):
        """Verify that PII is never stored in plaintext when masking is active."""
        entry = asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="user_deleted",
                user_id="admin",
                email="sensitive@secret.gov",
                metadata={
                    "target_user_email": "victim@secret.gov",
                },
            )
        )
        path = audit_service._get_log_path(entry.id)
        raw = asyncio.get_event_loop().run_until_complete(
            audit_service._afs.read_json(path)
        )
        json_str = json.dumps(raw)
        assert "sensitive@secret.gov" not in json_str
        assert "victim@secret.gov" not in json_str


class TestAuditStats:
    def test_stats_incremented_on_event(self, audit_service):
        """log_event() increments daily aggregate stats."""
        asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="login_success", user_id="u1", severity="info"
            )
        )
        asyncio.get_event_loop().run_until_complete(
            audit_service.log_event(
                event_type="login_failed", user_id="u2", severity="warning"
            )
        )
        from datetime import timedelta
        from authglow.core.datetime import utcnow

        since = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        stats = asyncio.get_event_loop().run_until_complete(
            audit_service.get_stats_since(since)
        )
        assert stats.get("login_success") == 1
        assert stats.get("login_failed") == 1
        assert stats.get("_security_events") == 1

    def test_stats_timeseries_empty_days_zero(self, audit_service):
        """Days with no events return zeroed entries."""
        series = asyncio.get_event_loop().run_until_complete(
            audit_service.get_stats_timeseries(days=3)
        )
        assert len(series) == 3
        for entry in series:
            assert entry["total"] == 0
            assert entry["success"] == 0
            assert entry["failed"] == 0

    def test_write_only_no_read_methods(self):
        """AuditService must not expose read/delete methods for audit logs."""
        from authglow.services.audit import AuditService

        forbidden = {
            "get_logs",
            "get_user_login_counts",
            "get_event_counts_by_type",
            "get_logs_by_date",
            "delete_old_logs",
        }
        available = set(AuditService.__dict__.keys())
        assert forbidden.isdisjoint(available), (
            f"AuditService still exposes read/delete methods: {forbidden & available}"
        )
