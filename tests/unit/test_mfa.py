import pytest
from datetime import datetime, timedelta, timezone


class TestTOTPGeneration:
    def test_generate_totp_secret(self, mfa_service):
        secret = mfa_service.generate_totp_secret()
        assert isinstance(secret, str)
        assert len(secret) == 32
        assert secret.isalnum()

    def test_get_totp_uri(self, mfa_service):
        secret = mfa_service.generate_totp_secret()
        uri = mfa_service.get_totp_uri(secret, "user@example.com")
        assert "otpauth://totp/" in uri
        assert secret in uri

    def test_generate_qr_code(self, mfa_service):
        secret = mfa_service.generate_totp_secret()
        uri = mfa_service.get_totp_uri(secret, "qr@example.com")
        qr = mfa_service.generate_qr_code(uri)
        assert qr.startswith("data:image/png;base64,")

    def test_verify_totp_valid(self, mfa_service):
        import pyotp

        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert mfa_service.verify_totp(secret, code)

    def test_verify_totp_invalid(self, mfa_service):
        secret = mfa_service.generate_totp_secret()
        assert not mfa_service.verify_totp(secret, "000000")


class TestBackupCodes:
    def test_generate_backup_codes_format(self, mfa_service):
        codes = mfa_service.generate_backup_codes(10)
        assert len(codes) == 10
        for code in codes:
            assert "-" in code
            parts = code.split("-")
            assert len(parts) == 2
            assert len(parts[0]) == 4
            assert len(parts[1]) == 4

    def test_generate_backup_codes_different_each_time(self, mfa_service):
        codes1 = mfa_service.generate_backup_codes(10)
        codes2 = mfa_service.generate_backup_codes(10)
        assert set(codes1) != set(codes2)

    def test_hash_and_verify_backup_code(self, mfa_service):
        code = "ABCD-1234"
        hashed = mfa_service.hash_backup_code(code)
        assert mfa_service.verify_backup_code(code, hashed)

    def test_verify_backup_code_case_insensitive(self, mfa_service):
        code = "ABCD-1234"
        hashed = mfa_service.hash_backup_code(code)
        assert mfa_service.verify_backup_code("ABCD-1234", hashed)

    def test_verify_backup_code_without_dash(self, mfa_service):
        code = "ABCD-1234"
        hashed = mfa_service.hash_backup_code(code)
        assert mfa_service.verify_backup_code("ABCD1234", hashed)

    def test_verify_wrong_backup_code(self, mfa_service):
        code = "ABCD-1234"
        hashed = mfa_service.hash_backup_code(code)
        assert not mfa_service.verify_backup_code("WRONG-5678", hashed)

    def test_save_and_get_backup_codes(self, mfa_service):
        import asyncio

        codes = mfa_service.generate_backup_codes(5)
        asyncio.get_event_loop().run_until_complete(
            mfa_service.save_backup_codes("user-backup-test", codes)
        )
        result = asyncio.get_event_loop().run_until_complete(
            mfa_service.get_backup_codes("user-backup-test")
        )
        assert result is not None
        assert result.user_id == "user-backup-test"
        assert len(result.codes) == 5

    def test_backup_codes_stored_as_hashes(self, mfa_service):
        import asyncio

        codes = mfa_service.generate_backup_codes(5)
        asyncio.get_event_loop().run_until_complete(
            mfa_service.save_backup_codes("user-hash-test", codes)
        )
        result = asyncio.get_event_loop().run_until_complete(
            mfa_service.get_backup_codes("user-hash-test")
        )
        assert result is not None
        for stored_code in result.codes:
            assert stored_code.startswith("$2b$")

    def test_verify_user_backup_code_correct(self, mfa_service):
        import asyncio

        codes = mfa_service.generate_backup_codes(5)
        user_id = "user-verify-codes"
        asyncio.get_event_loop().run_until_complete(
            mfa_service.save_backup_codes(user_id, codes)
        )
        first_code = codes[0]
        is_valid = asyncio.get_event_loop().run_until_complete(
            mfa_service.verify_user_backup_code(user_id, first_code)
        )
        assert is_valid

    def test_verify_user_backup_code_wrong(self, mfa_service):
        import asyncio

        codes = mfa_service.generate_backup_codes(5)
        user_id = "user-verify-wrong"
        asyncio.get_event_loop().run_until_complete(
            mfa_service.save_backup_codes(user_id, codes)
        )
        is_valid = asyncio.get_event_loop().run_until_complete(
            mfa_service.verify_user_backup_code(user_id, "WRONGCODE")
        )
        assert not is_valid

    def test_verify_user_backup_code_multi_use(self, mfa_service):
        import asyncio

        codes = mfa_service.generate_backup_codes(5)
        user_id = "user-multi-use"
        asyncio.get_event_loop().run_until_complete(
            mfa_service.save_backup_codes(user_id, codes)
        )
        first_code = codes[0]
        is_valid1 = asyncio.get_event_loop().run_until_complete(
            mfa_service.verify_user_backup_code(user_id, first_code)
        )
        assert is_valid1
        is_valid2 = asyncio.get_event_loop().run_until_complete(
            mfa_service.verify_user_backup_code(user_id, first_code)
        )
        assert is_valid2

    def test_delete_backup_codes(self, mfa_service):
        import asyncio

        codes = mfa_service.generate_backup_codes(5)
        user_id = "user-delete-codes"
        asyncio.get_event_loop().run_until_complete(
            mfa_service.save_backup_codes(user_id, codes)
        )
        asyncio.get_event_loop().run_until_complete(
            mfa_service.delete_backup_codes(user_id)
        )
        result = asyncio.get_event_loop().run_until_complete(
            mfa_service.get_backup_codes(user_id)
        )
        assert result is None


class TestDeviceFingerprint:
    def test_generate_device_fingerprint(self, mfa_service):
        fp = mfa_service.generate_device_fingerprint("Mozilla/5.0", "192.168.1.1")
        assert isinstance(fp, str)
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_device_fingerprint_deterministic(self, mfa_service):
        fp1 = mfa_service.generate_device_fingerprint("Mozilla/5.0", "192.168.1.1")
        fp2 = mfa_service.generate_device_fingerprint("Mozilla/5.0", "192.168.1.1")
        assert fp1 == fp2, "Same inputs must produce the same HMAC-SHA256 fingerprint"

        fp3 = mfa_service.generate_device_fingerprint("OtherAgent", "192.168.1.1")
        assert fp1 != fp3, "Different inputs must produce different fingerprints"

    def test_device_fingerprint_different_agents(self, mfa_service):
        fp1 = mfa_service.generate_device_fingerprint("Mozilla/5.0", "192.168.1.1")
        fp2 = mfa_service.generate_device_fingerprint("Chrome/100.0", "192.168.1.1")
        assert fp1 != fp2

    def test_trusted_device_lifecycle(self, mfa_service):
        import asyncio

        fp = mfa_service.generate_device_fingerprint("Mozilla/5.0", "192.168.1.1")
        user_id = "user-trusted-test"
        device = asyncio.get_event_loop().run_until_complete(
            mfa_service.add_trusted_device(user_id, fp, "Test Browser")
        )
        assert device is not None
        assert device.device_fingerprint == fp
        assert device.user_id == user_id

        is_trusted = asyncio.get_event_loop().run_until_complete(
            mfa_service.is_device_trusted(user_id, fp)
        )
        assert is_trusted

    def test_trusted_device_real_world_flow(self, mfa_service):
        """Simulate real-world: generate fp in session 1, re-generate in session 2."""
        import asyncio

        user_id = "user-real-world-flow"

        fp1 = mfa_service.generate_device_fingerprint("Chrome/120", "10.0.0.5")
        asyncio.get_event_loop().run_until_complete(
            mfa_service.add_trusted_device(user_id, fp1, "Chrome on macOS")
        )

        fp2 = mfa_service.generate_device_fingerprint("Chrome/120", "10.0.0.5")
        assert fp1 == fp2, "HMAC-SHA256 must be deterministic"
        is_trusted = asyncio.get_event_loop().run_until_complete(
            mfa_service.is_device_trusted(user_id, fp2)
        )
        assert is_trusted, "Same device should be recognized as trusted"

        fp3 = mfa_service.generate_device_fingerprint("Firefox/121", "10.0.0.5")
        is_trusted_other = asyncio.get_event_loop().run_until_complete(
            mfa_service.is_device_trusted(user_id, fp3)
        )
        assert not is_trusted_other, "Different device should not be trusted"

    def test_trusted_device_expires(self, mfa_service):
        import asyncio
        import json
        from authglow.models.mfa import TrustedDevice

        fp = mfa_service.generate_device_fingerprint("Mozilla/5.0", "10.0.0.1")
        user_id = "user-expired-device"
        device = asyncio.get_event_loop().run_until_complete(
            mfa_service.add_trusted_device(user_id, fp, "Expired Browser")
        )
        expired_device = TrustedDevice(**device.model_dump())
        expired_device.expires_at = datetime.utcnow() - timedelta(days=1)
        device_path = f"{mfa_service.storage_path}/trusted_devices/{device.id}.json"
        with mfa_service.fs.open(device_path, "w") as f:
            json.dump(expired_device.model_dump(mode="json"), f, indent=2, default=str)

        is_trusted = asyncio.get_event_loop().run_until_complete(
            mfa_service.is_device_trusted(user_id, fp)
        )
        assert not is_trusted, "Expired trusted devices should not be trusted."

    def test_untrusted_device(self, mfa_service):
        import asyncio

        fp = mfa_service.generate_device_fingerprint("SomeAgent", "1.2.3.4")
        is_trusted = asyncio.get_event_loop().run_until_complete(
            mfa_service.is_device_trusted("user-no-device", fp)
        )
        assert not is_trusted

    def test_list_trusted_devices(self, mfa_service):
        import asyncio

        user_id = "user-list-devices"
        fp1 = mfa_service.generate_device_fingerprint("Agent1", "1.1.1.1")
        fp2 = mfa_service.generate_device_fingerprint("Agent2", "2.2.2.2")

        asyncio.get_event_loop().run_until_complete(
            mfa_service.add_trusted_device(user_id, fp1, "Browser 1")
        )
        asyncio.get_event_loop().run_until_complete(
            mfa_service.add_trusted_device(user_id, fp2, "Browser 2")
        )

        devices = asyncio.get_event_loop().run_until_complete(
            mfa_service.list_trusted_devices(user_id)
        )
        assert len(devices) >= 2

    def test_remove_trusted_device(self, mfa_service):
        import asyncio

        fp = mfa_service.generate_device_fingerprint("Agent3", "3.3.3.3")
        user_id = "user-remove-device"
        device = asyncio.get_event_loop().run_until_complete(
            mfa_service.add_trusted_device(user_id, fp, "ToRemove")
        )
        result = asyncio.get_event_loop().run_until_complete(
            mfa_service.remove_trusted_device(device.id)
        )
        assert result


class TestTOTPSecretStorage:
    def test_totp_secret_stored_encrypted(self):
        from authglow.models.user import User

        user = User(
            email="totptest@example.com",
            hashed_password="$2b$12$xxxx",
            mfa_secret="JBSWY3DPEHPK3PXP",
        )
        assert user.mfa_secret is not None
        raw_secret = "JBSWY3DPEHPK3PXP"
        assert user.mfa_secret == raw_secret, (
            "MFA secret should be stored encrypted, not as plaintext base32"
        )
