import os
import pytest
import asyncio
from unittest.mock import patch, MagicMock
from authglow.models.oauth_client import OAuth2Client
from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import ConcurrentWriteError


def asyncio_run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _make_client(client_id="test-client-1", client_name="Test Client", **kwargs):
    return OAuth2Client(
        client_id=client_id,
        client_secret="placeholder",
        client_name=client_name,
        redirect_uris=kwargs.get("redirect_uris", ["https://example.com/callback"]),
        allowed_scopes=kwargs.get("allowed_scopes", ["read", "write"]),
        grant_types=kwargs.get("grant_types", ["authorization_code", "refresh_token"]),
        is_active=kwargs.get("is_active", True),
        is_confidential=kwargs.get("is_confidential", True),
    )


class TestCreateAndGetClient:
    def test_create_client(self, oauth_client_storage):
        client = _make_client()
        created = asyncio_run(
            oauth_client_storage.create_client(client, "my-secret-123")
        )
        assert created.client_id == "test-client-1"
        assert created.client_secret.startswith("$2b$")

    def test_create_client_hashes_secret(self, oauth_client_storage):
        from authglow.services.password import verify_password

        client = _make_client()
        plaintext = "my-secret-123"
        created = asyncio_run(oauth_client_storage.create_client(client, plaintext))
        assert verify_password(plaintext, created.client_secret)

    def test_get_client(self, oauth_client_storage):
        client = _make_client()
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        retrieved = asyncio_run(oauth_client_storage.get_client("test-client-1"))
        assert retrieved is not None
        assert retrieved.client_name == "Test Client"

    def test_get_client_not_found(self, oauth_client_storage):
        result = asyncio_run(oauth_client_storage.get_client("nonexistent"))
        assert result is None


class TestUpdateDeleteClient:
    def test_update_client(self, oauth_client_storage):
        client = _make_client()
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        client.client_name = "Updated Client"
        updated = asyncio_run(oauth_client_storage.update_client(client))
        assert updated.client_name == "Updated Client"

    def test_delete_client(self, oauth_client_storage):
        client = _make_client()
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        result = asyncio_run(oauth_client_storage.delete_client("test-client-1"))
        assert result is True
        assert asyncio_run(oauth_client_storage.get_client("test-client-1")) is None

    def test_delete_nonexistent_client(self, oauth_client_storage):
        result = asyncio_run(oauth_client_storage.delete_client("nonexistent"))
        assert result is False


class TestListClients:
    def test_list_clients(self, oauth_client_storage):
        for i in range(3):
            client = _make_client(
                client_id=f"client-list-{i}", client_name=f"Client {i}"
            )
            asyncio_run(oauth_client_storage.create_client(client, f"secret-{i}"))
        clients = asyncio_run(oauth_client_storage.list_clients())
        assert len(clients) >= 3

    def test_list_clients_active_only(self, oauth_client_storage):
        active_client = _make_client(
            client_id="active-1", client_name="Active", is_active=True
        )
        inactive_client = _make_client(
            client_id="inactive-1", client_name="Inactive", is_active=False
        )
        asyncio_run(oauth_client_storage.create_client(active_client, "secret-a"))
        asyncio_run(oauth_client_storage.create_client(inactive_client, "secret-i"))
        clients = asyncio_run(oauth_client_storage.list_clients(active_only=True))
        assert all(c.is_active for c in clients)


class TestVerifyClientSecret:
    def test_verify_correct_secret(self, oauth_client_storage):
        client = _make_client()
        asyncio_run(oauth_client_storage.create_client(client, "correct-secret"))
        retrieved = asyncio_run(oauth_client_storage.get_client("test-client-1"))
        result = asyncio_run(
            oauth_client_storage.verify_client_secret(retrieved, "correct-secret")
        )
        assert result is True

    def test_verify_wrong_secret(self, oauth_client_storage):
        client = _make_client()
        asyncio_run(oauth_client_storage.create_client(client, "correct-secret"))
        retrieved = asyncio_run(oauth_client_storage.get_client("test-client-1"))
        result = asyncio_run(
            oauth_client_storage.verify_client_secret(retrieved, "wrong-secret")
        )
        assert result is False

    def test_verify_secret_inactive_client(self, oauth_client_storage):
        client = _make_client(is_active=False)
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        assert not asyncio_run(
            oauth_client_storage.verify_client_secret(client, "secret")
        )


class TestVerifyRedirectURI:
    def test_verify_valid_redirect_uri(self, oauth_client_storage):
        client = _make_client(redirect_uris=["https://example.com/callback"])
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        result = asyncio_run(
            oauth_client_storage.verify_redirect_uri(
                "test-client-1", "https://example.com/callback"
            )
        )
        assert result is True

    def test_verify_invalid_redirect_uri(self, oauth_client_storage):
        client = _make_client(redirect_uris=["https://example.com/callback"])
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        result = asyncio_run(
            oauth_client_storage.verify_redirect_uri(
                "test-client-1", "https://evil.com/callback"
            )
        )
        assert result is False

    def test_verify_redirect_uri_inactive_client(self, oauth_client_storage):
        client = _make_client(is_active=False)
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        result = asyncio_run(
            oauth_client_storage.verify_redirect_uri(
                "test-client-1", "https://example.com/callback"
            )
        )
        assert result is False


class TestScopeAndGrantType:
    def test_is_scope_allowed(self, oauth_client_storage):
        client = _make_client(allowed_scopes=["read", "write", "admin"])
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        result = asyncio_run(
            oauth_client_storage.is_scope_allowed("test-client-1", ["read", "write"])
        )
        assert result is True

    def test_is_scope_not_allowed(self, oauth_client_storage):
        client = _make_client(allowed_scopes=["read"])
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        result = asyncio_run(
            oauth_client_storage.is_scope_allowed("test-client-1", ["read", "delete"])
        )
        assert result is False

    def test_is_scope_inactive_client(self, oauth_client_storage):
        client = _make_client(is_active=False)
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        result = asyncio_run(
            oauth_client_storage.is_scope_allowed("test-client-1", ["read"])
        )
        assert result is False

    def test_is_grant_type_allowed(self, oauth_client_storage):
        client = _make_client(grant_types=["authorization_code", "refresh_token"])
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        result = asyncio_run(
            oauth_client_storage.is_grant_type_allowed(
                "test-client-1", "authorization_code"
            )
        )
        assert result is True

    def test_is_grant_type_not_allowed(self, oauth_client_storage):
        client = _make_client(grant_types=["authorization_code"])
        asyncio_run(oauth_client_storage.create_client(client, "secret"))
        result = asyncio_run(
            oauth_client_storage.is_grant_type_allowed(
                "test-client-1", "client_credentials"
            )
        )
        assert result is False


class TestSecretRotation:
    def test_rotate_secret(self, oauth_client_storage):
        client = _make_client()
        asyncio_run(oauth_client_storage.create_client(client, "old-secret"))
        retrieved = asyncio_run(oauth_client_storage.get_client("test-client-1"))
        assert asyncio_run(
            oauth_client_storage.verify_client_secret(retrieved, "old-secret")
        )

        new_secret = asyncio_run(oauth_client_storage.rotate_secret("test-client-1"))
        assert isinstance(new_secret, str)
        assert len(new_secret) > 20

        retrieved2 = asyncio_run(oauth_client_storage.get_client("test-client-1"))
        assert asyncio_run(
            oauth_client_storage.verify_client_secret(retrieved2, new_secret)
        )
        assert not asyncio_run(
            oauth_client_storage.verify_client_secret(retrieved2, "old-secret")
        )

    def test_rotate_secret_nonexistent(self, oauth_client_storage):
        with pytest.raises(ValueError):
            asyncio_run(oauth_client_storage.rotate_secret("nonexistent"))

    def test_generate_client_secret(self, oauth_client_storage):
        secret = oauth_client_storage.generate_client_secret()
        assert isinstance(secret, str)
        assert len(secret) > 20
        secret2 = oauth_client_storage.generate_client_secret()
        assert secret != secret2


class TestAsyncFileSystemMigration:
    """P7: Verify OAuth2ClientStorage uses AsyncFileSystem instead of pathlib."""

    def test_uses_async_file_system(self, oauth_client_storage):
        assert isinstance(oauth_client_storage._afs, AsyncFileSystem)

    def test_no_pathlib_in_service_module(self):
        import inspect
        from authglow.services import oauth_client as mod

        source = inspect.getsource(mod)
        assert "pathlib" not in source
        assert "from pathlib import" not in source
        assert "Path(" not in source

    def test_storage_path_is_fstring_not_pathlib(self, oauth_client_storage):
        assert isinstance(oauth_client_storage.storage_path, str)
        assert not hasattr(oauth_client_storage.storage_path, "glob")

    def test_has_fsspec_filesystem(self, oauth_client_storage):
        import fsspec

        assert oauth_client_storage.fs is not None
        assert isinstance(oauth_client_storage.fs, fsspec.spec.AbstractFileSystem)


class TestCASConcurrencyProtection:
    """P7: Verify CAS versioned write protects rotate_secret and update_last_used."""

    def test_rotate_secret_retries_on_version_conflict(self, oauth_client_storage):
        client = _make_client()
        asyncio_run(oauth_client_storage.create_client(client, "old-secret"))

        real_write = oauth_client_storage._afs.write_json_versioned
        call_count = [0]

        async def mock_write_versioned(
            path, data, expected_version, indent=2, default=None
        ):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConcurrentWriteError("version mismatch")
            return await real_write(
                path, data, expected_version, indent=indent, default=default
            )

        with patch.object(
            oauth_client_storage._afs, "write_json_versioned", mock_write_versioned
        ):
            new_secret = asyncio_run(
                oauth_client_storage.rotate_secret("test-client-1")
            )

        assert isinstance(new_secret, str)
        assert call_count[0] == 2

    def test_rotate_secret_exhausts_retries(self, oauth_client_storage):
        client = _make_client()
        asyncio_run(oauth_client_storage.create_client(client, "old-secret"))

        def mock_always_fail(path, data, expected_version, indent=2, default=None):
            raise ConcurrentWriteError("version mismatch")

        with patch.object(
            oauth_client_storage._afs, "write_json_versioned", mock_always_fail
        ):
            with pytest.raises(ConcurrentWriteError):
                asyncio_run(oauth_client_storage.rotate_secret("test-client-1"))

    def test_update_last_used_retries_on_version_conflict(self, oauth_client_storage):
        client = _make_client()
        asyncio_run(oauth_client_storage.create_client(client, "secret"))

        real_write = oauth_client_storage._afs.write_json_versioned
        call_count = [0]

        async def mock_write_versioned(
            path, data, expected_version, indent=2, default=None
        ):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConcurrentWriteError("version mismatch")
            return await real_write(
                path, data, expected_version, indent=indent, default=default
            )

        with patch.object(
            oauth_client_storage._afs, "write_json_versioned", mock_write_versioned
        ):
            asyncio_run(oauth_client_storage.update_last_used("test-client-1"))

        assert call_count[0] == 2

    def test_update_last_used_skips_nonexistent_client(self, oauth_client_storage):
        asyncio_run(oauth_client_storage.update_last_used("nonexistent-client"))


class TestCloudBackendCompatibility:
    """P7: Verify service initializes correctly with non-file storage backends."""

    def test_initializes_with_s3_backend(self, test_settings, tmp_path):
        from authglow.services.oauth_client import OAuth2ClientStorage

        s3_settings = test_settings.model_copy()
        s3_settings.storage_backend = "s3"
        s3_settings.storage_path = str(tmp_path / "data" / "s3_users")
        s3_settings.aws_access_key_id = "test-key"
        s3_settings.aws_secret_access_key = "test-secret"
        s3_settings.aws_region = "us-east-1"

        with patch(
            "authglow.services.oauth_client.get_settings", return_value=s3_settings
        ):
            with patch("authglow.services.oauth_client.fsspec.filesystem") as mock_fs:
                with patch(
                    "authglow.services.password.get_settings", return_value=s3_settings
                ):
                    OAuth2ClientStorage()

        mock_fs.assert_called_once_with(
            "s3",
            key="test-key",
            secret="test-secret",
            client_kwargs={"region_name": "us-east-1"},
        )

    def test_initializes_with_gcs_backend(self, test_settings, tmp_path):
        from authglow.services.oauth_client import OAuth2ClientStorage

        gcs_settings = test_settings.model_copy()
        gcs_settings.storage_backend = "gcs"
        gcs_settings.storage_path = str(tmp_path / "data" / "gcs_users")
        gcs_settings.google_application_credentials = "/path/to/creds.json"

        with patch(
            "authglow.services.oauth_client.get_settings", return_value=gcs_settings
        ):
            with patch("authglow.services.oauth_client.fsspec.filesystem") as mock_fs:
                with patch(
                    "authglow.services.password.get_settings", return_value=gcs_settings
                ):
                    OAuth2ClientStorage()

        mock_fs.assert_called_once_with("gcs", token="/path/to/creds.json")
