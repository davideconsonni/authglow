import pytest
import asyncio
from authglow.models.oauth_client import OAuth2Client


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
