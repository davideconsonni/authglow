"""Unit tests for the FileOAuth2ClientRepository.

Covers the file layout, Pydantic round-trip (with the transparent
``_version`` field handling), CRUD semantics, versioned-write CAS
behavior, and Protocol conformance. The service-level behaviour
(secret hashing, named lock, CAS retry loop, business verification
methods) is exercised by ``tests/unit/test_oauth_client_service.py``.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from authglow.core.concurrency import ConcurrentWriteError
from authglow.models.oauth_client import OAuth2Client
from authglow.repositories.file.oauth_client import FileOAuth2ClientRepository
from authglow.repositories.protocols import OAuth2ClientRepository


def _make_repo(test_settings) -> FileOAuth2ClientRepository:
    return FileOAuth2ClientRepository(settings=test_settings)


def _make_client(
    client_id: str = "test-client-1",
    client_name: str = "Test Client",
    *,
    is_active: bool = True,
) -> OAuth2Client:
    return OAuth2Client(
        client_id=client_id,
        client_secret="$2b$12$dummybcrypthash",
        client_name=client_name,
        redirect_uris=["https://example.com/callback"],
        allowed_scopes=["read", "write"],
        grant_types=["authorization_code"],
        is_active=is_active,
    )


class TestFileOAuth2ClientRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "oauth_clients"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert FileOAuth2ClientRepository._subdir == "oauth_clients"

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings


class TestFileOAuth2ClientRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, OAuth2ClientRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in ("create", "get_by_id", "update", "delete", "list"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFileOAuth2ClientRepositoryCreate:
    async def test_create_writes_file_named_after_client_id(self, test_settings):
        repo = _make_repo(test_settings)
        client = _make_client(client_id="plaintext-id-xyz")
        await repo.create(client)
        path = Path(repo._path("plaintext-id-xyz.json"))
        assert path.exists()

    async def test_create_round_trips(self, test_settings):
        repo = _make_repo(test_settings)
        client = _make_client(client_id="rt-1", client_name="RT Client")
        await repo.create(client)
        result = await repo.get_by_id("rt-1")
        assert result is not None
        assert result.client_id == "rt-1"
        assert result.client_name == "RT Client"
        assert result.is_active is True

    async def test_create_persists_branding(self, test_settings):
        repo = _make_repo(test_settings)
        from authglow.models.oauth_client import ClientBranding

        client = _make_client(client_id="brand-1")
        client.branding = ClientBranding(
            primary_color="#ff00aa", logo_url="https://example.com/logo.png"
        )
        await repo.create(client)
        result = await repo.get_by_id("brand-1")
        assert result.branding is not None
        assert result.branding.primary_color == "#ff00aa"
        assert result.branding.logo_url == "https://example.com/logo.png"

    async def test_branding_persists_light_dark_variants(self, test_settings):
        repo = _make_repo(test_settings)
        from authglow.models.oauth_client import BrandingVariant, ClientBranding

        client = _make_client(client_id="brand-2")
        client.branding = ClientBranding(
            primary_color="#2E5BFF",
            light=BrandingVariant(surface_color="#F5F7FF"),
            dark=BrandingVariant(surface_color="#172040", text_color="#FFFFFF"),
        )
        await repo.create(client)
        result = await repo.get_by_id("brand-2")
        assert result.branding is not None
        assert result.branding.primary_color == "#2E5BFF"
        assert result.branding.light is not None
        assert result.branding.light.surface_color == "#F5F7FF"
        assert result.branding.light.primary_color is None
        assert result.branding.dark is not None
        assert result.branding.dark.surface_color == "#172040"
        assert result.branding.dark.text_color == "#FFFFFF"

    async def test_branding_variant_rejects_bad_hex(self, test_settings):
        from authglow.models.oauth_client import BrandingVariant

        with pytest.raises(ValueError):
            BrandingVariant(primary_color="red")

        with pytest.raises(ValueError):
            BrandingVariant(border_radius="12rem; background: red")

    async def test_create_overwrites(self, test_settings):
        repo = _make_repo(test_settings)
        c1 = _make_client(client_id="ow-1", client_name="First")
        c2 = _make_client(client_id="ow-1", client_name="Second")
        await repo.create(c1)
        await repo.create(c2)
        result = await repo.get_by_id("ow-1")
        assert result.client_name == "Second"


class TestFileOAuth2ClientRepositoryGetById:
    async def test_get_returns_client(self, test_settings):
        repo = _make_repo(test_settings)
        client = _make_client(client_id="get-1")
        await repo.create(client)
        result = await repo.get_by_id("get-1")
        assert result is not None
        assert result.client_id == "get-1"

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_by_id("nonexistent")
        assert result is None

    async def test_get_returns_none_for_corrupt_json(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("corrupt.json"))
        path.write_text("{not valid json")
        result = await repo.get_by_id("corrupt")
        assert result is None

    async def test_get_returns_none_for_invalid_pydantic(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("bad.json"))
        path.write_text('{"client_name": "c"}')
        result = await repo.get_by_id("bad")
        assert result is None

    async def test_get_transparently_strips_version_field(self, test_settings):
        """After update, the on-disk file has ``_version``; get_by_id
        must still return a valid OAuth2Client."""
        repo = _make_repo(test_settings)
        client = _make_client(client_id="ver-1")
        await repo.create(client)
        await repo.update(client)
        result = await repo.get_by_id("ver-1")
        assert result is not None
        assert result.client_id == "ver-1"


class TestFileOAuth2ClientRepositoryUpdate:
    async def test_update_persists_changes(self, test_settings):
        repo = _make_repo(test_settings)
        client = _make_client(client_id="upd-1", is_active=True)
        await repo.create(client)
        client.is_active = False
        await repo.update(client)
        result = await repo.get_by_id("upd-1")
        assert result.is_active is False

    async def test_update_first_time_succeeds(self, test_settings):
        """First update on a freshly-created client succeeds because
        the file has no ``_version`` field (read returns 0, the
        versioned write with expected=0 passes)."""
        repo = _make_repo(test_settings)
        client = _make_client(client_id="upd-first")
        await repo.create(client)
        client.client_name = "Renamed"
        await repo.update(client)
        result = await repo.get_by_id("upd-first")
        assert result.client_name == "Renamed"

    async def test_update_raises_concurrent_write_error_on_stale_version(self, test_settings):
        repo = _make_repo(test_settings)
        client = _make_client(client_id="upd-cas")
        await repo.create(client)
        client.client_name = "v1"
        await repo.update(client)

        original_read = repo._read_json_versioned

        async def stale_read(path_arg):
            data, _ = await original_read(path_arg)
            return data, 0  # stale: disk has version=1

        with patch.object(repo, "_read_json_versioned", side_effect=stale_read):
            client.client_name = "v2"
            try:
                await repo.update(client)
            except ConcurrentWriteError:
                return
        raise AssertionError("expected ConcurrentWriteError on stale version")


class TestFileOAuth2ClientRepositoryDelete:
    async def test_delete_removes_file(self, test_settings):
        repo = _make_repo(test_settings)
        client = _make_client(client_id="del-1")
        await repo.create(client)
        path = Path(repo._path("del-1.json"))
        assert path.exists()
        result = await repo.delete("del-1")
        assert result is True
        assert not path.exists()

    async def test_delete_returns_false_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.delete("nope")
        assert result is False


class TestFileOAuth2ClientRepositoryList:
    async def test_list_returns_all_clients(self, test_settings):
        repo = _make_repo(test_settings)
        for i in range(3):
            await repo.create(_make_client(client_id=f"list-{i}"))
        clients = await repo.list()
        assert len(clients) == 3

    async def test_list_active_only(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.create(_make_client(client_id="active-1", is_active=True))
        await repo.create(_make_client(client_id="active-2", is_active=True))
        await repo.create(_make_client(client_id="inactive-1", is_active=False))
        clients = await repo.list(active_only=True)
        assert len(clients) == 2
        assert all(c.is_active for c in clients)

    async def test_list_pagination(self, test_settings):
        repo = _make_repo(test_settings)
        for i in range(5):
            await repo.create(_make_client(client_id=f"page-{i:02d}"))
        page1 = await repo.list(limit=2, offset=0)
        page2 = await repo.list(limit=2, offset=2)
        page3 = await repo.list(limit=2, offset=4)
        assert len(page1) == 2
        assert len(page2) == 2
        assert len(page3) == 1

    async def test_list_sorted_by_client_id(self, test_settings):
        repo = _make_repo(test_settings)
        for cid in ("zzz", "aaa", "mmm"):
            await repo.create(_make_client(client_id=cid))
        clients = await repo.list()
        assert [c.client_id for c in clients] == ["aaa", "mmm", "zzz"]


class TestFileOAuth2ClientRepositoryWithPatchedSettings:
    def test_repo_can_be_constructed_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructor resolves
        ``get_settings()`` via ``BaseFileRepository``'s binding."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from authglow.core.config import Settings
        from authglow.core.crypto import encrypt_private_key

        storage_path = str(tmp_path / "data" / "users")
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path = str(keys_dir / "private_key.pem")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encrypted_priv = encrypt_private_key(
            priv_bytes, secret_key="test-secret-key-for-authglow-testing-32chars!"
        )
        with open(priv_path, "wb") as f:
            f.write(encrypted_priv)

        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32chars!",
            storage_path=storage_path,
            storage_backend="file",
            keys_dir=str(keys_dir),
            private_key_path=priv_path,
            public_key_path=str(keys_dir / "public_key.pem"),
        )

        with patch("authglow.repositories.file.base.get_settings", return_value=settings):
            repo = FileOAuth2ClientRepository()
            assert Path(repo._storage_path).exists()
