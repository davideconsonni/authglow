"""Unit tests for the FileClientClaimPolicyRepository.

Covers the file layout, Pydantic round-trip, the "no policy =
None" semantics, the over-write on save, and the delete.
The service-level behaviour is exercised by
``tests/unit/test_claim_policy.py``; the protocol conformance
smoke is in ``tests/unit/repositories/test_protocols.py``.
"""

from pathlib import Path
from unittest.mock import patch

from authglow.models.claim_policy import (
    ClaimRule,
    ClaimSource,
    ClaimSourceConfig,
    ClaimTarget,
    ClientClaimPolicy,
)
from authglow.repositories.file.claim_policy import (
    FileClientClaimPolicyRepository,
)
from authglow.repositories.protocols import ClientClaimPolicyRepository


def _make_repo(test_settings) -> FileClientClaimPolicyRepository:
    return FileClientClaimPolicyRepository(settings=test_settings)


def _make_policy(
    client_id: str = "test-client-1",
) -> ClientClaimPolicy:
    return ClientClaimPolicy(
        client_id=client_id,
        rules=[
            ClaimRule(
                claim_name="https://authglow.example.com/claims/tenant_id",
                source=ClaimSource.USER_FIELD,
                source_config=ClaimSourceConfig(user_field="tenant_id"),
                include_in=[ClaimTarget.ACCESS_TOKEN, ClaimTarget.ID_TOKEN],
            )
        ],
    )


class TestFileClientClaimPolicyRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "client_claim_policies"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert FileClientClaimPolicyRepository._subdir == "client_claim_policies"

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings


class TestFileClientClaimPolicyRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, ClientClaimPolicyRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in ("get_by_client", "save", "delete"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFileClientClaimPolicyRepositoryGet:
    async def test_missing_returns_none(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_by_client("nonexistent")
        assert result is None

    async def test_round_trip(self, test_settings):
        repo = _make_repo(test_settings)
        policy = _make_policy(client_id="rt-1")
        await repo.save(policy)
        result = await repo.get_by_client("rt-1")
        assert result is not None
        assert result.client_id == "rt-1"
        assert len(result.rules) == 1
        assert result.rules[0].claim_name == "https://authglow.example.com/claims/tenant_id"
        assert result.rules[0].source == ClaimSource.USER_FIELD

    async def test_corrupt_payload_returns_none(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("corrupt-client.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not json {{{")
        assert await repo.get_by_client("corrupt-client") is None


class TestFileClientClaimPolicyRepositorySave:
    async def test_save_writes_file_named_after_client_id(self, test_settings):
        repo = _make_repo(test_settings)
        policy = _make_policy(client_id="plaintext-id-xyz")
        await repo.save(policy)
        path = Path(repo._path("plaintext-id-xyz.json"))
        assert path.exists()

    async def test_save_overwrites_existing(self, test_settings):
        repo = _make_repo(test_settings)
        policy_v1 = _make_policy(client_id="overwrite")
        await repo.save(policy_v1)
        # Save a different policy for the same client
        policy_v2 = ClientClaimPolicy(
            client_id="overwrite",
            rules=[
                ClaimRule(
                    claim_name="https://authglow.example.com/claims/org",
                    source=ClaimSource.USER_FIELD,
                    source_config=ClaimSourceConfig(user_field="organization"),
                    include_in=[ClaimTarget.ACCESS_TOKEN],
                )
            ],
        )
        await repo.save(policy_v2)
        result = await repo.get_by_client("overwrite")
        assert result is not None
        assert len(result.rules) == 1
        assert result.rules[0].claim_name == "https://authglow.example.com/claims/org"


class TestFileClientClaimPolicyRepositoryDelete:
    async def test_delete_existing_returns_true(self, test_settings):
        repo = _make_repo(test_settings)
        policy = _make_policy(client_id="to-delete")
        await repo.save(policy)
        assert await repo.delete("to-delete") is True
        # Subsequent get returns None
        assert await repo.get_by_client("to-delete") is None

    async def test_delete_missing_returns_false(self, test_settings):
        repo = _make_repo(test_settings)
        assert await repo.delete("does-not-exist") is False
