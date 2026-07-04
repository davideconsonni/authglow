"""Unit tests for the FileAPIKeyClaimPolicyRepository.

Covers the file layout, Pydantic round-trip, the
"no policy = None" semantics, the over-write on save, and
the delete. The service-level behaviour is exercised by
``tests/unit/test_claim_policy.py``; the protocol
conformance smoke is in
``tests/unit/repositories/test_protocols.py``.
"""

from pathlib import Path

from authglow.models.api_key_claim_policy import APIKeyClaimPolicy
from authglow.models.claim_policy import (
    ClaimRule,
    ClaimSource,
    ClaimSourceConfig,
    ClaimTarget,
)
from authglow.repositories.file.api_key_claim_policy import (
    FileAPIKeyClaimPolicyRepository,
)
from authglow.repositories.protocols import APIKeyClaimPolicyRepository


def _make_repo(test_settings) -> FileAPIKeyClaimPolicyRepository:
    return FileAPIKeyClaimPolicyRepository(settings=test_settings)


def _make_policy(
    key_id: str = "test-key-1",
) -> APIKeyClaimPolicy:
    return APIKeyClaimPolicy(
        api_key_id=key_id,
        rules=[
            ClaimRule(
                claim_name="https://authglow.example.com/claims/api_key_name",
                source=ClaimSource.API_KEY_FIELD,
                source_config=ClaimSourceConfig(api_key_field="name"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )
        ],
    )


class TestFileAPIKeyClaimPolicyRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "api_key_claim_policies"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert (
            FileAPIKeyClaimPolicyRepository._subdir == "api_key_claim_policies"
        )

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings


class TestFileAPIKeyClaimPolicyRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, APIKeyClaimPolicyRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in ("get_by_api_key", "save", "delete"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFileAPIKeyClaimPolicyRepositoryGet:
    async def test_missing_returns_none(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_by_api_key("nonexistent")
        assert result is None

    async def test_round_trip(self, test_settings):
        repo = _make_repo(test_settings)
        policy = _make_policy(key_id="rt-1")
        await repo.save(policy)
        result = await repo.get_by_api_key("rt-1")
        assert result is not None
        assert result.api_key_id == "rt-1"
        assert len(result.rules) == 1
        assert (
            result.rules[0].claim_name
            == "https://authglow.example.com/claims/api_key_name"
        )
        assert result.rules[0].source == ClaimSource.API_KEY_FIELD

    async def test_corrupt_payload_returns_none(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("corrupt.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not json {{{")
        assert await repo.get_by_api_key("corrupt") is None


class TestFileAPIKeyClaimPolicyRepositorySave:
    async def test_save_writes_file_named_after_key_id(self, test_settings):
        repo = _make_repo(test_settings)
        policy = _make_policy(key_id="plaintext-key-xyz")
        await repo.save(policy)
        path = Path(repo._path("plaintext-key-xyz.json"))
        assert path.exists()

    async def test_save_overwrites_existing(self, test_settings):
        repo = _make_repo(test_settings)
        policy_v1 = _make_policy(key_id="overwrite")
        await repo.save(policy_v1)
        policy_v2 = APIKeyClaimPolicy(
            api_key_id="overwrite",
            rules=[
                ClaimRule(
                    claim_name="https://authglow.example.com/claims/api_key_tier",
                    source=ClaimSource.API_KEY_FIELD,
                    source_config=ClaimSourceConfig(api_key_field="tier"),
                    include_in=[ClaimTarget.ACCESS_TOKEN],
                )
            ],
        )
        await repo.save(policy_v2)
        result = await repo.get_by_api_key("overwrite")
        assert result is not None
        assert len(result.rules) == 1
        assert (
            result.rules[0].claim_name
            == "https://authglow.example.com/claims/api_key_tier"
        )


class TestFileAPIKeyClaimPolicyRepositoryDelete:
    async def test_delete_existing_returns_true(self, test_settings):
        repo = _make_repo(test_settings)
        policy = _make_policy(key_id="to-delete")
        await repo.save(policy)
        assert await repo.delete("to-delete") is True
        assert await repo.get_by_api_key("to-delete") is None

    async def test_delete_missing_returns_false(self, test_settings):
        repo = _make_repo(test_settings)
        assert await repo.delete("does-not-exist") is False
