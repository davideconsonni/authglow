"""Integration tests for the per-API-key claim policy admin API.

End-to-end tests that exercise the GET / PUT / DELETE endpoints
against a FastAPI ``TestClient`` with the claim policy
repository backed by the real FileClientClaimPolicyRepository
(via the conftest's tmp_path storage).
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.claim_policy import router as claim_policy_router
from authglow.api.claim_policy import require_admin as _claim_admin
from authglow.models.api_key import APIKey
from authglow.models.claim_policy import (
    BUILTIN_TEMPLATES,
    ClaimRule,
    ClaimSource,
    ClaimSourceConfig,
    ClaimTarget,
)
from authglow.models.user import User
from authglow.services.password import hash_password


def _make_admin_user():
    return User(
        id="admin-1",
        email="admin@test.com",
        hashed_password=hash_password("TestP@ss123!"),
        is_active=True,
        scopes=["admin"],
    )


def _make_oauth_client(client_id: str = "test-client-1"):
    from authglow.models.oauth_client import OAuth2Client

    return OAuth2Client(
        client_id=client_id,
        client_secret="$2b$12$dummyhash",
        client_name="Test Client",
        redirect_uris=["https://example.com/callback"],
        allowed_scopes=["read", "write"],
        grant_types=["authorization_code"],
        is_active=True,
    )


def _make_api_key(key_id: str = "test-key-1") -> APIKey:
    return APIKey(
        key_id=key_id,
        user_id="u-1",
        name="Test Key",
        key_prefix="ak_ABCDEFGHIJ",
        key_hash="$2b$12$dummyhash",
        scopes=["read", "write"],
        is_active=True,
        allowed_ips=[],
        tier="production",
        created_by="u-1",
    )


@pytest.fixture
def admin_client(test_settings):
    """A FastAPI ``TestClient`` with ``require_admin`` bypassed."""
    app = FastAPI()
    app.include_router(claim_policy_router)
    app.dependency_overrides[_claim_admin] = _make_admin_user
    return TestClient(app)


class TestGetApiKeyClaimPolicy:
    def test_returns_404_when_key_not_found(self, admin_client, test_settings):
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(return_value=None)
            resp = admin_client.get(
                "/api/admin/api-keys/nonexistent/claim-policy"
            )
            assert resp.status_code == 404

    def test_returns_default_payload_for_existing_key_without_policy(
        self, admin_client, test_settings
    ):
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=_make_api_key("k-no-policy")
            )
            resp = admin_client.get(
                "/api/admin/api-keys/k-no-policy/claim-policy"
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["is_custom"] is False
            # No saved policy AND no defaults surfaced: API
            # keys use REPLACE semantics, so the namespaced
            # RBAC roles / permissions are NOT auto-applied
            # (see :class:`ClaimPolicyService`). The admin UI
            # therefore has nothing to show in
            # ``default_rules``; the admin opts in by saving
            # explicit rules via the Claims tab.
            assert data["rules"] == []
            assert data["default_rules"] == []

    def test_default_payload_keeps_rules_empty_for_oauth_client_too(
        self, admin_client, test_settings
    ):
        """Regression: the same fix applies to the OAuth
        client GET endpoint (the function is shared). When
        no policy is saved, the admin must see an empty
        "Current Rules" list — not the system defaults
        masquerading as user rules."""
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(
                return_value=_make_oauth_client("c-no-policy")
            )
            resp = admin_client.get(
                "/api/admin/oauth-clients/c-no-policy/claim-policy"
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["is_custom"] is False
            assert data["rules"] == []
            assert len(data["default_rules"]) == 2

    def test_returns_saved_policy_when_present(
        self, admin_client, test_settings
    ):
        from authglow.models.api_key_claim_policy import APIKeyClaimPolicy

        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=_make_api_key("k-saved")
            )
            saved = APIKeyClaimPolicy(
                api_key_id="k-saved",
                rules=[
                    ClaimRule(
                        claim_name="https://authglow.example.com/claims/api_key_name",
                        source=ClaimSource.API_KEY_FIELD,
                        source_config=ClaimSourceConfig(api_key_field="name"),
                        include_in=[ClaimTarget.ACCESS_TOKEN],
                    )
                ],
            )
            from authglow.services.claim_policy import ClaimPolicyService

            svc = ClaimPolicyService()
            asyncio.run(svc.save_api_key_policy("k-saved", saved.rules))

            resp = admin_client.get(
                "/api/admin/api-keys/k-saved/claim-policy"
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["is_custom"] is True
            assert len(data["rules"]) == 1
            assert (
                data["rules"][0]["claim_name"]
                == "https://authglow.example.com/claims/api_key_name"
            )


class TestPutApiKeyClaimPolicy:
    def test_put_replaces_saved_policy(self, admin_client, test_settings):
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=_make_api_key("k-put")
            )
            body = {
                "rules": [
                    {
                        "claim_name": "https://authglow.example.com/claims/api_key_name",
                        "source": "api_key_field",
                        "source_config": {"api_key_field": "name"},
                        "include_in": ["access_token"],
                    }
                ]
            }
            resp = admin_client.put(
                "/api/admin/api-keys/k-put/claim-policy", json=body
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["is_custom"] is True
            assert len(data["rules"]) == 1
            assert (
                data["rules"][0]["claim_name"]
                == "https://authglow.example.com/claims/api_key_name"
            )

    def test_put_with_empty_rules_deletes_saved(self, admin_client, test_settings):
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=_make_api_key("k-empty")
            )
            from authglow.services.claim_policy import ClaimPolicyService

            svc = ClaimPolicyService()
            rule = ClaimRule(
                claim_name="https://authglow.example.com/claims/api_key_name",
                source=ClaimSource.API_KEY_FIELD,
                source_config=ClaimSourceConfig(api_key_field="name"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )
            asyncio.run(svc.save_api_key_policy("k-empty", [rule]))
            resp = admin_client.put(
                "/api/admin/api-keys/k-empty/claim-policy",
                json={"rules": []},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["is_custom"] is False

    def test_put_rejects_non_uri_claim_name(self, admin_client):
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=_make_api_key("k-bad")
            )
            body = {
                "rules": [
                    {
                        "claim_name": "tenant_id",  # plain, not URI
                        "source": "static",
                        "source_config": {"value": "x"},
                        "include_in": ["access_token"],
                    }
                ]
            }
            resp = admin_client.put(
                "/api/admin/api-keys/k-bad/claim-policy", json=body
            )
            assert resp.status_code == 422

    def test_put_rejects_unknown_source(self, admin_client):
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=_make_api_key("k-bad-source")
            )
            body = {
                "rules": [
                    {
                        "claim_name": "https://authglow/x",
                        "source": "made_up_source",
                        "include_in": ["access_token"],
                    }
                ]
            }
            resp = admin_client.put(
                "/api/admin/api-keys/k-bad-source/claim-policy", json=body
            )
            assert resp.status_code == 422

    def test_put_rejects_duplicate_claim_names(self, admin_client):
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=_make_api_key("k-dup")
            )
            body = {
                "rules": [
                    {
                        "claim_name": "https://authglow/x",
                        "source": "static",
                        "source_config": {"value": 1},
                        "include_in": ["access_token"],
                    },
                    {
                        "claim_name": "https://authglow/x",
                        "source": "static",
                        "source_config": {"value": 2},
                        "include_in": ["access_token"],
                    },
                ]
            }
            resp = admin_client.put(
                "/api/admin/api-keys/k-dup/claim-policy", json=body
            )
            assert resp.status_code == 422

    def test_put_accepts_api_key_field_source(self, admin_client):
        """The new ``api_key_field`` source is valid (covered
        by the model validator) — the API accepts it."""
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=_make_api_key("k-api-key-source")
            )
            body = {
                "rules": [
                    {
                        "claim_name": "https://authglow.example.com/claims/api_key_tier",
                        "source": "api_key_field",
                        "source_config": {"api_key_field": "tier"},
                        "include_in": ["access_token"],
                    }
                ]
            }
            resp = admin_client.put(
                "/api/admin/api-keys/k-api-key-source/claim-policy",
                json=body,
            )
            assert resp.status_code == 200, resp.text


class TestDeleteApiKeyClaimPolicy:
    def test_delete_removes_saved_policy(self, admin_client, test_settings):
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=_make_api_key("k-del")
            )
            from authglow.services.claim_policy import ClaimPolicyService

            svc = ClaimPolicyService()
            rule = ClaimRule(
                claim_name="https://authglow.example.com/claims/api_key_name",
                source=ClaimSource.API_KEY_FIELD,
                source_config=ClaimSourceConfig(api_key_field="name"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )
            asyncio.run(svc.save_api_key_policy("k-del", [rule]))

            resp = admin_client.delete(
                "/api/admin/api-keys/k-del/claim-policy"
            )
            assert resp.status_code == 204
            # Subsequent GET returns the default
            resp = admin_client.get(
                "/api/admin/api-keys/k-del/claim-policy"
            )
            assert resp.status_code == 200
            assert resp.json()["is_custom"] is False

    def test_delete_when_no_saved_is_idempotent_204(self, admin_client):
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=_make_api_key("k-del-empty")
            )
            resp = admin_client.delete(
                "/api/admin/api-keys/k-del-empty/claim-policy"
            )
            assert resp.status_code == 204

    def test_delete_unknown_key_is_404(self, admin_client):
        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(return_value=None)
            resp = admin_client.delete(
                "/api/admin/api-keys/does-not-exist/claim-policy"
            )
            assert resp.status_code == 404


class TestRequireAdmin:
    def test_non_admin_user_rejected(self, test_settings):
        from authglow.models.user import User

        non_admin = User(
            id="non-admin",
            email="user@test.com",
            hashed_password=hash_password("TestP@ss123!"),
            is_active=True,
            scopes=["read"],
        )
        app = FastAPI()
        app.include_router(claim_policy_router)
        client = TestClient(app)
        resp = client.get("/api/admin/claim-templates")
        assert resp.status_code in (401, 403)


class TestApiKeyBuildClaimsReplace:
    """Build-claims integration test for the API key REPLACE
    semantic: the namespaced RBAC defaults must NOT auto-emit
    when the API key has no saved policy. The unit-test class
    ``TestBuildClaimsAPIKeyReplace`` covers the service-level
    branch; this test pins the same invariant through the
    route handler that ``exchange_api_key_for_token`` calls."""

    def _mock_key(self, key_id: str) -> APIKey:
        return _make_api_key(key_id)

    def test_no_policy_no_extra_claims(
        self, admin_client, test_settings
    ) -> None:
        from authglow.services.claim_policy import ClaimPolicyService

        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=self._mock_key("k-clean")
            )

            svc = ClaimPolicyService()
            from authglow.models.user import User

            user = User(
                id="u-1",
                email="u@test.com",
                hashed_password=hash_password("TestP@ss123!"),
                is_active=True,
                scopes=["read"],
            )

            claims = asyncio.run(
                svc.build_claims(
                    user,
                    api_key_id="k-clean",
                    api_key=self._mock_key("k-clean"),
                    scopes=["read"],
                    target=ClaimTarget.ACCESS_TOKEN,
                )
            )
            ns = test_settings.claim_namespace.rstrip("/")
            assert claims == {}
            assert f"{ns}/roles" not in claims
            assert f"{ns}/permissions" not in claims

    def test_saved_policy_alone_emits(
        self, admin_client, test_settings
    ) -> None:
        from authglow.services.claim_policy import ClaimPolicyService

        with patch(
            "authglow.api.claim_policy.APIKeyService"
        ) as MockService:
            MockService.return_value.get_key = AsyncMock(
                return_value=self._mock_key("k-rule")
            )

            svc = ClaimPolicyService()
            from authglow.models.user import User

            user = User(
                id="u-1",
                email="u@test.com",
                hashed_password=hash_password("TestP@ss123!"),
                is_active=True,
                scopes=["read"],
            )
            rule = ClaimRule(
                claim_name="https://authglow.example.com/claims/tenant_id",
                source=ClaimSource.STATIC,
                source_config=ClaimSourceConfig(value="acme"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )
            asyncio.run(svc.save_api_key_policy("k-rule", [rule]))

            claims = asyncio.run(
                svc.build_claims(
                    user,
                    api_key_id="k-rule",
                    api_key=self._mock_key("k-rule"),
                    scopes=["read"],
                    target=ClaimTarget.ACCESS_TOKEN,
                )
            )
            ns = test_settings.claim_namespace.rstrip("/")
            assert claims == {
                "https://authglow.example.com/claims/tenant_id": "acme"
            }
            assert f"{ns}/roles" not in claims
            assert f"{ns}/permissions" not in claims
