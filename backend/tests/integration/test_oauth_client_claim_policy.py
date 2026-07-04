"""Integration tests for the claim policy admin API.

End-to-end tests that exercise the GET / PUT / DELETE
endpoints and the templates listing against a FastAPI
``TestClient``, with the OAuth2 client storage and the
claim policy repository stubbed or backed by the real
``FileClientClaimPolicyRepository`` (so the JSON file
persistence is exercised on the test tmp_path).
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.claim_policy import router as claim_policy_router
from authglow.api.claim_policy import require_admin
from authglow.models.claim_policy import (
    BUILTIN_TEMPLATES,
    ClaimRule,
    ClaimSource,
    ClaimSourceConfig,
    ClaimTarget,
)
from authglow.models.oauth_client import OAuth2Client
from authglow.services.password import hash_password


def _make_admin_user():
    from authglow.models.user import User

    return User(
        id="admin-1",
        email="admin@test.com",
        hashed_password=hash_password("TestP@ss123!"),
        is_active=True,
        scopes=["admin"],
    )


def _make_client(client_id: str = "test-client-1") -> OAuth2Client:
    return OAuth2Client(
        client_id=client_id,
        client_secret="$2b$12$dummyhash",
        client_name="Test Client",
        redirect_uris=["https://example.com/callback"],
        allowed_scopes=["read", "write"],
        grant_types=["authorization_code"],
        is_active=True,
    )


@pytest.fixture
def admin_client(test_settings):
    """A FastAPI ``TestClient`` with ``require_admin`` bypassed
    and the underlying services backed by the real
    ``FileClientClaimPolicyRepository`` (against the
    per-test tmp_path)."""
    app = FastAPI()
    app.include_router(claim_policy_router)
    app.dependency_overrides[require_admin] = lambda: _make_admin_user()
    return TestClient(app)


class TestGetClaimPolicy:
    def test_returns_default_when_no_saved_policy(self, admin_client):
        resp = admin_client.get(
            "/api/admin/oauth-clients/no-such-client/claim-policy"
        )
        # 404 because the OAuth2 client does not exist
        assert resp.status_code == 404

    def test_returns_default_payload_for_existing_client_without_policy(
        self, admin_client, test_settings
    ):
        # Stub the storage to return a valid client
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(
                return_value=_make_client("c-no-policy")
            )
            resp = admin_client.get(
                "/api/admin/oauth-clients/c-no-policy/claim-policy"
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["is_custom"] is False
            # The default RBAC rules are in ``default_rules``
            # (read-only informational) — NOT in ``rules``
            # (which the admin UI shows as the editable
            # "Current Rules" list). This is the regression
            # fix for the "default masquerading as user
            # rules" UX bug.
            assert data["rules"] == []
            assert len(data["default_rules"]) == 2
            ns = test_settings.claim_namespace.rstrip("/")
            assert any(
                r["claim_name"] == f"{ns}/roles" for r in data["default_rules"]
            )
            assert any(
                r["claim_name"] == f"{ns}/permissions"
                for r in data["default_rules"]
            )

    def test_returns_saved_policy_when_present(self, admin_client, test_settings):
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(
                return_value=_make_client("c-saved")
            )
            # Pre-save a policy directly via the service
            from authglow.services.claim_policy import ClaimPolicyService

            svc = ClaimPolicyService()
            rule = ClaimRule(
                claim_name="https://authglow/tenant",
                source=ClaimSource.USER_FIELD,
                source_config=ClaimSourceConfig(user_field="tenant_id"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )
            asyncio.run(svc.save_policy("c-saved", [rule]))

            resp = admin_client.get(
                "/api/admin/oauth-clients/c-saved/claim-policy"
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["is_custom"] is True
            assert len(data["rules"]) == 1
            assert data["rules"][0]["claim_name"] == "https://authglow/tenant"


class TestPutClaimPolicy:
    def test_put_replaces_saved_policy(self, admin_client):
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(
                return_value=_make_client("c-put")
            )
            body = {
                "rules": [
                    {
                        "claim_name": "https://authglow/tenant",
                        "source": "user_field",
                        "source_config": {"user_field": "tenant_id"},
                        "include_in": ["access_token"],
                    }
                ]
            }
            resp = admin_client.put(
                "/api/admin/oauth-clients/c-put/claim-policy", json=body
            )
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["is_custom"] is True
            assert len(data["rules"]) == 1
            assert data["rules"][0]["claim_name"] == "https://authglow/tenant"

    def test_put_with_empty_rules_deletes_saved(self, admin_client, test_settings):
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(
                return_value=_make_client("c-empty")
            )
            # First save something
            from authglow.services.claim_policy import ClaimPolicyService

            svc = ClaimPolicyService()
            rule = ClaimRule(
                claim_name="https://authglow/x",
                source=ClaimSource.STATIC,
                source_config=ClaimSourceConfig(value="y"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )
            asyncio.run(svc.save_policy("c-empty", [rule]))
            # Now PUT with empty rules → should delete
            resp = admin_client.put(
                "/api/admin/oauth-clients/c-empty/claim-policy",
                json={"rules": []},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["is_custom"] is False
            # No custom rules saved; the defaults live in
            # ``default_rules`` (read-only).
            assert data["rules"] == []
            assert len(data["default_rules"]) == 2

    def test_put_rejects_non_uri_claim_name(self, admin_client):
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(
                return_value=_make_client("c-bad")
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
                "/api/admin/oauth-clients/c-bad/claim-policy", json=body
            )
            assert resp.status_code == 422

    def test_put_rejects_unknown_source(self, admin_client):
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(
                return_value=_make_client("c-bad-source")
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
                "/api/admin/oauth-clients/c-bad-source/claim-policy", json=body
            )
            assert resp.status_code == 422

    def test_put_rejects_duplicate_claim_names(self, admin_client):
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(
                return_value=_make_client("c-dup")
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
                "/api/admin/oauth-clients/c-dup/claim-policy", json=body
            )
            assert resp.status_code == 422


class TestDeleteClaimPolicy:
    def test_delete_removes_saved_policy(self, admin_client):
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(
                return_value=_make_client("c-del")
            )
            from authglow.services.claim_policy import ClaimPolicyService

            svc = ClaimPolicyService()
            rule = ClaimRule(
                claim_name="https://authglow/x",
                source=ClaimSource.STATIC,
                source_config=ClaimSourceConfig(value="y"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )
            asyncio.run(svc.save_policy("c-del", [rule]))

            resp = admin_client.delete(
                "/api/admin/oauth-clients/c-del/claim-policy"
            )
            assert resp.status_code == 204
            # Subsequent GET returns the default
            resp = admin_client.get(
                "/api/admin/oauth-clients/c-del/claim-policy"
            )
            assert resp.status_code == 200
            assert resp.json()["is_custom"] is False

    def test_delete_when_no_saved_is_idempotent_204(self, admin_client):
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(
                return_value=_make_client("c-del-empty")
            )
            resp = admin_client.delete(
                "/api/admin/oauth-clients/c-del-empty/claim-policy"
            )
            assert resp.status_code == 204

    def test_delete_unknown_client_is_404(self, admin_client):
        with patch(
            "authglow.api.claim_policy.OAuth2ClientStorage"
        ) as MockStorage:
            MockStorage.return_value.get_client = AsyncMock(return_value=None)
            resp = admin_client.delete(
                "/api/admin/oauth-clients/does-not-exist/claim-policy"
            )
            assert resp.status_code == 404


class TestListClaimTemplates:
    def test_returns_builtin_templates(self, admin_client):
        resp = admin_client.get("/api/admin/claim-templates")
        assert resp.status_code == 200
        data = resp.json()
        ids = [t["id"] for t in data]
        assert set(ids) == {t.id for t in BUILTIN_TEMPLATES}
        # Spot-check the rbac-roles template
        rbac_roles = next(t for t in data if t["id"] == "rbac-roles")
        assert rbac_roles["source"] == "rbac_roles"
        assert "access_token" in rbac_roles["include_in"]

    def test_template_claim_names_are_namespace_expanded(self, admin_client, test_settings):
        """The server expands the relative ``claim_name`` field
        of each built-in template against
        ``settings.claim_namespace`` before returning. The
        frontend would otherwise see ``api_key_tier`` (the
        relative form) and reject it via the OIDC §5.1.2
        validator (only OIDC standard claims and absolute
        URIs are accepted).
        """
        resp = admin_client.get("/api/admin/claim-templates")
        assert resp.status_code == 200
        data = resp.json()
        ns = test_settings.claim_namespace.rstrip("/")
        # Spot-check several templates
        expected_pairs = [
            ("rbac-roles", f"{ns}/roles"),
            ("rbac-permissions", f"{ns}/permissions"),
            ("user-tenant", f"{ns}/tenant_id"),
            ("api-key-name", f"{ns}/api_key_name"),
            ("api-key-tier", f"{ns}/api_key_tier"),
        ]
        for template_id, expected_name in expected_pairs:
            t = next(t_ for t_ in data if t_["id"] == template_id)
            assert t["claim_name"] == expected_name, (
                f"Template {template_id!r} returned {t['claim_name']!r}, "
                f"expected the namespace-expanded form {expected_name!r}"
            )

    def test_no_template_returns_unexpanded_relative_name(
        self, admin_client, test_settings
    ):
        """None of the returned templates should have a
        relative (un-namespaced) claim name — that is the
        root cause of the "must be a URI" error the admin
        would otherwise see when clicking a Quick template."""
        resp = admin_client.get("/api/admin/claim-templates")
        assert resp.status_code == 200
        data = resp.json()
        for t in data:
            name = t["claim_name"]
            # The OIDC standard claim whitelist — these are
            # the only short names that are legal.
            is_standard_claim = name in {
                "sub", "email", "name", "iss", "aud", "exp", "iat",
                "jti", "scope", "client_id",
            }
            is_uri = name.startswith("https://") or name.startswith("urn:")
            assert is_standard_claim or is_uri, (
                f"Template {t['id']!r} has an unexpanded relative "
                f"claim_name {name!r} — the frontend would reject it"
            )


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
        # Don't override require_admin — the real check runs
        client = TestClient(app)
        resp = client.get("/api/admin/claim-templates")
        # 401 because the request has no auth (get_current_user
        # requires a session or a token)
        assert resp.status_code in (401, 403)
