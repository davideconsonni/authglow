"""Tests for the reserved-scope rejection (RBAC admin migration).

The OAuth ``admin`` scope token is reserved: admin authority is
RBAC-driven (the "Authglow Administrator" role), so every ingestion
point that runs ``validate_scope_tokens`` must reject it loudly.
"""

import pytest
from pydantic import ValidationError

from authglow.core.scopes import RESERVED_SCOPE_TOKENS, validate_scope_tokens


class TestReservedScopeTokens:
    def test_admin_is_reserved(self):
        assert "admin" in RESERVED_SCOPE_TOKENS

    def test_validate_rejects_admin(self):
        with pytest.raises(ValueError, match="Reserved scope"):
            validate_scope_tokens(["read", "admin"])

    def test_validate_accepts_regular_scopes(self):
        assert validate_scope_tokens(["read", "write", "offline_access"]) == [
            "read",
            "write",
            "offline_access",
        ]

    def test_user_create_rejects_admin_scope(self):
        from authglow.models.user import UserCreate

        with pytest.raises(ValidationError, match="Authglow Administrator"):
            UserCreate(
                email="u@example.com",
                password="StrongP@ss1!",
                scopes=["read", "admin"],
            )

    def test_invite_rejects_admin_scope(self):
        from authglow.models.user import InviteUser

        with pytest.raises(ValidationError, match="Authglow Administrator"):
            InviteUser(email="i@example.com", scopes=["admin"])

    def test_api_key_create_rejects_admin_scope(self):
        from authglow.models.api_key import APIKeyCreate

        with pytest.raises(ValidationError, match="Authglow Administrator"):
            APIKeyCreate(name="k", scopes=["admin"], never_expires=True)

    def test_admin_update_rejects_admin_scope(self):
        from authglow.models.admin import UserUpdate

        with pytest.raises(ValidationError, match="Authglow Administrator"):
            UserUpdate(scopes=["admin"])
