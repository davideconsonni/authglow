"""Unit tests for the checktool group registry."""

import pytest

import checktool.groups  # noqa: F401  (registers every group)
from checktool.config import CheckConfig
from checktool.console import ConsoleUI
from checktool.registry import Group, GroupContext, all_groups, get_group, register_group
from checktool.results import GroupResult

EXPECTED_CORE_GROUPS = {"bootstrap", "auth", "oauth2", "api_keys", "rbac", "admin_users"}

EXPECTED_BACKLOG_GROUPS = {
    "mfa",
    "oauth_clients",
    "claim_policy",
    "device_auth",
    "user_profile",
    "password_reset",
    "email_verification",
    "webhooks",
    "federation",
    "sessions",
    "consents",
    "jwk_keys",
    "settings",
    "par",
    "passkeys",
    "phone_verification",
    "demo_inbox",
    "admin_insights",
}


class TestRegistry:
    def test_core_groups_are_registered(self):
        assert EXPECTED_CORE_GROUPS.issubset(set(g.slug for g in all_groups()))

    def test_backlog_groups_are_registered(self):
        registered = {g.slug for g in all_groups()}
        assert EXPECTED_BACKLOG_GROUPS.issubset(registered)
        # Every group must have a non-empty title/description for the UI.
        for group in all_groups():
            assert group.title
            assert group.description

    def test_lookup_by_slug(self):
        group = get_group("oauth2")
        assert group is not None
        assert group.requires_admin is True

    def test_bootstrap_group_needs_no_admin(self):
        assert get_group("bootstrap").requires_admin is False

    def test_duplicate_slug_rejected(self):
        class Dupe(Group):
            slug = "bootstrap"
            title = "x"

        with pytest.raises(ValueError):
            register_group(Dupe)

    def test_missing_slug_rejected(self):
        class NoSlug(Group):
            slug = ""
            title = "x"

        with pytest.raises(ValueError):
            register_group(NoSlug)


class TestContextHelpers:
    def _ctx(self, base_url="http://localhost:8000"):
        config = CheckConfig(base_url=base_url, run_id="abc123")
        ui = ConsoleUI(quiet=True)
        return GroupContext(api=None, config=config, ui=ui, result=GroupResult("g", "G"))

    def test_namespaced_names(self):
        ctx = self._ctx()
        assert ctx.name("key") == "ct-abc123-key"
        assert ctx.email("user") == "ct-abc123-user@example.com"

    def test_expose_records_raw_secret_by_default(self):
        from checktool.client import ApiClient

        config = CheckConfig(base_url="http://localhost:8000", run_id="abc123")
        ctx = GroupContext(
            api=ApiClient(config.base_url),
            config=config,
            ui=ConsoleUI(quiet=True),
            result=GroupResult("g", "G"),
        )
        ctx.expose("API key", "supersecretvalue")
        assert ctx.result.artifacts[0].value == "supersecretvalue"

    def test_expose_masks_when_secrets_disabled(self):
        from checktool.client import ApiClient

        config = CheckConfig(base_url="http://localhost:8000", run_id="abc123", show_secrets=False)
        ctx = GroupContext(
            api=ApiClient(config.base_url),
            config=config,
            ui=ConsoleUI(quiet=True),
            result=GroupResult("g", "G"),
        )
        ctx.expose("API key", "supersecretvalue")
        assert ctx.result.artifacts[0].value == "supers…***"
