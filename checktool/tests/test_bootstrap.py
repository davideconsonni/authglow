"""Unit tests for checktool credential bootstrap (no network)."""

import re

from checktool import bootstrap
from checktool.config import CheckConfig


class TestGeneratedPassword:
    def test_meets_common_policy(self):
        for _ in range(20):
            password = bootstrap._generate_password()
            assert len(password) >= 12
            assert re.search(r"[A-Z]", password)
            assert re.search(r"[a-z]", password)
            assert re.search(r"\d", password)
            assert re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password)


class TestProvidedCredentials:
    def test_from_cli_args(self):
        config = CheckConfig(email="a@example.com", password="pw")
        creds = bootstrap._provided(config)
        assert creds is not None
        assert creds.email == "a@example.com"

    def test_none_without_credentials(self, monkeypatch):
        monkeypatch.delenv("AUTHGLOW_ADMIN_EMAIL", raising=False)
        monkeypatch.delenv("AUTHGLOW_ADMIN_PASSWORD", raising=False)
        assert bootstrap._provided(CheckConfig()) is None

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("AUTHGLOW_ADMIN_EMAIL", "env@example.com")
        monkeypatch.setenv("AUTHGLOW_ADMIN_PASSWORD", "envpw")
        creds = bootstrap._provided(CheckConfig())
        assert creds is not None and creds.email == "env@example.com"


class TestSetupTokenResolution:
    def test_config_token_wins(self, monkeypatch):
        monkeypatch.setenv("SETUP_TOKEN", "from-env")
        assert bootstrap._setup_token(CheckConfig(setup_token="from-config")) == "from-config"

    def test_env_token_used(self, monkeypatch):
        monkeypatch.setenv("SETUP_TOKEN", "from-env")
        assert bootstrap._setup_token(CheckConfig()) == "from-env"


class TestStatePersistence:
    def test_round_trip(self, monkeypatch, tmp_path):
        state_file = tmp_path / "state.json"
        monkeypatch.setattr(bootstrap, "STATE_PATH", state_file)
        creds = bootstrap.Credentials("x@example.com", "secret", "test")
        bootstrap._write_state(creds)
        loaded = bootstrap._read_state()
        assert loaded is not None
        assert loaded.email == "x@example.com"
        assert loaded.password == "secret"

    def test_missing_state_returns_none(self, monkeypatch, tmp_path):
        monkeypatch.setattr(bootstrap, "STATE_PATH", tmp_path / "absent.json")
        assert bootstrap._read_state() is None
