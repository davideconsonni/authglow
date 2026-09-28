"""Unit tests for checktool runtime configuration."""

from checktool.config import CheckConfig


class TestCheckConfig:
    def test_namespace_has_prefix(self):
        assert CheckConfig().namespace.startswith("ct-")

    def test_localhost_is_local(self):
        assert CheckConfig(base_url="http://localhost:8000").is_local is True

    def test_loopback_ip_is_local(self):
        assert CheckConfig(base_url="http://127.0.0.1:9000").is_local is True

    def test_remote_host_is_not_local(self):
        assert CheckConfig(base_url="https://authglow.example.com").is_local is False

    def test_mode_reflects_locality(self):
        assert CheckConfig(base_url="http://localhost:1").mode == "local"
        assert CheckConfig(base_url="https://example.org").mode == "remote"

    def test_normalized_url_strips_trailing_slash(self):
        assert CheckConfig(base_url="http://localhost:8000/").normalized_url == "http://localhost:8000"
