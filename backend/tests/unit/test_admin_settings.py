import inspect
from unittest.mock import patch


class TestAdminSettingsEndpointStructure:
    def test_router_has_settings_endpoints(self):
        from authglow.api.admin_settings import router

        paths = set()
        for r in router.routes:
            if hasattr(r, "path"):
                paths.add(r.path)
        assert "/api/admin/settings" in paths
        assert "/api/admin/settings/schema" in paths

    def test_settings_endpoint_is_read_only(self):
        from authglow.api.admin_settings import router

        patch_paths = []
        for r in router.routes:
            if hasattr(r, "methods") and hasattr(r, "path"):
                if "PATCH" in r.methods:
                    patch_paths.append(r.path)
        assert not patch_paths, f"Found PATCH endpoints: {patch_paths}"

    def test_get_settings_returns_grouped_data(self):
        from authglow.api.admin_settings import _get_settings_fields, _FIELD_META, _CATEGORY_ORDER

        with patch("authglow.core.config.get_settings") as mock_get:
            from authglow.core.config import Settings

            mock_get.return_value = Settings(secret_key="0" * 32)
            fields = _get_settings_fields(mock_get.return_value)

        assert len(fields) > 0
        keys = {f["key"] for f in fields}
        assert "secret_key" not in keys  # excluded
        assert "app_name" in keys
        assert all(f["category"] in _CATEGORY_ORDER for f in fields)

    def test_field_meta_covers_all_categorized_fields(self):
        import pathlib
        from authglow.api.admin_settings import _FIELD_META, _EXCLUDED_FIELDS

        config_path = pathlib.Path(__file__).parent.parent.parent / "authglow" / "core" / "config.py"
        source = config_path.read_text()
        import re

        field_names = set(re.findall(r"^\s+(\w+):\s", source, re.MULTILINE))
        excluded_in_meta = _EXCLUDED_FIELDS | {
            "auth_cookie_secure", "is_production", "model_config",
            "get_storage_options", "get_cors_origins", "get_cors_methods",
            "get_cors_headers", "get_trusted_proxies", "def",
        }
        categorized = set(_FIELD_META.keys())
        missing = field_names - excluded_in_meta - categorized
        acceptable_missing = {
            "host", "port", "keys_dir", "private_key_path", "public_key_path",
            "model_config",
            # Local variables from helper functions in config.py (not Settings fields)
            "keyring_path", "keyring", "kid", "old_kid", "key_size",
            "rotation_days", "auto_rotate", "options", "smtp_username", "try",
            "finally", "Implementation",
            # Doc-comment text matched by the naive regex (e.g.
            # ``# Security: the file is written in plaintext...``).
            "Security",
        }
        unexpected = missing - acceptable_missing
        assert not unexpected, f"Fields in config.py but not in _FIELD_META: {unexpected}"

    def test_frontend_base_url_not_duplicated(self):
        import pathlib
        config_path = pathlib.Path(__file__).parent.parent.parent / "authglow" / "core" / "config.py"
        source = config_path.read_text()
        count = source.count("frontend_base_url")
        assert count == 1, f"frontend_base_url appears {count} times in config.py source"
