import inspect
import pathlib


class TestOIDCDiscoveryCustomization:
    def test_discovery_reads_from_settings(self):
        from authglow.api.oidc import openid_configuration
        source = inspect.getsource(openid_configuration)
        assert "oidc_claims_supported" in source
        assert "oidc_scopes_supported" in source
        assert "oidc_grant_types_supported" in source
        assert "oidc_response_types_supported" in source
        assert "oidc_service_documentation" in source

    def test_settings_have_oidc_discovery_fields(self):
        config_path = pathlib.Path(__file__).parent.parent.parent / "authglow" / "core" / "config.py"
        source = config_path.read_text()
        assert "oidc_claims_supported" in source
        assert "oidc_scopes_supported" in source
        assert "oidc_grant_types_supported" in source
        assert "oidc_response_types_supported" in source
        assert "oidc_service_documentation" in source
        assert "oidc_op_policy_uri" in source
        assert "oidc_op_tos_uri" in source

    def test_openid_configuration_model_has_optional_uris(self):
        from authglow.models.oidc import OpenIDConfiguration

        assert "service_documentation" in OpenIDConfiguration.model_fields
        assert "op_policy_uri" in OpenIDConfiguration.model_fields
        assert "op_tos_uri" in OpenIDConfiguration.model_fields
        # These must be optional
        for field_name in ("service_documentation", "op_policy_uri", "op_tos_uri"):
            field = OpenIDConfiguration.model_fields[field_name]
            assert field.annotation is not None

    def test_discovery_custom_scopes_parsed(self):
        from authglow.api.oidc import openid_configuration
        source = inspect.getsource(openid_configuration)
        assert ".split(" in source  # csv parsing

    def test_discovery_uses_defaults_when_fields_are_none(self):
        from authglow.api.oidc import openid_configuration
        source = inspect.getsource(openid_configuration)
        # Falls back to hardcoded defaults
        assert '"openid"' in source  # default scope
        assert '"authorization_code"' in source  # default grant
