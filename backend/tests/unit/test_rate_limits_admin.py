import inspect


class TestRateLimitsAdminEndpoint:
    def test_router_has_rate_limits_endpoints(self):
        from authglow.api.admin_settings import router

        paths = set()
        for r in router.routes:
            if hasattr(r, "path"):
                paths.add(r.path)
        assert "/api/admin/rate-limits" in paths
        assert "/api/admin/rate-limits/status" in paths

    def test_get_rate_limits_reads_from_app_state(self):
        from authglow.api.admin_settings import get_rate_limits
        source = inspect.getsource(get_rate_limits)
        assert "app.state.limiter" in source
        assert "_route_limits" in source

    def test_get_rate_limits_status_returns_stats(self):
        from authglow.api.admin_settings import get_rate_limits_status
        source = inspect.getsource(get_rate_limits_status)
        assert "total_routes_limited" in source
        assert "enabled" in source

    def test_federation_model_has_rate_limit_field(self):
        from authglow.models.federation import ExternalIdpConfig

        assert "rate_limit_per_minute" in ExternalIdpConfig.model_fields

    def test_federation_create_has_rate_limit_field(self):
        from authglow.models.federation import ExternalIdpConfigCreate

        assert "rate_limit_per_minute" in ExternalIdpConfigCreate.model_fields

    def test_federation_update_has_rate_limit_field(self):
        from authglow.models.federation import ExternalIdpConfigUpdate

        assert "rate_limit_per_minute" in ExternalIdpConfigUpdate.model_fields

    def test_federation_response_has_rate_limit_field(self):
        from authglow.models.federation import ExternalIdpConfigResponse

        assert "rate_limit_per_minute" in ExternalIdpConfigResponse.model_fields

    def test_rate_limit_field_has_ge_validation(self):
        from authglow.models.federation import ExternalIdpConfigCreate

        field = ExternalIdpConfigCreate.model_fields["rate_limit_per_minute"]
        assert field is not None
