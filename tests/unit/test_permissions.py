import pytest
from unittest.mock import patch, MagicMock


class TestLazyJWTServiceInit:
    def test_import_does_not_instantiate_jwt_service(self):
        import importlib
        import authglow.core.permissions as perm_mod

        with patch.object(
            perm_mod.JWTService, "__init__", side_effect=RuntimeError("should not init")
        ) as mock_init:
            importlib.reload(perm_mod)
            mock_init.assert_not_called()

    def test_lazy_init_creates_instance_on_first_call(self, test_settings):
        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            from authglow.core.permissions import _get_jwt_service, _jwt_service

            import authglow.core.permissions as perm_mod
            import importlib

            perm_mod._jwt_service = None

            svc = _get_jwt_service()
            assert svc is not None
            assert perm_mod._jwt_service is svc

    def test_lazy_init_caches_instance(self, test_settings):
        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            import authglow.core.permissions as perm_mod

            perm_mod._jwt_service = None

            svc1 = perm_mod._get_jwt_service()
            svc2 = perm_mod._get_jwt_service()
            assert svc1 is svc2

    def test_reset_lazy_singleton(self, test_settings):
        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            import authglow.core.permissions as perm_mod

            perm_mod._jwt_service = None
            svc1 = perm_mod._get_jwt_service()
            perm_mod._jwt_service = None
            svc2 = perm_mod._get_jwt_service()
            assert svc1 is not svc2
