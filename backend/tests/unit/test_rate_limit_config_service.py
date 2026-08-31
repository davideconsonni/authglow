"""Unit tests for the RateLimitConfigService.

Covers limit-string validation, live patching of the slowapi limiter
(via a stub limiter mirroring the ``_route_limits`` shape), reset to
decorator defaults, persisted-state change detection
(``refresh_if_changed``), and tolerance for unknown route paths.

Repository conformance is covered by
``tests/unit/repositories/file/test_rate_limit_config.py``; API-level
behaviour by ``tests/unit/test_admin_runtime_config_api.py``.
"""

import pytest
from fastapi import FastAPI
from limits import parse_many

from authglow.models.rate_limit_config import RateLimitConfig
from authglow.services.rate_limit_config import (
    InvalidRateLimitError,
    RateLimitConfigService,
    bind_limiter,
    build_route_map,
    reset_originals,
    validate_limit_string,
)


class FakeLimit:
    """Mimics slowapi's ``Limit``: holds a ``RateLimitItem``."""

    def __init__(self, item):
        self.limit = item


class FakeLimiter:
    """Mimics slowapi's ``Limiter`` surface used by the service."""

    def __init__(self, route_limits):
        self.enabled = True
        self._route_limits = route_limits
        self._dynamic_route_limits = {}


def _make_app_and_limiter():
    """Build a real FastAPI app (for the route map) + matching stub limiter."""
    app = FastAPI()

    @app.get("/api/login")
    async def login_ep():
        return {}

    @app.post("/api/refresh")
    async def refresh_ep():
        return {}

    route_map = build_route_map(app)
    limiter = FakeLimiter(
        {
            route_map["/api/login"][0]: [FakeLimit(parse_many("10/minute")[0])],
            route_map["/api/refresh"][0]: [FakeLimit(parse_many("5/minute")[0])],
        }
    )
    return app, limiter, route_map


@pytest.fixture(autouse=True)
def _clean_originals():
    reset_originals()
    yield
    reset_originals()


class StubRepo:
    def __init__(self):
        self.saved = None

    async def load(self):
        return self.saved

    async def save(self, config):
        self.saved = config


@pytest.fixture
def stub_repo():
    return StubRepo()


class TestValidateLimitString:
    def test_accepts_valid_limit(self):
        validate_limit_string("5/minute")
        validate_limit_string("100/hour")
        validate_limit_string("10/day")

    @pytest.mark.parametrize("bad", ["banana", "5/banana", "", "abc/minute"])
    def test_rejects_invalid_limit(self, bad):
        with pytest.raises(InvalidRateLimitError):
            validate_limit_string(bad)

    def test_error_is_value_error(self):
        assert issubclass(InvalidRateLimitError, ValueError)


class TestBindLimiter:
    def test_captures_originals(self):
        _app, limiter, _route_map = _make_app_and_limiter()
        bind_limiter(limiter)
        from authglow.services.rate_limit_config import _ORIGINAL_ROUTE_LIMITS

        assert len(_ORIGINAL_ROUTE_LIMITS) == 2
        for originals in _ORIGINAL_ROUTE_LIMITS.values():
            assert originals == ["10 per 1 minute"] or originals == [
                "5 per 1 minute"
            ]

    def test_idempotent_keeps_first_capture(self):
        _app, limiter, route_map = _make_app_and_limiter()
        bind_limiter(limiter)
        # Simulate an override having been applied, then re-bind: the
        # original must NOT be replaced by the overridden value.
        key = route_map["/api/login"][0]
        limiter._route_limits[key][0].limit = parse_many("99/minute")[0]
        bind_limiter(limiter)
        from authglow.services.rate_limit_config import _ORIGINAL_ROUTE_LIMITS

        assert _ORIGINAL_ROUTE_LIMITS[key] == ["10 per 1 minute"]


class TestSetConfig:
    async def test_set_enabled_false_applies_and_persists(self, stub_repo):
        _app, limiter, _route_map = _make_app_and_limiter()
        service = RateLimitConfigService(
            repository=stub_repo, settings=None, limiter=limiter
        )
        service.bind_app(_app)

        config = await service.set_config(enabled=False)

        assert limiter.enabled is False
        assert config.enabled is False
        assert stub_repo.saved is config

    async def test_set_override_patches_limit_in_place(self, stub_repo):
        _app, limiter, route_map = _make_app_and_limiter()
        service = RateLimitConfigService(
            repository=stub_repo, settings=None, limiter=limiter
        )
        service.bind_app(_app)

        await service.set_config(overrides_update={"/api/login": "2/hour"})

        key = route_map["/api/login"][0]
        assert str(limiter._route_limits[key][0].limit) == "2 per 1 hour"
        # Untouched route keeps its decorator default.
        other = route_map["/api/refresh"][0]
        assert str(limiter._route_limits[other][0].limit) == "5 per 1 minute"

    async def test_reset_override_restores_original(self, stub_repo):
        _app, limiter, route_map = _make_app_and_limiter()
        service = RateLimitConfigService(
            repository=stub_repo, settings=None, limiter=limiter
        )
        service.bind_app(_app)
        key = route_map["/api/login"][0]

        await service.set_config(overrides_update={"/api/login": "2/hour"})
        await service.set_config(overrides_update={"/api/login": None})

        assert str(limiter._route_limits[key][0].limit) == "10 per 1 minute"

    async def test_invalid_limit_aborts_everything(self, stub_repo):
        _app, limiter, route_map = _make_app_and_limiter()
        service = RateLimitConfigService(
            repository=stub_repo, settings=None, limiter=limiter
        )
        service.bind_app(_app)

        with pytest.raises(InvalidRateLimitError):
            await service.set_config(
                overrides_update={"/api/login": "2/hour", "/api/refresh": "garbage"}
            )

        # Nothing persisted, nothing applied.
        assert stub_repo.saved is None
        key = route_map["/api/login"][0]
        assert str(limiter._route_limits[key][0].limit) == "10 per 1 minute"

    async def test_unknown_path_is_tolerated(self, stub_repo):
        _app, limiter, _route_map = _make_app_and_limiter()
        service = RateLimitConfigService(
            repository=stub_repo, settings=None, limiter=limiter
        )
        service.bind_app(_app)

        config = await service.set_config(overrides_update={"/api/ghost": "1/minute"})

        assert config.overrides["/api/ghost"] == "1/minute"
        assert limiter.enabled is True

    async def test_reapply_all_removes_stale_overrides(self, stub_repo):
        _app, limiter, route_map = _make_app_and_limiter()
        service = RateLimitConfigService(
            repository=stub_repo, settings=None, limiter=limiter
        )
        service.bind_app(_app)
        key = route_map["/api/login"][0]

        await service.set_config(overrides_update={"/api/login": "2/hour"})
        # Simulate another node removing the override in the persisted doc.
        stub_repo.saved = RateLimitConfig(enabled=True, overrides={})
        changed = await service.refresh_if_changed()

        assert changed is True
        assert str(limiter._route_limits[key][0].limit) == "10 per 1 minute"


class TestRefreshIfChanged:
    async def test_applies_when_repo_changed(self, stub_repo):
        _app, limiter, _route_map = _make_app_and_limiter()
        service = RateLimitConfigService(
            repository=stub_repo, settings=None, limiter=limiter
        )
        service.bind_app(_app)

        stub_repo.saved = RateLimitConfig(enabled=False)
        changed = await service.refresh_if_changed()

        assert changed is True
        assert limiter.enabled is False

    async def test_noop_when_unchanged(self, stub_repo):
        _app, limiter, _route_map = _make_app_and_limiter()
        service = RateLimitConfigService(
            repository=stub_repo, settings=None, limiter=limiter
        )
        service.bind_app(_app)
        await service.set_config(enabled=False)
        before = limiter.enabled

        changed = await service.refresh_if_changed()

        assert changed is False
        assert limiter.enabled is before

    async def test_false_when_never_saved(self, stub_repo):
        _app, limiter, _route_map = _make_app_and_limiter()
        service = RateLimitConfigService(
            repository=stub_repo, settings=None, limiter=limiter
        )
        service.bind_app(_app)

        assert await service.refresh_if_changed() is False

    async def test_swallows_repo_read_errors(self):
        class BrokenRepo:
            async def load(self):
                raise RuntimeError("disk gone")

            async def save(self, config):
                raise RuntimeError("disk gone")

        _app, limiter, _route_map = _make_app_and_limiter()
        service = RateLimitConfigService(
            repository=BrokenRepo(), settings=None, limiter=limiter
        )
        service.bind_app(_app)

        assert await service.refresh_if_changed() is False
