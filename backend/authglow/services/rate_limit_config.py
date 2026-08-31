"""Admin-managed rate-limit configuration service.

Bridges the persisted :class:`RateLimitConfig` document and the live
slowapi ``Limiter`` singleton. Two slowapi internals make runtime
reconfiguration possible without a restart:

* ``Limiter.enabled`` is checked on every request by
  ``Limiter._check_request_limit`` — setting it to ``False``
  short-circuits every limit check.
* Each ``Limit`` object held in ``Limiter._route_limits`` exposes its
  ``limits.RateLimitItem`` as ``.limit``, which
  ``_evaluate_limits`` reads at request-evaluation time — patching
  that attribute changes the effective limit immediately.

Multi-node convergence: every node runs a periodic refresh
(:meth:`RateLimitConfigService.refresh_if_changed`) that re-reads the
repository and re-applies the configuration when the persisted
document changed. A PUT applies immediately on the node that handled
it; the other nodes converge within
``Settings.admin_config_refresh_seconds``.

Route identity: overrides are keyed by route *path* (what the admin UI
displays). At startup :func:`build_route_map` resolves every FastAPI
route path to its endpoint function name(s) (``module.func``), which
is the key slowapi uses in ``_route_limits``. Handlers sharing a path
(GET+POST pairs) are patched together — the limit is handler-level,
exactly like the ``@limiter.limit`` decorator that produced it.
"""

from typing import TYPE_CHECKING, Any, Dict, List, Optional

import structlog
from limits import parse_many

from authglow.core.config import Settings, get_settings
from authglow.core.datetime import utcnow
from authglow.models.rate_limit_config import RateLimitConfig
from authglow.repositories.protocols import RateLimitConfigRepository

if TYPE_CHECKING:
    from fastapi import FastAPI
    from slowapi import Limiter

logger = structlog.get_logger("authglow.audit")

# ---------------------------------------------------------------------------
# Process-wide original-limits registry
# ---------------------------------------------------------------------------

# Original (decorator-time) limit strings per endpoint function name,
# captured by :func:`bind_limiter` BEFORE any override is applied. This
# is process-wide state shared by every service instance (per-request
# instances and the long-lived refresher instance alike) so that
# "reset to default" can always restore the decorator value. Tests can
# wipe it via :func:`reset_originals`.
_ORIGINAL_ROUTE_LIMITS: Dict[str, List[str]] = {}


class InvalidRateLimitError(ValueError):
    """Raised when an admin-provided limit string cannot be parsed."""


def bind_limiter(limiter: "Limiter") -> None:
    """Capture the original (decorator-time) limits from *limiter*.

    Must be called once at startup, before applying any persisted
    override. Idempotent: entries already captured are kept, so
    re-binding never replaces a captured original with an
    already-overridden value.
    """
    for func_name, limit_list in getattr(limiter, "_route_limits", {}).items():
        if func_name in _ORIGINAL_ROUTE_LIMITS or not limit_list:
            continue
        _ORIGINAL_ROUTE_LIMITS[func_name] = [
            str(limit.limit) for limit in limit_list
        ]


def reset_originals() -> None:
    """Wipe the process-wide originals registry (tests only)."""
    _ORIGINAL_ROUTE_LIMITS.clear()


def iter_effective_routes(app: "FastAPI") -> Any:
    """Yield ``(path, endpoint, methods)`` for every effective API route.

    Transparently recurses into lazily-included routers: FastAPI >= 0.141
    wraps ``include_router`` results in ``_IncludedRouter`` placeholders
    whose ``effective_candidates()`` resolve prefixes and expose the real
    routes. Older versions expose plain routes directly — handled by the
    same duck-typed walk (no private class imports, so version drift in
    FastAPI internals degrades to "fewer routes found", never a crash).
    """

    def _walk(routes: Any) -> Any:
        for route in routes:
            effective = getattr(route, "effective_candidates", None)
            if callable(effective):
                try:
                    candidates = effective()
                except Exception:
                    logger.warning("route_candidates_enumeration_failed")
                    candidates = []
                yield from _walk(candidates)
                continue
            endpoint = getattr(route, "endpoint", None)
            path = getattr(route, "path", None)
            methods = getattr(route, "methods", None)
            if methods is None:
                methods = getattr(
                    getattr(route, "starlette_route", None), "methods", None
                )
            if endpoint is None or path is None:
                continue
            yield path, endpoint, methods

    yield from _walk(list(getattr(app, "routes", [])))


def build_route_map(app: "FastAPI") -> Dict[str, List[str]]:
    """Map every FastAPI route path to its endpoint function name(s).

    The resulting ``path -> [module.func, ...]`` map is the bridge
    between the path-keyed overrides persisted by the admin UI and the
    function-name keys slowapi uses internally in ``_route_limits``.
    """
    route_map: Dict[str, List[str]] = {}
    for path, endpoint, _methods in iter_effective_routes(app):
        name = f"{endpoint.__module__}.{endpoint.__name__}"
        bucket = route_map.setdefault(path, [])
        if name not in bucket:
            bucket.append(name)
    return route_map


def validate_limit_string(limit_str: str) -> None:
    """Validate a slowapi limit string, raising ``InvalidRateLimitError``.

    Args:
        limit_str: e.g. ``"5/minute"`` or ``"100/hour"``.

    Raises:
        InvalidRateLimitError: if the string cannot be parsed by
            ``limits.parse_many``.
    """
    try:
        items = parse_many(limit_str)
    except ValueError as exc:
        raise InvalidRateLimitError(f"Invalid rate limit string: {limit_str!r}") from exc
    if not items:
        raise InvalidRateLimitError(f"Invalid rate limit string: {limit_str!r}")


class RateLimitConfigService:
    """Applies the persisted rate-limit configuration to the live limiter."""

    def __init__(
        self,
        repository: Optional[RateLimitConfigRepository] = None,
        settings: Optional[Settings] = None,
        limiter: Optional["Limiter"] = None,
    ) -> None:
        """Initialise the service.

        ``repository`` defaults to the factory-selected File impl; tests
        can inject a stub. ``limiter`` defaults to the process singleton
        in ``authglow.core.rate_limit``.
        """
        from authglow.core.rate_limit import limiter as default_limiter
        from authglow.repositories.dependencies import (
            get_rate_limit_config_repository,
        )

        self.settings = settings or get_settings()
        self._repo = repository or get_rate_limit_config_repository(
            settings=self.settings
        )
        self._limiter = limiter or default_limiter
        self._route_map: Dict[str, List[str]] = {}
        self._applied: Optional[RateLimitConfig] = None

    # ------------------------------------------------------------------
    # Startup binding
    # ------------------------------------------------------------------

    def bind_app(self, app: "FastAPI") -> None:
        """Capture the route map + original limits for *app*'s limiter.

        Call once at startup, before the first apply, so overrides can
        be resolved to functions and resets can restore decorator
        defaults.
        """
        self._route_map = build_route_map(app)
        bind_limiter(self._limiter)

    # ------------------------------------------------------------------
    # Persistence + live application
    # ------------------------------------------------------------------

    async def load_config(self) -> RateLimitConfig:
        """Return the persisted configuration (defaults if never saved)."""
        config = await self._repo.load()
        return config if config is not None else RateLimitConfig()

    async def set_config(
        self,
        enabled: Optional[bool] = None,
        overrides_update: Optional[Dict[str, Optional[str]]] = None,
    ) -> RateLimitConfig:
        """Update, persist, and apply the configuration.

        Args:
            enabled: new global enable flag, or ``None`` to keep.
            overrides_update: mapping of route path -> new limit string,
                or path -> ``None`` to remove the override (reset to the
                decorator default).

        Returns:
            The updated, persisted configuration.

        Raises:
            InvalidRateLimitError: if any provided limit string is invalid
                (nothing is persisted or applied in that case).
        """
        if overrides_update:
            for limit_str in overrides_update.values():
                if limit_str is not None:
                    validate_limit_string(limit_str)

        config = await self.load_config()
        if enabled is not None:
            config.enabled = enabled
        if overrides_update:
            for path, limit_str in overrides_update.items():
                if limit_str is None:
                    config.overrides.pop(path, None)
                else:
                    config.overrides[path] = limit_str
        config.updated_at = utcnow()

        await self._repo.save(config)
        self._apply(config)
        return config

    async def refresh_if_changed(self) -> bool:
        """Reload the persisted config and re-apply it if it changed.

        Never raises on repository errors: the periodic refresher must
        not take the worker down over a transient read failure.

        Returns:
            ``True`` if the configuration was (re)applied.
        """
        try:
            config = await self._repo.load()
        except Exception:
            logger.warning("rate_limit_config_refresh_read_failed")
            return False
        if config is None:
            return False
        if (
            self._applied is not None
            and config.model_dump(mode="json") == self._applied.model_dump(mode="json")
        ):
            return False
        self._apply(config)
        logger.debug(
            "rate_limit_config_applied",
            enabled=config.enabled,
            overrides_count=len(config.overrides),
            source="refresh",
        )
        return True

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _patch_func(self, func_name: str, limit_str: Optional[str]) -> None:
        """Patch (or restore) the ``Limit`` objects for *func_name*.

        With ``limit_str`` set, every ``Limit`` in the function's list
        gets its ``.limit`` replaced with the parsed item (the codebase
        uses single-limit decorators, so in practice the list has one
        element). With ``limit_str`` ``None``, each position is
        restored to its captured decorator default.
        """
        limit_list = getattr(self._limiter, "_route_limits", {}).get(func_name) or []
        originals = _ORIGINAL_ROUTE_LIMITS.get(func_name) or []
        if limit_str is None:
            for i, limit in enumerate(limit_list):
                if i < len(originals):
                    limit.limit = parse_many(originals[i])[0]
            return
        item = parse_many(limit_str)[0]
        for limit in limit_list:
            limit.limit = item

    def _apply(self, config: RateLimitConfig) -> None:
        """Apply *config* to the live limiter (idempotent).

        All captured functions are restored to their decorator defaults
        first, then the current overrides are re-applied — removals and
        value changes are handled with the same code path.
        """
        self._limiter.enabled = config.enabled
        for func_name in list(_ORIGINAL_ROUTE_LIMITS.keys()):
            self._patch_func(func_name, None)
        applied_paths = 0
        for path, limit_str in config.overrides.items():
            for func_name in self._route_map.get(path, []):
                if func_name in _ORIGINAL_ROUTE_LIMITS:
                    self._patch_func(func_name, limit_str)
                    applied_paths += 1
        if applied_paths < len(config.overrides):
            logger.warning(
                "rate_limit_config_unresolved_paths",
                unresolved=[
                    path
                    for path in config.overrides
                    if not self._route_map.get(path)
                ],
            )
        self._applied = config

    # ------------------------------------------------------------------
    # Introspection helpers (API layer)
    # ------------------------------------------------------------------

    def current_config(self) -> Optional[RateLimitConfig]:
        """Return the last applied in-memory config, if any."""
        return self._applied
