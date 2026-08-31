"""Admin-managed ``Settings`` overrides service.

The admin UI (``/admin/settings``) persists per-key overrides to the
``SettingsOverrideRepository`` and live-applies them onto the process
``Settings`` singleton via ``setattr``. Fields whose consumers capture
values at import time (lru_cache / TTLCache construction) are flagged
``restart_required`` in the API layer and only take effect after the
overrides are re-applied at startup (or by the periodic refresher on
the other nodes).

Validation is type-driven: an update is accepted only if the key is a
real ``Settings`` field whose current value is a scalar and whose type
matches the incoming JSON scalar (bool / int / float / str). Secrets
and paths never reach this layer — the API filters them out via
``_EXCLUDED_FIELDS`` before calling in.
"""

from typing import TYPE_CHECKING, Any, Dict, Optional

import structlog

from authglow.core.config import Settings, get_settings

if TYPE_CHECKING:
    from authglow.repositories.protocols import SettingsOverrideRepository

logger = structlog.get_logger("authglow.audit")


class InvalidSettingUpdateError(ValueError):
    """Raised when an admin-provided settings update fails validation."""


def _scalar_type_name(value: Any) -> str:
    """Classify *value* for type-compat checks (bool before int!)."""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "number"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    return "other"


# ---------------------------------------------------------------------------
# Pristine (env-derived) values registry
# ---------------------------------------------------------------------------

# Snapshot of the Settings field values as they came from the
# environment, captured by :func:`capture_pristine` at startup BEFORE
# any persisted override is applied. Process-wide state shared by every
# service instance (per-request instances and the refresher alike) so
# that "remove override" can restore the env-derived value. Tests can
# wipe it via :func:`reset_pristine`.
_PRISTINE_VALUES: Dict[str, Any] = {}


def capture_pristine(settings: Settings) -> None:
    """Snapshot the env-derived scalar values of *settings*.

    Must be called once at startup, before the first override is
    applied. Idempotent: entries already captured are kept.
    """
    for key in type(settings).model_fields:
        if key in _PRISTINE_VALUES:
            continue
        value = getattr(settings, key, None)
        if _scalar_type_name(value) != "other":
            _PRISTINE_VALUES[key] = value


def reset_pristine() -> None:
    """Wipe the pristine registry (tests only)."""
    _PRISTINE_VALUES.clear()


def pristine_value(key: str, default: Any = None) -> Any:
    """Return the captured env-derived value for *key* (or *default*)."""
    return _PRISTINE_VALUES.get(key, default)


class SettingsOverrideService:
    """Persists and live-applies admin ``Settings`` overrides."""

    def __init__(
        self,
        repository: Optional["SettingsOverrideRepository"] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        """Initialise the service.

        ``repository`` defaults to the factory-selected File impl; tests
        can inject a stub. ``settings`` defaults to the process singleton
        from ``get_settings()`` — overrides are applied onto THIS object,
        so a patched binding (tests) mutates the patched instance.
        """
        from authglow.repositories.dependencies import (
            get_settings_override_repository,
        )

        self.settings = settings or get_settings()
        self._repo = repository or get_settings_override_repository(
            settings=self.settings
        )
        self._applied: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_updates(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Validate admin updates against the live ``Settings``.

        Args:
            updates: ``{setting_key: value}`` proposed updates.

        Returns:
            The validated subset (same shape).

        Raises:
            InvalidSettingUpdateError: on unknown key, non-scalar target,
                null value, or type mismatch.
        """
        validated: Dict[str, Any] = {}
        model_fields = type(self.settings).model_fields
        for key, value in updates.items():
            if key not in model_fields:
                raise InvalidSettingUpdateError(f"Unknown setting: {key}")
            if value is None:
                raise InvalidSettingUpdateError(f"Setting {key} cannot be null")
            current = getattr(self.settings, key)
            current_type = _scalar_type_name(current)
            if current_type == "other":
                raise InvalidSettingUpdateError(
                    f"Setting {key} is not an admin-editable scalar value"
                )
            value_type = _scalar_type_name(value)
            if value_type == "other":
                raise InvalidSettingUpdateError(
                    f"Setting {key} must be a scalar value"
                )
            if current_type != value_type:
                # int targets accept JSON ints only; float targets accept
                # ints too (JSON has no int/float distinction for e.g. 30.0).
                if not (current_type == "number" and value_type == "number"):
                    raise InvalidSettingUpdateError(
                        f"Setting {key} expects a {current_type}, "
                        f"got {value_type}"
                    )
            if current_type == "number":
                if isinstance(current, float) and isinstance(value, int):
                    # Keep float targets float (JSON 30 → 30.0).
                    value = float(value)
                elif isinstance(current, int) and isinstance(value, float):
                    if not float(value).is_integer():
                        raise InvalidSettingUpdateError(
                            f"Setting {key} expects an integer value"
                        )
                    value = int(value)
            validated[key] = value
        return validated

    # ------------------------------------------------------------------
    # Persistence + live application
    # ------------------------------------------------------------------

    async def load_overrides(self) -> Dict[str, Any]:
        """Return the persisted overrides map (empty if never saved)."""
        data = await self._repo.load()
        return data if data is not None else {}

    async def set_overrides(self, validated: Dict[str, Any]) -> Dict[str, Any]:
        """Merge validated updates into the persisted map and save.

        Returns:
            The full persisted overrides map after the merge.
        """
        overrides = await self.load_overrides()
        overrides.update(validated)
        await self._repo.save(overrides)
        return overrides

    async def remove_override(self, key: str) -> bool:
        """Remove a persisted override and restore the pristine value.

        The live ``Settings`` attribute is set back to the env-derived
        value captured by :func:`capture_pristine` at startup (no-op
        restore if the snapshot was never taken).

        Returns:
            ``True`` if an override was removed; ``False`` if the key
            had no override (no-op — nothing persisted or restored).
        """
        overrides = await self.load_overrides()
        if key not in overrides:
            return False
        overrides.pop(key)
        await self._repo.save(overrides)
        if key in _PRISTINE_VALUES:
            setattr(self.settings, key, _PRISTINE_VALUES[key])
        self.mark_synced(overrides)
        logger.info("settings_override_removed", key=key)
        return True

    def apply_overrides(self, overrides: Dict[str, Any]) -> Dict[str, Any]:
        """Apply *overrides* onto the live ``Settings`` via ``setattr``.

        Invalid entries (unknown key / type drift since persistence) are
        skipped individually — a stale override must never prevent the
        remaining ones (or the application boot) from working.

        Returns:
            The subset actually applied.
        """
        applied: Dict[str, Any] = {}
        for key, value in overrides.items():
            try:
                validated = self.validate_updates({key: value})
            except InvalidSettingUpdateError:
                logger.warning("settings_override_skipped", key=key)
                continue
            setattr(self.settings, key, validated[key])
            applied[key] = validated[key]
        self._applied = dict(overrides)
        return applied

    def mark_synced(self, overrides: Dict[str, Any]) -> None:
        """Record *overrides* as the last-seen persisted state.

        Used after a live-apply that covered only part of the document
        (e.g. the freshly PUT keys): it tells ``refresh_if_changed``
        that this node has already seen the current persisted state, so
        the periodic tick will not re-apply it redundantly.
        """
        self._applied = dict(overrides)

    async def refresh_if_changed(self) -> bool:
        """Reload the persisted overrides and re-apply them if changed.

        Never raises on repository errors: the periodic refresher must
        not take the worker down over a transient read failure.

        Returns:
            ``True`` if the overrides were (re)applied.
        """
        try:
            data = await self._repo.load()
        except Exception:
            logger.warning("settings_override_refresh_read_failed")
            return False
        if data is None:
            return False
        if self._applied is not None and data == self._applied:
            return False
        applied = self.apply_overrides(data)
        logger.debug(
            "settings_override_applied",
            count=len(applied),
            source="refresh",
        )
        return True

    # ------------------------------------------------------------------
    # Introspection helpers (API layer)
    # ------------------------------------------------------------------

    def current_overrides(self) -> Optional[Dict[str, Any]]:
        """Return the last applied in-memory overrides, if any."""
        return self._applied
