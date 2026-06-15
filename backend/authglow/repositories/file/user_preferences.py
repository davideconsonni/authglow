"""File-system-backed repository for per-user UI / notification preferences.

On-disk layout (relative to ``settings.storage_path``):

* ``<storage>/user_preferences/<user_id>.json`` — one document
  per user. The repository uses the ``UserPreferences``
  Pydantic model from ``authglow.models.user_profile`` for
  serialisation.

The pre-refactor ``UserProfileService`` owned the file I/O
inline in ``services/user_profile.py`` (the ``_afs.read_json``
/ ``_afs.write_json`` calls + the path layout in
``get_user_preferences`` / ``update_user_preferences``). The
``delete_account`` path also did an inline
``self._afs.rm(prefs_path)`` to clean up the preferences file
when the user was deleted.

This repository implements :class:`UserPreferencesRepository`
with ``get`` / ``save`` / ``delete`` semantics. ``get`` returns
``None`` for missing users (the service layer maps that to
``UserPreferences(user_id=user_id)`` defaults).

The underlying fsspec filesystem and ``AsyncFileSystem`` wrapper
are managed by :class:`BaseFileRepository`. Cross-process
safety is delegated to the ``named_lock("preferences:<id>")``
held by ``UserProfileService``.
"""

from typing import Optional

from authglow.models.user_profile import UserPreferences
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import UserPreferencesRepository


class FileUserPreferencesRepository(BaseFileRepository, UserPreferencesRepository):
    """File-backed implementation of :class:`UserPreferencesRepository`.

    Stores each user's preferences as a JSON object at
    ``<storage>/user_preferences/<user_id>.json``. The repository
    handles the Pydantic model round-trip transparently — the
    service layer never sees a raw dict.
    """

    _subdir = "user_preferences"

    # ------------------------------------------------------------------
    # Path helper
    # ------------------------------------------------------------------

    def _prefs_path(self, user_id: str) -> str:
        """Return the on-disk path for a user's preferences file."""
        return self._path(f"{user_id}.json")

    # ------------------------------------------------------------------
    # Protocol: get
    # ------------------------------------------------------------------

    async def get(self, user_id: str) -> Optional[UserPreferences]:
        """Return the preferences for *user_id*, or ``None`` if
        no preferences file exists.

        Returns ``None`` (not a default ``UserPreferences``) so
        the service layer can decide how to handle the
        "no preferences yet" case — typically by returning
        ``UserPreferences(user_id=user_id)`` with all defaults.
        """
        data = await self._read_json(self._prefs_path(user_id))
        if not isinstance(data, dict):
            return None
        try:
            return UserPreferences(**data)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Protocol: save
    # ------------------------------------------------------------------

    async def save(self, preferences: UserPreferences) -> None:
        """Persist (upsert) the preferences for a user.

        The caller is responsible for setting ``updated_at``
        (or any other fields) on the model before calling
        ``save`` — the repository only handles serialisation
        and I/O.
        """
        await self._write_json(
            self._prefs_path(preferences.user_id),
            preferences.model_dump(),
        )

    # ------------------------------------------------------------------
    # Protocol: delete
    # ------------------------------------------------------------------

    async def delete(self, user_id: str) -> None:
        """Remove the preferences for *user_id*. No-op if absent."""
        await self._delete(self._prefs_path(user_id))
