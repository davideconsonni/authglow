"""Base class for file-system-backed repositories.

Every ``File<Entity>Repository`` inherits from ``BaseFileRepository``
and provides the entity-specific serialisation logic. The base class
owns:

* the fsspec filesystem selection (``file``, ``s3``, ``gcs``, ``abfs``),
  driven by ``Settings.storage_backend``;
* the ``AsyncFileSystem`` wrapper for non-blocking I/O;
* the in-process ``named_lock`` (singleton) for cross-coroutine
  serialisation within the same process;
* path helpers (``_path``) and the standard JSON read / write /
  versioned-read / versioned-write / glob / exists / delete primitives.

Subclasses add:

* a subdirectory (e.g. ``"refresh_tokens"``);
* entity-specific serialisation (Pydantic model round-trip, PII
  encryption, etc.);
* the public methods declared on the relevant ``Protocol`` in
  ``authglow.repositories.protocols``.

The class deliberately does **not** add entity-specific semantics:
no Pydantic model, no field-level encryption, no per-key path
construction. Those live in the concrete subclass.

Cross-process optimistic concurrency (``_version`` field) is exposed
via ``_read_json_versioned`` / ``_write_json_versioned`` and is
expected to be used by subclasses that need CAS protection
(refresh-token rotation, authorization-code redemption, etc.).
"""

from typing import Any, List, Optional, Tuple

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import named_lock
from authglow.core.config import Settings, get_settings


class BaseFileRepository:
    """Common scaffolding for file-backed repositories.

    Subclasses MUST set ``_subdir`` to the on-disk subdirectory
    (relative to ``settings.storage_path``) that this repository
    owns, and MAY set ``_extra_dirs`` to additional subdirectories
    to pre-create on first construction.

    Example::

        class FileRefreshTokenRepository(BaseFileRepository, RefreshTokenRepository):
            _subdir = "refresh_tokens"

            def __init__(self) -> None:
                super().__init__()
                # ... entity-specific init ...

            async def create(self, token: RefreshToken) -> None:
                path = self._path(f"{token.token_lookup}.json")
                await self._write_json(path, token.model_dump(mode="json"))
    """

    _subdir: str = ""
    _extra_dirs: tuple[str, ...] = ()

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        subdir: Optional[str] = None,
        extra_dirs: Optional[tuple[str, ...]] = None,
    ) -> None:
        """Initialise fsspec, AsyncFileSystem, locks, and paths.

        Args:
            settings: Optional ``Settings`` instance. Defaults to
                ``get_settings()`` (the process-cached singleton). Tests
                typically pass a custom ``Settings`` via this argument
                rather than patching ``get_settings``.
            subdir: Override the per-class ``_subdir``. Useful for
                repositories that share a base class but need a
                different on-disk location per concrete subclass.
            extra_dirs: Override ``_extra_dirs``. Additional
                subdirectories (relative to the subdir) to create
                on first construction.
        """
        self._settings: Settings = settings or get_settings()

        if subdir is not None:
            self._subdir = subdir
        if extra_dirs is not None:
            self._extra_dirs = extra_dirs

        if not self._subdir:
            raise ValueError(
                f"{type(self).__name__} must set _subdir or pass subdir=... "
                "to BaseFileRepository.__init__"
            )

        self._storage_root: str = self._settings.storage_path.rstrip("/")
        self._storage_path: str = f"{self._storage_root}/{self._subdir}"

        self._filesystem, self._afs = self._init_filesystem()
        self._lock = named_lock()

    # ------------------------------------------------------------------
    # Filesystem initialisation
    # ------------------------------------------------------------------

    def _init_filesystem(self) -> Tuple[Any, AsyncFileSystem]:
        """Build the fsspec filesystem and the async wrapper.

        Honours ``settings.storage_backend``:

        * ``"file"`` (default) → local filesystem, root directory
          pre-created with ``os.makedirs(..., exist_ok=True)``.
        * ``"s3"`` / ``"gcs"`` / ``"abfs"`` → cloud filesystem
          with credentials from ``settings.get_storage_options()``.
          No local mkdir; the cloud provider creates the bucket /
          container on first write.
        """
        import os

        if self._settings.storage_backend == "file":
            os.makedirs(self._storage_path, exist_ok=True)
            for extra in self._extra_dirs:
                os.makedirs(f"{self._storage_path}/{extra}", exist_ok=True)
            return fsspec.filesystem("file"), AsyncFileSystem(fsspec.filesystem("file"))

        fs = fsspec.filesystem(
            self._settings.storage_backend, **self._settings.get_storage_options()
        )
        return fs, AsyncFileSystem(fs)

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _path(self, filename: str) -> str:
        """Build the full path for *filename* under this repository.

        ``filename`` may include subdirectories (e.g. ``"<user_id>/<x>.json"``);
        the caller is responsible for ensuring the parent directory
        exists (use ``await self._ensure_parent(path)`` if needed).
        """
        filename = filename.lstrip("/")
        return f"{self._storage_path}/{filename}"

    async def _ensure_parent(self, path: str) -> None:
        """Make sure the parent directory of *path* exists.

        Cloud backends (``s3``, ``gcs``, ``abfs``) do not require
        this; the call is a no-op there. Local filesystem always
        gets an ``os.makedirs(parent, exist_ok=True)``.
        """
        import os

        if self._settings.storage_backend == "file":
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)

    # ------------------------------------------------------------------
    # JSON I/O primitives
    # ------------------------------------------------------------------

    async def _read_json(self, path: str) -> Optional[Any]:
        """Read a JSON file. Returns ``None`` on missing / corrupt file.

        Subclasses should translate ``None`` into domain semantics
        (``get_by_id`` → ``None`` to caller, ``_write_json`` → ignore
        the read). We swallow ``FileNotFoundError`` and
        ``json.JSONDecodeError`` because the on-disk state is
        inherently racy in a file-based system.
        """
        try:
            return await self._afs.read_json(path)
        except FileNotFoundError:
            return None
        except (ValueError, TypeError):
            return None

    async def _write_json(
        self,
        path: str,
        data: Any,
        *,
        indent: int = 2,
        default: Any = None,
    ) -> None:
        """Atomically-ish write JSON. The caller is responsible for
        parent directory creation (``_ensure_parent``) when needed.

        On the local filesystem this is a single ``fsspec.open(..., "w")``
        call — not crash-safe across power loss, but consistent with
        the pre-refactor behaviour. For crash-safe writes use
        ``_write_json_atomic``.
        """
        await self._ensure_parent(path)
        await self._afs.write_json(path, data, indent=indent, default=default)

    async def _write_json_atomic(
        self,
        path: str,
        data: Any,
        *,
        indent: int = 2,
        default: Any = None,
    ) -> None:
        """Crash-safe write via the ``tmp + rename`` pattern.

        Used by the token-blacklist and the (future) keyring
        repositories, both of which need to survive a process crash
        between write and rename. On the local filesystem the rename
        is atomic at the POSIX level (``os.replace``); on cloud
        backends (``s3`` / ``gcs`` / ``abfs``) the rename is **not**
        available, so the call falls back to a best-effort plain
        write and logs a warning. Callers that require strict
        atomicity on cloud backends must layer their own versioning
        (e.g. the ``_version`` field used by ``_write_json_versioned``).
        """
        import logging

        await self._ensure_parent(path)

        if self._settings.storage_backend == "file":
            import os

            tmp_path = path + ".tmp"
            await self._afs.write_json(tmp_path, data, indent=indent, default=default)
            os.replace(tmp_path, path)
            return

        logging.getLogger("authglow.repositories").debug(
            "atomic_write_fallback",
            extra={"path": path, "backend": self._settings.storage_backend},
        )
        await self._write_json(path, data, indent=indent, default=default)

    async def _read_json_versioned(self, path: str) -> Tuple[Optional[Any], int]:
        """Read a JSON file and return ``(data, version)``.

        Returns ``(None, 0)`` if the file is missing.
        """
        try:
            data, version = await self._afs.read_json_versioned(path)
            return data, version
        except FileNotFoundError:
            return None, 0

    async def _write_json_versioned(
        self,
        path: str,
        data: Any,
        expected_version: int,
        *,
        indent: int = 2,
        default: Any = None,
    ) -> None:
        """Write JSON with optimistic-concurrency check.

        Raises ``ConcurrentWriteError`` (from
        ``authglow.core.concurrency``) on a version mismatch. The
        service layer is responsible for retrying the read-mutate-write
        loop on this error.
        """
        await self._ensure_parent(path)
        await self._afs.write_json_versioned(
            path, data, expected_version, indent=indent, default=default
        )

    async def _write_text(self, path: str, content: str) -> None:
        """Write raw text. Used by repositories that need a custom
        serialisation (e.g. ``PasswordResetRepository`` writes the
        same payload as JSON text to two mirror files for VAPT-022)."""
        await self._ensure_parent(path)
        await self._afs.write_text(path, content)

    async def _read_text(self, path: str) -> Optional[str]:
        """Read raw text. Returns ``None`` on missing file."""
        try:
            return await self._afs.read_text(path)
        except FileNotFoundError:
            return None

    # ------------------------------------------------------------------
    # Filesystem helpers
    # ------------------------------------------------------------------

    async def _exists(self, path: str) -> bool:
        """Return ``True`` if *path* exists."""
        return await self._afs.exists(path)

    async def _delete(self, path: str) -> bool:
        """Delete *path*. Returns ``True`` on success, ``False`` if missing."""
        try:
            await self._afs.rm(path)
            return True
        except FileNotFoundError:
            return False

    async def _glob(self, pattern: str) -> List[str]:
        """Glob *pattern* (relative to the fsspec root)."""
        return await self._afs.glob(pattern)

    async def _ls(self, path: Optional[str] = None) -> Any:
        """List *path* (defaults to this repository's storage path).

        The return type mirrors ``AsyncFileSystem.ls`` (``Any``) because
        the underlying call supports both flat and detail modes.
        Subclasses that need a ``List[str]`` should call
        ``await self._afs.ls(target, detail=False)`` directly and cast.
        """
        target = path if path is not None else self._storage_path
        return await self._afs.ls(target)

    async def _makedirs(self, path: str) -> None:
        """Create a directory. No-op on cloud backends (idempotent)."""
        await self._afs.makedirs(path, exist_ok=True)
