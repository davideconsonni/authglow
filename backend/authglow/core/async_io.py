"""Async wrappers for synchronous fsspec I/O operations.

All fsspec operations are synchronous and would block the asyncio event loop.
This module provides async versions that delegate to a thread pool via
``asyncio.to_thread()``, keeping the event loop responsive especially when
the storage backend is a cloud provider (S3, GCS, ADLS).

CAS (Compare-And-Swap) helpers are provided for optimistic-concurrency control:
``read_json_versioned`` reads a record together with its ``_version`` field,
and ``write_json_versioned`` writes only if the version has not changed since
the read. The check and the write run inside a single critical section
(one worker-thread operation guarded by a process-wide lock), so no concurrent
coroutine or thread can interleave between them. Across OS processes the
version re-check remains best-effort: a writer that observed a stale version
is rejected, but two processes can still pass the check in the same instant
unless the storage backend offers a native atomic compare-and-swap.
"""

import asyncio
import json
import threading
from typing import Any, List, Tuple

from authglow.core.concurrency import ConcurrentWriteError

# Process-wide lock serializing CAS check+write critical sections. A
# ``threading.Lock`` (not an ``asyncio.Lock``) deliberately: the guarded
# code runs on a ``asyncio.to_thread`` worker, and a threading lock carries
# no event-loop affinity, so tests that drive each case on a fresh event
# loop keep working.
_cas_write_lock = threading.Lock()


class AsyncFileSystem:
    """Async wrapper around an fsspec filesystem instance.

    Typical usage::

        from authglow.core.async_io import AsyncFileSystem

        class MyService:
            def __init__(self):
                self.fs = fsspec.filesystem(...)
                self._afs = AsyncFileSystem(self.fs)

            async def get_item(self, path: str):
                data = await self._afs.read_json(path)
                return Item(**data)
    """

    def __init__(self, fs):
        self._fs = fs

    async def read_json(self, path: str) -> Any:
        def _op():
            with self._fs.open(path, "r") as f:
                return json.load(f)

        return await asyncio.to_thread(_op)

    async def write_json(self, path: str, data: Any, indent: int = 2, default=None) -> None:
        _default = default if default is not None else str

        def _op():
            with self._fs.open(path, "w") as f:
                json.dump(data, f, indent=indent, default=_default)

        await asyncio.to_thread(_op)

    async def read_json_versioned(self, path: str) -> Tuple[Any, int]:
        """Read a JSON record and return ``(data, version)``.

        If the record does not contain a ``_version`` key, version defaults to 0.
        """
        data = await self.read_json(path)
        version = data.pop("_version", 0)
        return data, version

    async def write_json_versioned(
        self,
        path: str,
        data: Any,
        expected_version: int,
        indent: int = 2,
        default=None,
    ) -> None:
        """Write a JSON record with optimistic-concurrency check.

        The current ``_version`` is read, compared to *expected_version*,
        and the record is written inside one critical section — a single
        worker-thread operation under the process-wide ``_cas_write_lock``
        — so no concurrent coroutine or thread can observe the record
        between the check and the write. On a version mismatch,
        ``ConcurrentWriteError`` is raised so the caller can retry the
        read-mutate-write loop.

        On success the stored record's ``_version`` is incremented by 1.
        """
        _default = default if default is not None else str

        def _op() -> None:
            with _cas_write_lock:
                try:
                    with self._fs.open(path, "r") as f:
                        current = json.load(f)
                except FileNotFoundError:
                    current = {}

                current_version = current.get("_version", 0)
                if current_version != expected_version:
                    raise ConcurrentWriteError(
                        f"Version mismatch for {path}: "
                        f"expected {expected_version}, found {current_version}"
                    )

                data_with_version = {**data, "_version": expected_version + 1}
                with self._fs.open(path, "w") as f:
                    json.dump(data_with_version, f, indent=indent, default=_default)

        await asyncio.to_thread(_op)

    async def read_text(self, path: str) -> str:
        def _op():
            with self._fs.open(path, "r") as f:
                return f.read()

        return await asyncio.to_thread(_op)

    async def write_text(self, path: str, content: str) -> None:
        def _op():
            with self._fs.open(path, "w") as f:
                f.write(content)

        await asyncio.to_thread(_op)

    async def glob(self, pattern: str) -> List[str]:
        return await asyncio.to_thread(self._fs.glob, pattern)

    async def ls(self, path: str, detail: bool = False) -> Any:
        return await asyncio.to_thread(self._fs.ls, path, detail)

    async def exists(self, path: str) -> bool:
        return await asyncio.to_thread(self._fs.exists, path)

    async def rm(self, path: str, recursive: bool = False) -> None:
        await asyncio.to_thread(self._fs.rm, path, recursive=recursive)

    async def makedirs(self, path: str, exist_ok: bool = True) -> None:
        await asyncio.to_thread(self._fs.makedirs, path, exist_ok=exist_ok)

    async def info(self, path: str) -> dict:
        return await asyncio.to_thread(self._fs.info, path)

    async def mkdirs(self, path: str, exist_ok: bool = True) -> None:
        await asyncio.to_thread(self._fs.mkdirs, path, exist_ok=exist_ok)

    async def cat(self, path: str) -> bytes:
        return await asyncio.to_thread(self._fs.cat, path)

    async def read_bytes(self, path: str) -> bytes:
        def _op():
            with self._fs.open(path, "rb") as f:
                return f.read()

        return await asyncio.to_thread(_op)

    async def write_bytes(self, path: str, data: bytes) -> None:
        def _op():
            with self._fs.open(path, "wb") as f:
                f.write(data)

        await asyncio.to_thread(_op)
