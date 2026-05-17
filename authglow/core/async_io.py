"""Async wrappers for synchronous fsspec I/O operations.

All fsspec operations are synchronous and would block the asyncio event loop.
This module provides async versions that delegate to a thread pool via
``asyncio.to_thread()``, keeping the event loop responsive especially when
the storage backend is a cloud provider (S3, GCS, ADLS).
"""

import asyncio
import json
from typing import Any, List, Optional


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

    async def write_json(
        self, path: str, data: Any, indent: int = 2, default=None
    ) -> None:
        _default = default if default is not None else str

        def _op():
            with self._fs.open(path, "w") as f:
                json.dump(data, f, indent=indent, default=_default)

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
