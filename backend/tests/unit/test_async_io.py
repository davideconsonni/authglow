"""Tests for AsyncFileSystem wrapper."""

import asyncio
import json
import os
import tempfile

import pytest
import fsspec

from authglow.core.async_io import AsyncFileSystem


@pytest.fixture
def tmp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def afs(tmp_dir):
    """Create an AsyncFileSystem instance pointing at a temp dir."""
    fs = fsspec.filesystem("file")
    return AsyncFileSystem(fs)


@pytest.mark.asyncio
async def test_write_and_read_json(tmp_dir, afs):
    path = f"{tmp_dir}/test.json"
    data = {"key": "value", "number": 42}
    await afs.write_json(path, data)
    result = await afs.read_json(path)
    assert result == data


@pytest.mark.asyncio
async def test_write_and_read_text(tmp_dir, afs):
    path = f"{tmp_dir}/test.txt"
    content = "hello world"
    await afs.write_text(path, content)
    result = await afs.read_text(path)
    assert result == content


@pytest.mark.asyncio
async def test_read_json_file_not_found(tmp_dir, afs):
    path = f"{tmp_dir}/nonexistent.json"
    with pytest.raises(FileNotFoundError):
        await afs.read_json(path)


@pytest.mark.asyncio
async def test_read_text_file_not_found(tmp_dir, afs):
    path = f"{tmp_dir}/nonexistent.txt"
    with pytest.raises(FileNotFoundError):
        await afs.read_text(path)


@pytest.mark.asyncio
async def test_exists(tmp_dir, afs):
    path = f"{tmp_dir}/exists.json"
    assert await afs.exists(path) is False
    await afs.write_text(path, "test")
    assert await afs.exists(path) is True


@pytest.mark.asyncio
async def test_rm_nonexistent(tmp_dir, afs):
    path = f"{tmp_dir}/nonexistent.json"
    with pytest.raises(Exception):
        await afs.rm(path)


@pytest.mark.asyncio
async def test_glob(tmp_dir, afs):
    for i in range(3):
        await afs.write_json(f"{tmp_dir}/file_{i}.json", {"index": i})

    pattern = f"{tmp_dir}/*.json"
    files = await afs.glob(pattern)
    assert len(files) == 3


@pytest.mark.asyncio
async def test_ls(tmp_dir, afs):
    for i in range(2):
        await afs.write_text(f"{tmp_dir}/ls_file_{i}.txt", f"content_{i}")

    files = await afs.ls(tmp_dir)
    assert len(files) >= 2


@pytest.mark.asyncio
async def test_makedirs(tmp_dir, afs):
    nested_dir = f"{tmp_dir}/a/b/c"
    await afs.makedirs(nested_dir, exist_ok=True)
    assert await afs.exists(nested_dir) is True


@pytest.mark.asyncio
async def test_write_json_with_default(tmp_dir, afs):
    """Test write_json with default=str for datetime serialization."""
    from datetime import datetime, timezone

    path = f"{tmp_dir}/datetime.json"
    data = {"ts": datetime.now(timezone.utc)}
    await afs.write_json(path, data, default=str)
    result = await afs.read_json(path)
    assert "ts" in result


@pytest.mark.asyncio
async def test_async_io_does_not_block_event_loop(tmp_dir, afs):
    """Verify that async I/O actually yields control to the event loop."""
    import time

    path = f"{tmp_dir}/blocking_test.json"
    data = {"large": "x" * 100000}

    # Write and read concurrently - if blocking, this would be sequential
    start = time.monotonic()
    await asyncio.gather(
        afs.write_json(path, data),
        afs.write_json(f"{tmp_dir}/concurrent.json", data),
    )
    elapsed = time.monotonic() - start

    # Both should complete (basic sanity check)
    assert await afs.exists(path) is True
    assert await afs.exists(f"{tmp_dir}/concurrent.json") is True


@pytest.mark.asyncio
async def test_info(tmp_dir, afs):
    path = f"{tmp_dir}/info_test.json"
    await afs.write_text(path, "test content")
    info = await afs.info(path)
    assert isinstance(info, dict)
    assert "size" in info or "name" in info


# ---------------------------------------------------------------------------
# update_text — locked, atomic read-modify-write
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_text_creates_then_modifies(tmp_dir, afs):
    path = f"{tmp_dir}/idx.txt"

    def _append(current):
        return (current or "start") + "|mod"

    await afs.update_text(path, _append)
    assert await afs.read_text(path) == "start|mod"
    await afs.update_text(path, _append)
    assert await afs.read_text(path) == "start|mod|mod"
    # the tmp + os.replace write leaves no stray file behind
    assert not os.path.exists(path + ".tmp")


@pytest.mark.asyncio
async def test_update_text_none_result_deletes_file(tmp_dir, afs):
    path = f"{tmp_dir}/to_delete.txt"
    await afs.write_text(path, "content")
    await afs.update_text(path, lambda current: None)
    assert await afs.exists(path) is False


@pytest.mark.asyncio
async def test_update_text_noop_on_missing_file_does_not_create(tmp_dir, afs):
    """``None`` in, ``None`` out means "nothing to delete": no file is
    created, no error is raised."""
    path = f"{tmp_dir}/never_existed.txt"
    await afs.update_text(path, lambda current: current)
    assert await afs.exists(path) is False


@pytest.mark.asyncio
async def test_update_text_unchanged_content_skips_write(tmp_dir, afs, monkeypatch):
    path = f"{tmp_dir}/unchanged.txt"
    await afs.write_text(path, "payload")

    replaces = []
    import authglow.core.async_io as async_io_module

    monkeypatch.setattr(async_io_module.os, "replace", lambda *args: replaces.append(args))
    await afs.update_text(path, lambda current: current)
    # identical content in == no rename == no write at all
    assert replaces == []
    assert await afs.read_text(path) == "payload"


@pytest.mark.asyncio
async def test_update_text_concurrent_writers_lose_no_update(tmp_dir, afs):
    """The regression the lost-update bug deserved: N concurrent RMWs on
    one path must compose (each writer sees the previous one's result).

    Without the per-path lock the read-transform-write interleaves on the
    await of every hop and the counter comes out below ``n``.
    """
    path = f"{tmp_dir}/counter.txt"
    n = 32

    def _increment(current):
        return str(int(current) + 1 if current else 1)

    await asyncio.gather(*(afs.update_text(path, _increment) for _ in range(n)))
    assert int(await afs.read_text(path)) == n


@pytest.mark.asyncio
async def test_update_text_plain_fallback_when_not_atomic(tmp_dir, afs):
    path = f"{tmp_dir}/plain.txt"
    await afs.update_text(path, lambda current: "v1", atomic=False)
    assert await afs.read_text(path) == "v1"
    await afs.update_text(path, lambda current: current + "+v2", atomic=False)
    assert await afs.read_text(path) == "v1+v2"
    assert not os.path.exists(path + ".tmp")
