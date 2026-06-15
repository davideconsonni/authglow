"""Unit tests for the File-backed security-event repository.

Covers ``FileSecurityEventRepository``. The service-level behaviour is
exercised implicitly by the integration tests in
``tests/integration/test_admin_api.py`` (which mock the service).
There is no dedicated ``tests/unit/test_security_event.py`` because
``SecurityEventService`` is a thin pass-through (record + list_for_user
+ return values), and no current caller consumes the return value of
``record_event``.

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via ``isinstance(repo, <Protocol>)``.

Regression focus: the pre-refactor ``SecurityEventService`` had two
backend-bypass bugs (``fsspec.filesystem("file")`` hard-coded +
``os.makedirs`` bypassing the fsspec abstraction). Both are fixed by
delegating to ``BaseFileRepository._ensure_parent`` which is the
single, backend-agnostic place that creates directories.
"""

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from authglow.core.datetime import utcnow
from authglow.repositories.file.security_event import (
    FileSecurityEventRepository,
)
from authglow.repositories.protocols import SecurityEventRepository

# ---------------------------------------------------------------------------
# FileSecurityEventRepository
# ---------------------------------------------------------------------------


class TestFileSecurityEventRepository:
    def _make_repo(self, test_settings) -> FileSecurityEventRepository:
        return FileSecurityEventRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "security_events"
        assert Path(repo._storage_path).name == "security_events"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, SecurityEventRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in ("record", "list_for_user"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    # ----- record -----

    async def test_record_creates_user_subdir(self, test_settings):
        """Regression: pre-refactor service used ``os.makedirs`` to
        create the per-user sub-directory, bypassing the fsspec
        abstraction. Now the repo delegates to
        ``_ensure_parent`` which is backend-agnostic."""
        repo = self._make_repo(test_settings)
        await repo.record(
            user_id="target-rt",
            event_type="login.suspicious",
        )
        user_dir = Path(repo._user_dir("target-rt"))
        assert user_dir.exists()
        assert user_dir.is_dir()

    async def test_record_writes_event_file(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.record(
            user_id="target-w",
            event_type="password.changed",
        )
        user_dir = Path(repo._user_dir("target-w"))
        files = list(user_dir.glob("*.json"))
        assert len(files) == 1
        raw = files[0].read_text()
        assert "target-w" in raw
        assert "password.changed" in raw

    async def test_record_generates_id(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.record(
            user_id="target-id",
            event_type="login.success",
        )
        page, total = await repo.list_for_user("target-id")
        assert total == 1
        event_id = page[0]["id"]
        assert isinstance(event_id, str)
        assert len(event_id) >= 32  # UUID4 with hyphens = 36 chars

    async def test_record_generates_timestamp(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.record(
            user_id="target-ts",
            event_type="login.success",
        )
        page, total = await repo.list_for_user("target-ts")
        assert total == 1
        ts = page[0]["timestamp"]
        from datetime import datetime as dt

        parsed = dt.fromisoformat(ts)
        assert isinstance(parsed, dt)

    async def test_record_preserves_optional_fields(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.record(
            user_id="target-opts",
            event_type="login.suspicious",
            email="target@example.com",
            description="Multiple failed attempts from new IP",
            ip_address="10.0.0.42",
            metadata={"attempts": 5, "ip_country": "XX"},
        )
        page, total = await repo.list_for_user("target-opts")
        assert total == 1
        record = page[0]
        assert record["event_type"] == "login.suspicious"
        assert record["email"] == "target@example.com"
        assert record["description"] == "Multiple failed attempts from new IP"
        assert record["ip_address"] == "10.0.0.42"
        assert record["metadata"] == {"attempts": 5, "ip_country": "XX"}

    async def test_record_uses_ensure_parent_not_direct_os_makedirs(self, test_settings):
        """Regression: pre-refactor service called
        ``os.makedirs(os.path.dirname(event_path), exist_ok=True)``
        directly. The repo delegates to ``_ensure_parent`` (called
        by ``_write_json``), so directory creation flows through
        the fsspec abstraction (which is the single, backend-agnostic
        place that creates directories)."""
        repo = self._make_repo(test_settings)
        with patch.object(repo, "_ensure_parent", wraps=repo._ensure_parent) as spy_ensure_parent:
            await repo.record(
                user_id="target-makedirs",
                event_type="login.success",
            )
        # The repo's _write_json path calls _ensure_parent exactly
        # once — for the per-user sub-directory.
        assert spy_ensure_parent.call_count == 1

    # ----- list_for_user -----

    async def test_list_for_user_returns_empty_for_unknown_user(self, test_settings):
        repo = self._make_repo(test_settings)
        page, total = await repo.list_for_user("nobody")
        assert page == []
        assert total == 0

    async def test_list_for_user_returns_records_newest_first(self, test_settings):
        repo = self._make_repo(test_settings)
        user_dir = Path(repo._user_dir("target-ord"))
        for i, ts in enumerate(
            [
                utcnow() - timedelta(days=3),
                utcnow() - timedelta(days=2),
                utcnow() - timedelta(days=1),
            ]
        ):
            user_id_key = f"target-ord-{i}"
            await repo.record(
                user_id="target-ord",
                event_type=user_id_key,
            )
            # Find the file that holds this iteration's record
            # (its filename is a UUID generated by the repo, so
            # we have to scan by content) and overwrite its
            # timestamp + id so the sort is deterministic.
            for f in user_dir.glob("*.json"):
                payload = json.loads(f.read_text())
                if payload.get("event_type") == user_id_key:
                    payload["id"] = f"ord-{i}"
                    payload["timestamp"] = ts.isoformat()
                    f.write_text(json.dumps(payload))
                    break
        page, total = await repo.list_for_user("target-ord")
        assert total == 3
        assert [r["id"] for r in page] == ["ord-2", "ord-1", "ord-0"]

    async def test_list_for_user_pagination(self, test_settings):
        repo = self._make_repo(test_settings)
        user_dir = Path(repo._user_dir("target-page"))
        for i in range(5):
            event_type_key = f"page-event-{i}"
            await repo.record(
                user_id="target-page",
                event_type=event_type_key,
            )
            for f in user_dir.glob("*.json"):
                payload = json.loads(f.read_text())
                if payload.get("event_type") == event_type_key:
                    payload["id"] = f"page-{i}"
                    payload["timestamp"] = (utcnow() + timedelta(seconds=i)).isoformat()
                    f.write_text(json.dumps(payload))
                    break
        page1, total1 = await repo.list_for_user("target-page", limit=2, offset=0)
        page2, total2 = await repo.list_for_user("target-page", limit=2, offset=2)
        assert total1 == 5
        assert total2 == 5
        assert len(page1) == 2
        assert len(page2) == 2
        assert {r["id"] for r in page1}.isdisjoint({r["id"] for r in page2})

    async def test_list_for_user_filters_by_user(self, test_settings):
        repo = self._make_repo(test_settings)
        for uid in ("target-a", "target-b"):
            await repo.record(
                user_id=uid,
                event_type="login.success",
            )
        page, total = await repo.list_for_user("target-a")
        assert total == 1
        assert page[0]["user_id"] == "target-a"

    async def test_list_for_user_skips_corrupt_json(self, test_settings):
        repo = self._make_repo(test_settings)
        user_dir = Path(repo._user_dir("target-corrupt"))
        user_dir.mkdir(parents=True, exist_ok=True)
        (user_dir / "noise.json").write_text("not valid json {")
        await repo.record(
            user_id="target-corrupt",
            event_type="login.success",
        )
        page, total = await repo.list_for_user("target-corrupt")
        assert total == 1
        assert page[0]["user_id"] == "target-corrupt"


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileSecurityEventRepositoryWithPatchedSettings:
    def test_constructs_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructor resolves
        ``get_settings()`` via ``BaseFileRepository``'s binding —
        and (unlike the pre-refactor service) honours
        ``Settings.storage_backend``.
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from authglow.core.config import Settings
        from authglow.core.crypto import encrypt_private_key

        storage_path = str(tmp_path / "data" / "users")
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path = str(keys_dir / "private_key.pem")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encrypted_priv = encrypt_private_key(
            priv_bytes, secret_key="test-secret-key-for-authglow-testing-32chars!"
        )
        with open(priv_path, "wb") as f:
            f.write(encrypted_priv)

        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32chars!",
            storage_path=storage_path,
            storage_backend="file",
            keys_dir=str(keys_dir),
            private_key_path=priv_path,
            public_key_path=str(keys_dir / "public_key.pem"),
        )

        with patch("authglow.repositories.file.base.get_settings", return_value=settings):
            repo = FileSecurityEventRepository()
            assert Path(repo._storage_path).exists()
