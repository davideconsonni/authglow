import pytest
from authglow.models.user import User
from authglow.services.password import hash_password


class TestUserCRUD:
    def test_create_user(self, storage):
        import asyncio

        user = User(
            email="newuser@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            scopes=["read"],
        )
        created = asyncio.get_event_loop().run_until_complete(storage.create_user(user))
        assert created is not None
        assert created.email == "newuser@example.com"
        assert created.id is not None

    def test_get_user(self, storage):
        import asyncio

        user = User(
            email="getuser@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            scopes=["read"],
        )
        created = asyncio.get_event_loop().run_until_complete(storage.create_user(user))
        fetched = asyncio.get_event_loop().run_until_complete(
            storage.get_user(created.id)
        )
        assert fetched is not None
        assert fetched.email == "getuser@example.com"

    def test_get_user_by_email(self, storage):
        import asyncio

        user = User(
            email="byemail@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            scopes=["read"],
        )
        asyncio.get_event_loop().run_until_complete(storage.create_user(user))
        fetched = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("byemail@example.com")
        )
        assert fetched is not None
        assert fetched.email == "byemail@example.com"

    def test_get_user_by_email_case_insensitive(self, storage):
        import asyncio

        user = User(
            email="CaseTest@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            scopes=["read"],
        )
        asyncio.get_event_loop().run_until_complete(storage.create_user(user))
        fetched = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("casetest@example.com")
        )
        assert fetched is not None

    def test_create_user_duplicate_email(self, storage):
        import asyncio

        user1 = User(
            email="duplicate@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            scopes=["read"],
        )
        asyncio.get_event_loop().run_until_complete(storage.create_user(user1))
        user2 = User(
            email="duplicate@example.com",
            hashed_password=hash_password("OtherP@ss1!"),
            scopes=["read"],
        )
        with pytest.raises(ValueError, match="already exists"):
            asyncio.get_event_loop().run_until_complete(storage.create_user(user2))

    def test_update_user(self, storage):
        import asyncio

        user = User(
            email="update@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            first_name="Original",
            scopes=["read"],
        )
        created = asyncio.get_event_loop().run_until_complete(storage.create_user(user))
        created.first_name = "Updated"
        updated = asyncio.get_event_loop().run_until_complete(
            storage.update_user(created)
        )
        assert updated.first_name == "Updated"

    def test_delete_user(self, storage):
        import asyncio

        user = User(
            email="delete@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            scopes=["read"],
        )
        created = asyncio.get_event_loop().run_until_complete(storage.create_user(user))
        result = asyncio.get_event_loop().run_until_complete(
            storage.delete_user(created.id)
        )
        assert result is True
        fetched = asyncio.get_event_loop().run_until_complete(
            storage.get_user(created.id)
        )
        assert fetched is None

    def test_get_nonexistent_user(self, storage):
        import asyncio

        fetched = asyncio.get_event_loop().run_until_complete(
            storage.get_user("nonexistent-id")
        )
        assert fetched is None

    def test_list_users_pagination(self, storage):
        import asyncio

        for i in range(5):
            user = User(
                email=f"paguser{i}@example.com",
                hashed_password=hash_password("TestP@ss123!"),
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))
        page1, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(limit=3, offset=0)
        )
        assert len(page1) <= 3
        assert total == 5
        page2, total2 = asyncio.get_event_loop().run_until_complete(
            storage.list_users(limit=3, offset=3)
        )
        assert len(page2) <= 3
        assert total2 == 5


class TestAccountLockout:
    def _create_user(self, storage):
        import asyncio

        user = User(
            email="lockout@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            scopes=["read"],
        )
        return asyncio.get_event_loop().run_until_complete(storage.create_user(user))

    def test_record_failed_login(self, storage):
        import asyncio

        user = self._create_user(storage)
        result = asyncio.get_event_loop().run_until_complete(
            storage.record_failed_login(user.id)
        )
        assert result is None
        fetched = asyncio.get_event_loop().run_until_complete(storage.get_user(user.id))
        assert fetched.failed_login_attempts == 1

    def test_account_lockout_after_max_attempts(self, storage):
        import asyncio

        user = self._create_user(storage)
        for i in range(5):
            result = asyncio.get_event_loop().run_until_complete(
                storage.record_failed_login(user.id, max_attempts=5)
            )
        fetched = asyncio.get_event_loop().run_until_complete(storage.get_user(user.id))
        assert fetched.failed_login_attempts >= 5
        assert fetched.locked_until is not None

    def test_account_not_locked_below_threshold(self, storage):
        import asyncio

        user = self._create_user(storage)
        for i in range(4):
            asyncio.get_event_loop().run_until_complete(
                storage.record_failed_login(user.id, max_attempts=5)
            )
        is_locked = asyncio.get_event_loop().run_until_complete(
            storage.is_account_locked(user.id)
        )
        assert not is_locked

    def test_is_account_locked_expired(self, storage):
        import asyncio

        user = self._create_user(storage)
        for i in range(5):
            asyncio.get_event_loop().run_until_complete(
                storage.record_failed_login(
                    user.id, max_attempts=5, lockout_duration_minutes=0
                )
            )
        is_locked = asyncio.get_event_loop().run_until_complete(
            storage.is_account_locked(user.id)
        )
        assert not is_locked

    def test_reset_failed_login_attempts(self, storage):
        import asyncio

        user = self._create_user(storage)
        for i in range(3):
            asyncio.get_event_loop().run_until_complete(
                storage.record_failed_login(user.id)
            )
        asyncio.get_event_loop().run_until_complete(
            storage.reset_failed_login_attempts(user.id)
        )
        fetched = asyncio.get_event_loop().run_until_complete(storage.get_user(user.id))
        assert fetched.failed_login_attempts == 0
        assert fetched.locked_until is None


class TestTimingLeakProtection:
    def _create_user(self, storage, email):
        import asyncio
        from authglow.models.user import User
        from authglow.services.password import hash_password

        user = User(
            email=email,
            hashed_password=hash_password("TestP@ss123!"),
            scopes=["read"],
        )
        return asyncio.get_event_loop().run_until_complete(storage.create_user(user))

    def test_email_found_with_protection_enabled(self, storage):
        import asyncio

        self._create_user(storage, "timing-test@example.com")
        result = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("timing-test@example.com")
        )
        assert result is not None
        assert result.email == "timing-test@example.com"

    def test_email_not_found_with_protection_enabled(self, storage):
        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("nonexistent-timing@example.com")
        )
        assert result is None

    def test_email_not_found_does_not_crash(self, storage):
        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("no-such-user@example.com")
        )
        assert result is None

    def test_email_found_protection_disabled(self, storage):
        import asyncio

        self._create_user(storage, "timing-off@example.com")
        storage.settings.timing_leak_protection = False
        result = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("timing-off@example.com")
        )
        assert result is not None
        assert result.email == "timing-off@example.com"

    def test_email_not_found_protection_disabled(self, storage):
        import asyncio

        storage.settings.timing_leak_protection = False
        result = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("nonexistent-off@example.com")
        )
        assert result is None

    def test_protection_defaults_to_enabled(self, storage):
        assert storage.settings.timing_leak_protection is True

    def test_no_side_effect_on_consecutive_calls(self, storage):
        import asyncio

        self._create_user(storage, "repeat@example.com")
        for _ in range(5):
            found = asyncio.get_event_loop().run_until_complete(
                storage.get_user_by_email("repeat@example.com")
            )
            assert found is not None
            assert found.email == "repeat@example.com"
        for _ in range(5):
            not_found = asyncio.get_event_loop().run_until_complete(
                storage.get_user_by_email("never-here@example.com")
            )
            assert not_found is None
