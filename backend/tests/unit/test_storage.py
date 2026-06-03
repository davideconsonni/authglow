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
        fetched = asyncio.get_event_loop().run_until_complete(storage.get_user(created.id))
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
        updated = asyncio.get_event_loop().run_until_complete(storage.update_user(created))
        assert updated.first_name == "Updated"

    def test_delete_user(self, storage):
        import asyncio

        user = User(
            email="delete@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            scopes=["read"],
        )
        created = asyncio.get_event_loop().run_until_complete(storage.create_user(user))
        result = asyncio.get_event_loop().run_until_complete(storage.delete_user(created.id))
        assert result is True
        fetched = asyncio.get_event_loop().run_until_complete(storage.get_user(created.id))
        assert fetched is None

    def test_get_nonexistent_user(self, storage):
        import asyncio

        fetched = asyncio.get_event_loop().run_until_complete(storage.get_user("nonexistent-id"))
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
        result = asyncio.get_event_loop().run_until_complete(storage.record_failed_login(user.id))
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
        is_locked = asyncio.get_event_loop().run_until_complete(storage.is_account_locked(user.id))
        assert not is_locked

    def test_is_account_locked_expired(self, storage):
        import asyncio

        user = self._create_user(storage)
        for i in range(5):
            asyncio.get_event_loop().run_until_complete(
                storage.record_failed_login(user.id, max_attempts=5, lockout_duration_minutes=0)
            )
        is_locked = asyncio.get_event_loop().run_until_complete(storage.is_account_locked(user.id))
        assert not is_locked

    def test_reset_failed_login_attempts(self, storage):
        import asyncio

        user = self._create_user(storage)
        for i in range(3):
            asyncio.get_event_loop().run_until_complete(storage.record_failed_login(user.id))
        asyncio.get_event_loop().run_until_complete(storage.reset_failed_login_attempts(user.id))
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


class TestUserCache:
    """Tests for in-memory TTL cache on get_user_by_email (P6 performance)."""

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

    def test_cache_hit_skips_email_index(self, storage):
        import asyncio

        self._create_user(storage, "cache-hit@example.com")
        fetched_1 = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("cache-hit@example.com")
        )
        assert fetched_1 is not None

        original_load = storage._load_email_index

        def _load_must_not_be_called(*args, **kwargs):
            raise AssertionError("_load_email_index() called — cache was NOT hit!")

        storage._load_email_index = _load_must_not_be_called
        try:
            fetched_2 = asyncio.get_event_loop().run_until_complete(
                storage.get_user_by_email("cache-hit@example.com")
            )
            assert fetched_2 is not None
            assert fetched_2.email == "cache-hit@example.com"
        finally:
            storage._load_email_index = original_load

    def test_cache_invalidation_on_update(self, storage):
        import asyncio

        user = self._create_user(storage, "cache-upd@example.com")
        fetched_1 = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("cache-upd@example.com")
        )
        assert fetched_1 is not None
        assert fetched_1.first_name is None

        user.first_name = "Alice"
        asyncio.get_event_loop().run_until_complete(storage.update_user(user))

        fetched_2 = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("cache-upd@example.com")
        )
        assert fetched_2 is not None
        assert fetched_2.first_name == "Alice"

    def test_cache_invalidation_on_delete(self, storage):
        import asyncio

        user = self._create_user(storage, "cache-del@example.com")
        fetched_1 = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("cache-del@example.com")
        )
        assert fetched_1 is not None

        asyncio.get_event_loop().run_until_complete(storage.delete_user(user.id))

        fetched_2 = asyncio.get_event_loop().run_until_complete(
            storage.get_user_by_email("cache-del@example.com")
        )
        assert fetched_2 is None


class TestListUsersFilters:
    def _create_user(
        self,
        storage,
        email,
        is_active=True,
        mfa_enabled=False,
        scopes=None,
        created_at=None,
        last_login=None,
        email_verified=True,
    ):
        import asyncio
        from authglow.models.user import User
        from authglow.services.password import hash_password
        from authglow.core.datetime import utcnow

        user = User(
            email=email,
            hashed_password=hash_password("TestP@ss123!"),
            is_active=is_active,
            mfa_enabled=mfa_enabled,
            email_verified=email_verified,
            scopes=scopes or ["read"],
        )
        if created_at:
            user.created_at = created_at
        if last_login:
            user.last_login = last_login
        return asyncio.get_event_loop().run_until_complete(storage.create_user(user))

    def test_filter_by_active(self, storage):
        import asyncio

        self._create_user(storage, "active@test.com", is_active=True)
        self._create_user(storage, "inactive@test.com", is_active=False)

        all_users, total_all = asyncio.get_event_loop().run_until_complete(
            storage.list_users(is_active=None)
        )
        assert total_all == 2

        active, total_active = asyncio.get_event_loop().run_until_complete(
            storage.list_users(is_active=True)
        )
        assert total_active == 1
        assert active[0].email == "active@test.com"

        inactive, total_inactive = asyncio.get_event_loop().run_until_complete(
            storage.list_users(is_active=False)
        )
        assert total_inactive == 1
        assert inactive[0].email == "inactive@test.com"

    def test_filter_by_mfa(self, storage):
        import asyncio

        self._create_user(storage, "mfa@test.com", mfa_enabled=True)
        self._create_user(storage, "nomfa@test.com", mfa_enabled=False)

        mfa_users, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(mfa_enabled=True)
        )
        assert total == 1
        assert mfa_users[0].email == "mfa@test.com"

    def test_filter_by_email_verified(self, storage):
        import asyncio

        self._create_user(storage, "verified@test.com", email_verified=True)
        self._create_user(storage, "unverified@test.com", email_verified=False)

        verified, total_v = asyncio.get_event_loop().run_until_complete(
            storage.list_users(email_verified=True)
        )
        assert total_v == 1
        assert verified[0].email == "verified@test.com"

        unverified, total_u = asyncio.get_event_loop().run_until_complete(
            storage.list_users(email_verified=False)
        )
        assert total_u == 1
        assert unverified[0].email == "unverified@test.com"

    def test_filter_by_scopes(self, storage):
        import asyncio

        self._create_user(storage, "admin@test.com", scopes=["admin", "read"])
        self._create_user(storage, "user@test.com", scopes=["read"])
        self._create_user(storage, "super@test.com", scopes=["admin", "write"])

        admin_users, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(scopes=["admin"])
        )
        assert total == 2

        admin_read, total_ar = asyncio.get_event_loop().run_until_complete(
            storage.list_users(scopes=["admin", "read"])
        )
        assert total_ar == 1

    def test_filter_by_created_after(self, storage):
        import asyncio
        from authglow.core.datetime import utcnow
        from datetime import timedelta

        old = utcnow() - timedelta(days=10)
        recent = utcnow() - timedelta(days=1)

        self._create_user(storage, "old@test.com", created_at=old)
        self._create_user(storage, "recent@test.com", created_at=recent)

        cutoff = utcnow() - timedelta(days=5)
        results, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(created_after=cutoff)
        )
        assert total == 1
        assert results[0].email == "recent@test.com"

    def test_filter_combines_multiple_criteria(self, storage):
        import asyncio

        self._create_user(storage, "active-mfa@test.com", is_active=True, mfa_enabled=True)
        self._create_user(storage, "active-nomfa@test.com", is_active=True, mfa_enabled=False)
        self._create_user(storage, "inactive-mfa@test.com", is_active=False, mfa_enabled=True)

        results, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(is_active=True, mfa_enabled=True)
        )
        assert total == 1
        assert results[0].email == "active-mfa@test.com"

    def test_filter_all_params_comprehensive(self, storage):
        import asyncio
        from authglow.core.datetime import utcnow
        from datetime import timedelta

        recent = utcnow() - timedelta(hours=1)
        self._create_user(
            storage,
            "target@test.com",
            is_active=True,
            mfa_enabled=True,
            email_verified=True,
            scopes=["admin", "read"],
            created_at=recent,
            last_login=recent,
        )
        self._create_user(
            storage,
            "other@test.com",
            is_active=False,
            mfa_enabled=False,
            email_verified=False,
            scopes=["read"],
            created_at=utcnow() - timedelta(days=30),
        )

        cutoff = utcnow() - timedelta(days=1)
        results, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(
                is_active=True,
                mfa_enabled=True,
                email_verified=True,
                scopes=["admin"],
                created_after=cutoff,
            )
        )
        assert total == 1
        assert results[0].email == "target@test.com"
