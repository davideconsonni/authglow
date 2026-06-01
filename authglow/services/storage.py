"""User storage service using fsspec."""

import json
import os
from typing import Optional, List
from datetime import datetime, timedelta
import fsspec
from authglow.models.user import User
from authglow.core.config import get_settings
from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import named_lock
from authglow.core.datetime import utcnow


class UserStorage:
    """Stateless user storage using fsspec.

    All read-modify-write operations acquire a named lock keyed by resource
    (e.g. ``"user:<id>"`` or ``"email_index"``) to prevent in-process
    race conditions.

    Internal methods prefixed with ``_`` do NOT acquire locks — they are
    called from within lock-holding methods.  Public methods acquire locks.
    """

    def __init__(self):
        """Initialize storage with settings."""
        self.settings = get_settings()
        self.storage_path = self.settings.storage_path
        self.storage_options = self.settings.get_storage_options()

        # Initialize filesystem
        if self.settings.storage_backend == "file":
            # For local filesystem, ensure directory exists
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            # For cloud backends (s3, gcs, abfs)
            self.fs = fsspec.filesystem(
                self.settings.storage_backend, **self.storage_options
            )

        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

    def _get_user_path(self, user_id: str) -> str:
        """Get full path for a user file."""
        return f"{self.storage_path}/{user_id}.json"

    def _get_email_index_path(self) -> str:
        """Get path for email-to-id index."""
        return f"{self.storage_path}/email_index.json"

    async def _load_email_index(self) -> dict:
        """Load email to user_id mapping."""
        index_path = self._get_email_index_path()
        try:
            return await self._afs.read_json(index_path)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    async def _save_email_index(self, index: dict):
        """Save email to user_id mapping."""
        index_path = self._get_email_index_path()
        await self._afs.write_json(index_path, index)

    async def _write_user(self, user: User) -> User:
        """Write user data to storage without acquiring any lock.

        Caller must hold the appropriate lock if needed.
        """
        user.updated_at = utcnow()
        user_path = self._get_user_path(user.id)
        user_data = user.model_dump(mode="json")
        await self._afs.write_json(user_path, user_data)
        return user

    async def create_user(self, user: User) -> User:
        """Create a new user."""
        async with self._lock(f"user:{user.id}"), self._lock("email_index"):
            # Check if email already exists
            email_index = await self._load_email_index()
            if user.email.lower() in email_index:
                raise ValueError(f"User with email {user.email} already exists")

            # Save user
            user_path = self._get_user_path(user.id)
            user_data = user.model_dump(mode="json")

            await self._afs.write_json(user_path, user_data)

            # Update email index
            email_index[user.email.lower()] = user.id
            await self._save_email_index(email_index)

        return user

    async def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        user_path = self._get_user_path(user_id)

        try:
            user_data = await self._afs.read_json(user_path)
            return User(**user_data)
        except FileNotFoundError:
            return None

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email.

        When ``timing_leak_protection`` is enabled (default), the method
        normalises the I/O profile of the "user not found" path so that
        it resembles the "user found" path (an extra file read attempt),
        then adds a small random jitter on top to mask residual timing
        differences.  This prevents an attacker from measuring response
        times to determine whether an email address is registered.
        """
        import asyncio
        import secrets

        email_index = await self._load_email_index()
        user_id = email_index.get(email.lower())

        result = None
        if user_id:
            result = await self.get_user(user_id)

        if self.settings.timing_leak_protection:
            if result is None:
                try:
                    await self._afs.read_json(self._get_user_path("__timing_padding"))
                except Exception:
                    pass
            jitter_ms = secrets.randbelow(50)
            await asyncio.sleep(jitter_ms / 1000.0)

        return result

    async def update_user(self, user: User) -> User:
        """Update an existing user (acquires per-user lock)."""
        async with self._lock(f"user:{user.id}"):
            return await self._write_user(user)

    async def delete_user(self, user_id: str) -> bool:
        """Delete a user."""
        async with self._lock(f"user:{user_id}"), self._lock("email_index"):
            user = await self.get_user(user_id)
            if not user:
                return False

            # Remove from email index
            email_index = await self._load_email_index()
            email_index.pop(user.email.lower(), None)
            await self._save_email_index(email_index)

            # Delete user file
            user_path = self._get_user_path(user_id)
            try:
                await self._afs.rm(user_path)
                return True
            except FileNotFoundError:
                return False

    async def count_users(self) -> int:
        """Count total number of users from the email index."""
        email_index = await self._load_email_index()
        return len(email_index)

    async def get_user_stats(self) -> dict:
        """Compute aggregate user statistics in a single pass.

        Returns counts without keeping all User objects in memory
        simultaneously — each user object is processed and released.
        """
        email_index = await self._load_email_index()
        now = utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)
        month_start = today_start - timedelta(days=30)

        total = active = mfa = new_today = new_week = new_month = 0

        for user_id in email_index.values():
            user = await self.get_user(user_id)
            if not user:
                continue
            total += 1
            if user.is_active:
                active += 1
            if user.mfa_enabled and user.mfa_verified:
                mfa += 1
            if user.created_at >= today_start:
                new_today += 1
            if user.created_at >= week_start:
                new_week += 1
            if user.created_at >= month_start:
                new_month += 1

        return {
            "total": total,
            "active": active,
            "inactive": total - active,
            "mfa": mfa,
            "new_today": new_today,
            "new_week": new_week,
            "new_month": new_month,
        }

    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
        mfa_enabled: Optional[bool] = None,
    ) -> tuple[List[User], int]:
        """List users with optional server-side filtering and pagination.

        Returns a tuple of (filtered_page, total_matching_count).
        """
        email_index = await self._load_email_index()
        all_user_ids = list(email_index.values())

        filtered = []
        for uid in all_user_ids:
            user = await self.get_user(uid)
            if not user:
                continue

            if search:
                sl = search.lower()
                if not (
                    sl in user.email.lower()
                    or (user.first_name and sl in user.first_name.lower())
                    or (user.last_name and sl in user.last_name.lower())
                ):
                    continue

            if is_active is not None and user.is_active != is_active:
                continue

            if mfa_enabled is not None and user.mfa_enabled != mfa_enabled:
                continue

            filtered.append(user)

        total = len(filtered)
        page = filtered[offset : offset + limit]
        return page, total

    async def update_last_login(self, user_id: str):
        """Update user's last login timestamp and increment login counter."""
        async with self._lock(f"user:{user_id}"):
            user = await self.get_user(user_id)
            if user:
                user.last_login = utcnow()
                user.login_count = user.login_count + 1
                await self._write_user(user)

    async def record_failed_login(
        self, user_id: str, max_attempts: int = 5, lockout_duration_minutes: int = 15
    ):
        """Record a failed login attempt and lock account if threshold exceeded."""
        async with self._lock(f"user:{user_id}"):
            user = await self.get_user(user_id)
            if user:
                user.failed_login_attempts += 1
                user.failed_login_count = user.failed_login_count + 1

                # Lock account if max attempts exceeded
                if user.failed_login_attempts >= max_attempts:
                    user.locked_until = utcnow() + timedelta(
                        minutes=lockout_duration_minutes
                    )

                await self._write_user(user)
                return user.locked_until

    async def reset_failed_login_attempts(self, user_id: str):
        """Reset failed login attempts after successful login."""
        async with self._lock(f"user:{user_id}"):
            user = await self.get_user(user_id)
            if user:
                user.failed_login_attempts = 0
                user.locked_until = None
                await self._write_user(user)

    async def is_account_locked(self, user_id: str) -> bool:
        """Check if account is currently locked."""
        async with self._lock(f"user:{user_id}"):
            user = await self.get_user(user_id)
            if not user or not user.locked_until:
                return False

            # Check if lockout period has expired
            if utcnow() >= user.locked_until:
                # Auto-unlock account
                user.locked_until = None
                user.failed_login_attempts = 0
                await self._write_user(user)
                return False

            return True
