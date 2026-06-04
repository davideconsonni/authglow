"""User storage service using fsspec.

All PII fields (email, name, phone) are encrypted at rest with AES-256-GCM.
The email index uses HMAC-SHA256 keys — plaintext email never stored on disk.
"""

import json
import os
from datetime import datetime, timedelta
from typing import List, Optional

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.cache import user_cache
from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.core.crypto import decrypt_field, encrypt_field, hash_index_key
from authglow.core.datetime import utcnow
from authglow.models.user import User


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

        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(self.settings.storage_backend, **self.storage_options)

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
            result: dict = await self._afs.read_json(index_path)
            return result
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    async def _save_email_index(self, index: dict):
        """Save email to user_id mapping."""
        index_path = self._get_email_index_path()
        await self._afs.write_json(index_path, index)

    def _encrypt_user_for_storage(self, user: User) -> dict:
        """Prepare user dict for storage — encrypts PII fields."""
        data = user.model_dump(mode="json")
        if data.get("email"):
            data["email"] = encrypt_field(data["email"])
        if data.get("first_name"):
            data["first_name"] = encrypt_field(data["first_name"])
        if data.get("last_name"):
            data["last_name"] = encrypt_field(data["last_name"])
        if data.get("phone"):
            data["phone"] = encrypt_field(data["phone"])
        if data.get("avatar_url"):
            data["avatar_url"] = encrypt_field(data["avatar_url"])
        return data

    def _decrypt_user_from_storage(self, data: dict) -> dict:
        """Decrypt PII fields from a user dict read from disk."""
        if data.get("email"):
            data["email"] = decrypt_field(data["email"])
        if data.get("first_name"):
            data["first_name"] = decrypt_field(data["first_name"])
        if data.get("last_name"):
            data["last_name"] = decrypt_field(data["last_name"])
        if data.get("phone"):
            data["phone"] = decrypt_field(data["phone"])
        if data.get("avatar_url"):
            data["avatar_url"] = decrypt_field(data["avatar_url"])
        return data

    async def _write_user(self, user: User) -> User:
        """Write user data to storage without acquiring any lock.

        Caller must hold the appropriate lock if needed.
        """
        user.updated_at = utcnow()
        user_path = self._get_user_path(user.id)
        user_data = self._encrypt_user_for_storage(user)
        await self._afs.write_json(user_path, user_data)
        user_cache.pop(user.email.lower(), None)
        return user

    async def create_user(self, user: User) -> User:
        """Create a new user."""
        async with self._lock(f"user:{user.id}"), self._lock("email_index"):
            email_index = await self._load_email_index()
            index_key = hash_index_key(user.email.lower())
            if index_key in email_index:
                raise ValueError(f"User with email {user.email} already exists")

            user_path = self._get_user_path(user.id)
            user_data = self._encrypt_user_for_storage(user)
            await self._afs.write_json(user_path, user_data)

            email_index[index_key] = user.id
            await self._save_email_index(email_index)

        return user

    async def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        user_path = self._get_user_path(user_id)
        try:
            user_data = await self._afs.read_json(user_path)
            return User(**self._decrypt_user_from_storage(user_data))
        except FileNotFoundError:
            return None

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        import asyncio
        import secrets

        key = email.lower()
        cached: User | None = user_cache.get(key)
        if cached is not None:
            return cached

        email_index = await self._load_email_index()
        index_key = hash_index_key(key)
        user_id = email_index.get(index_key)

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

        if result is not None:
            user_cache[key] = result

        return result

    async def update_user(self, user: User) -> User:
        """Update an existing user (acquires per-user lock)."""
        async with self._lock(f"user:{user.id}"):
            return await self._write_user(user)

    async def update_email(self, user_id: str, new_email: str) -> Optional[User]:
        """Update a user's email, handling the email index update."""
        async with self._lock(f"user:{user_id}"), self._lock("email_index"):
            user = await self.get_user(user_id)
            if not user:
                return None

            old_key = hash_index_key(user.email.lower())
            new_key = hash_index_key(new_email.lower())

            if old_key == new_key:
                user.email = new_email  # type: ignore[assignment]
                return await self._write_user(user)

            email_index = await self._load_email_index()

            if new_key in email_index and email_index[new_key] != user_id:
                raise ValueError(f"User with email {new_email} already exists")

            if old_key in email_index:
                del email_index[old_key]
            email_index[new_key] = user_id
            await self._save_email_index(email_index)

            user.email = new_email  # type: ignore[assignment]
            user_cache.pop(user.email.lower(), None)
            user_cache.pop(new_email.lower(), None)
            return await self._write_user(user)

    async def delete_user(self, user_id: str) -> bool:
        """Delete a user."""
        async with self._lock(f"user:{user_id}"), self._lock("email_index"):
            user = await self.get_user(user_id)
            if not user:
                return False

            email_index = await self._load_email_index()
            index_key = hash_index_key(user.email.lower())
            email_index.pop(index_key, None)
            await self._save_email_index(email_index)

            user_path = self._get_user_path(user_id)
            try:
                await self._afs.rm(user_path)
                user_cache.pop(user.email.lower(), None)
                return True
            except FileNotFoundError:
                return False

    async def count_users(self) -> int:
        """Count total number of users from the email index."""
        email_index = await self._load_email_index()
        return len(email_index)

    async def get_user_stats(self) -> dict:
        """Compute aggregate user statistics in a single pass."""
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
        email_verified: Optional[bool] = None,
        scopes: Optional[list[str]] = None,
        created_after: Optional[datetime] = None,
        created_before: Optional[datetime] = None,
        last_login_after: Optional[datetime] = None,
        last_login_before: Optional[datetime] = None,
    ) -> tuple[List[User], int]:
        """List users with optional server-side filtering and pagination."""
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

            if email_verified is not None and user.email_verified != email_verified:
                continue

            if scopes is not None:
                if not all(s in user.scopes for s in scopes):
                    continue

            if created_after is not None and user.created_at < created_after:
                continue

            if created_before is not None and user.created_at > created_before:
                continue

            if last_login_after is not None:
                if user.last_login is None or user.last_login < last_login_after:
                    continue

            if last_login_before is not None:
                if user.last_login is None or user.last_login > last_login_before:
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

                if user.failed_login_attempts >= max_attempts:
                    user.locked_until = utcnow() + timedelta(minutes=lockout_duration_minutes)

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

            if utcnow() >= user.locked_until:
                user.locked_until = None
                user.failed_login_attempts = 0
                await self._write_user(user)
                return False

            return True

    async def set_password(
        self,
        user_id: str,
        hashed_password: str,
        require_change: bool = False,
    ):
        """Set a new password for a user."""
        async with self._lock(f"user:{user_id}"):
            user = await self.get_user(user_id)
            if not user:
                return None
            user.hashed_password = hashed_password
            user.password_expired = require_change
            user.password_changed_at = utcnow()
            await self._write_user(user)
            return user

    async def clear_failed_login_attempts(self, user_id: str):
        """Zero out failed_login_attempts without clearing lockout."""
        async with self._lock(f"user:{user_id}"):
            user = await self.get_user(user_id)
            if user:
                user.failed_login_attempts = 0
                await self._write_user(user)
