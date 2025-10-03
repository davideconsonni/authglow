"""Script to create an admin user."""

import asyncio
import os
import sys
from authglow.models.user import User
from authglow.services.storage import UserStorage
from authglow.services.password import hash_password, PasswordValidator


async def create_admin():
    """Create an admin user."""
    print("=== AuthGlow Admin User Creation ===\n")

    # Get email from env or input
    email = os.getenv("ADMIN_EMAIL")
    if not email:
        email = input("Admin email: ").strip()
    else:
        print(f"Admin email: {email} (from ADMIN_EMAIL)")

    if not email:
        print("Error: Email is required")
        return

    # Get password from env or input
    password = os.getenv("ADMIN_PASSWORD")
    if not password:
        password = input("Admin password: ").strip()
    else:
        print("Admin password: ******** (from ADMIN_PASSWORD)")

    if not password:
        print("Error: Password is required")
        return

    # Validate password
    validator = PasswordValidator()
    is_valid, errors = validator.validate(password)
    if not is_valid:
        print("\nPassword validation failed:")
        for error in errors:
            print(f"  - {error}")
        return

    # Create storage
    storage = UserStorage()

    # Check if user already exists
    existing_user = await storage.get_user_by_email(email)
    if existing_user:
        print(f"\nError: User with email {email} already exists")
        return

    # Get optional fields from env or input
    first_name = os.getenv("ADMIN_FIRST_NAME")
    last_name = os.getenv("ADMIN_LAST_NAME")

    # Only prompt for optional fields if possible
    if not first_name:
        try:
            first_name = input("First name (optional): ").strip() or None
        except (EOFError, OSError):
            first_name = None
    if not last_name:
        try:
            last_name = input("Last name (optional): ").strip() or None
        except (EOFError, OSError):
            last_name = None

    # Create admin user
    admin = User(
        email=email,
        hashed_password=hash_password(password),
        scopes=["read", "write", "admin"],
        is_active=True,
        first_name=first_name,
        last_name=last_name
    )

    await storage.create_user(admin)
    print(f"\n[SUCCESS] Admin user created successfully!")
    print(f"  Email: {admin.email}")
    print(f"  User ID: {admin.id}")
    print(f"  Scopes: {', '.join(admin.scopes)}")


if __name__ == "__main__":
    asyncio.run(create_admin())
