"""Script to create an admin user."""

import asyncio
from authglow.models.user import User
from authglow.services.storage import UserStorage
from authglow.services.password import hash_password, PasswordValidator


async def create_admin():
    """Create an admin user."""
    print("=== AuthGlow Admin User Creation ===\n")

    # Get email
    email = input("Admin email: ").strip()
    if not email:
        print("Error: Email is required")
        return

    # Get password
    password = input("Admin password: ").strip()
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

    # Create admin user
    admin = User(
        email=email,
        hashed_password=hash_password(password),
        scopes=["read", "write", "admin"],
        is_active=True,
        first_name=input("First name (optional): ").strip() or None,
        last_name=input("Last name (optional): ").strip() or None
    )

    await storage.create_user(admin)
    print(f"\n✓ Admin user created successfully!")
    print(f"  Email: {admin.email}")
    print(f"  User ID: {admin.id}")
    print(f"  Scopes: {', '.join(admin.scopes)}")


if __name__ == "__main__":
    asyncio.run(create_admin())
