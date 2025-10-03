#!/usr/bin/env python
"""Create a default OAuth client for testing."""
import asyncio
import os
from authglow.models.oauth_client import OAuth2Client, OAuth2ClientCreate
from authglow.services.oauth_client import OAuth2ClientService

async def create_default_client():
    """Create a default OAuth client."""
    print("=== Creating Default OAuth Client ===\n")

    service = OAuth2ClientService()

    # Check if default client exists
    existing = await service.get_client("default-client")
    if existing:
        print(f"Default client already exists!")
        print(f"  Client ID: {existing.client_id}")
        print(f"  Client Name: {existing.client_name}")
        print(f"  Redirect URIs: {existing.redirect_uris}")
        return

    # Create default client
    client_data = OAuth2ClientCreate(
        client_id="default-client",
        client_name="Default Client",
        redirect_uris=["http://127.0.0.1:8000/callback", "http://localhost:8000/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scopes=["read", "write", "openid", "profile", "email"],
        token_endpoint_auth_method="client_secret_post"
    )

    client = await service.create_client(
        client_data=client_data,
        owner_id="system"
    )

    print("[SUCCESS] Default OAuth client created!")
    print(f"  Client ID: {client.client_id}")
    print(f"  Client Secret: {client.client_secret}")
    print(f"  Client Name: {client.client_name}")
    print(f"  Redirect URIs: {', '.join(client.redirect_uris)}")
    print(f"\nYou can now use this client for OAuth login!")

if __name__ == "__main__":
    asyncio.run(create_default_client())
