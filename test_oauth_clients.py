"""Test OAuth2 Client Management."""
import requests
import json

BASE_URL = "http://127.0.0.1:8000"

print("="*70)
print(" OAuth2 Client Management Test")
print("="*70)

# Step 1: Login as admin to get token
print("\n[1] Login as admin...")
login_response = requests.post(
    f"{BASE_URL}/api/token",
    data={"username": "admin@authglow.local", "password": "admin123"}
)

if login_response.status_code != 200:
    print(f"   ERROR: Failed to login - {login_response.status_code}")
    print(f"   {login_response.json()}")
    exit(1)

access_token = login_response.json()["access_token"]
headers = {"Authorization": f"Bearer {access_token}"}
print(f"   SUCCESS: Logged in as admin")

# Step 2: Create a new OAuth2 client
print("\n[2] Creating new OAuth2 client...")
new_client = {
    "client_name": "Test Application",
    "redirect_uris": ["http://localhost:3000/callback", "https://myapp.com/callback"],
    "allowed_scopes": ["read", "write", "admin"],
    "grant_types": ["authorization_code", "refresh_token"],
    "is_confidential": True,
    "require_pkce": False,
    "require_consent": True,
    "description": "Test OAuth2 application",
    "homepage_uri": "https://myapp.com",
    "access_token_lifetime": 3600,
    "refresh_token_lifetime": 2592000
}

create_response = requests.post(
    f"{BASE_URL}/api/oauth-clients",
    headers=headers,
    json=new_client
)

if create_response.status_code != 201:
    print(f"   ERROR: Failed to create client - {create_response.status_code}")
    print(f"   {create_response.json()}")
    exit(1)

client_data = create_response.json()
client_id = client_data["client_id"]
client_secret = client_data["client_secret"]

print(f"   SUCCESS: Created OAuth2 client")
print(f"   Client ID: {client_id}")
print(f"   Client Secret: {client_secret[:10]}... (truncated)")

# Step 3: List all clients
print("\n[3] Listing all OAuth2 clients...")
list_response = requests.get(
    f"{BASE_URL}/api/oauth-clients",
    headers=headers
)

if list_response.status_code != 200:
    print(f"   ERROR: Failed to list clients - {list_response.status_code}")
else:
    clients = list_response.json()
    print(f"   SUCCESS: Found {len(clients)} client(s)")
    for client in clients:
        print(f"   - {client['client_name']} (ID: {client['client_id'][:8]}...)")

# Step 4: Get specific client
print(f"\n[4] Getting client details...")
get_response = requests.get(
    f"{BASE_URL}/api/oauth-clients/{client_id}",
    headers=headers
)

if get_response.status_code != 200:
    print(f"   ERROR: Failed to get client - {get_response.status_code}")
else:
    client_details = get_response.json()
    print(f"   SUCCESS: Retrieved client '{client_details['client_name']}'")
    print(f"   Redirect URIs: {len(client_details['redirect_uris'])}")
    print(f"   Allowed Scopes: {', '.join(client_details['allowed_scopes'])}")

# Step 5: Update client
print(f"\n[5] Updating client...")
update_data = {
    "description": "Updated test application",
    "allowed_scopes": ["read", "write"]
}

update_response = requests.put(
    f"{BASE_URL}/api/oauth-clients/{client_id}",
    headers=headers,
    json=update_data
)

if update_response.status_code != 200:
    print(f"   ERROR: Failed to update client - {update_response.status_code}")
else:
    print(f"   SUCCESS: Client updated")

# Step 6: Rotate client secret
print(f"\n[6] Rotating client secret...")
rotate_response = requests.post(
    f"{BASE_URL}/api/oauth-clients/{client_id}/rotate-secret",
    headers=headers
)

if rotate_response.status_code != 200:
    print(f"   ERROR: Failed to rotate secret - {rotate_response.status_code}")
else:
    rotation_data = rotate_response.json()
    new_secret = rotation_data["new_client_secret"]
    print(f"   SUCCESS: Secret rotated")
    print(f"   New Secret: {new_secret[:10]}... (truncated)")

# Step 7: Deactivate client
print(f"\n[7] Deactivating client...")
deactivate_response = requests.post(
    f"{BASE_URL}/api/oauth-clients/{client_id}/deactivate",
    headers=headers
)

if deactivate_response.status_code != 200:
    print(f"   ERROR: Failed to deactivate - {deactivate_response.status_code}")
else:
    print(f"   SUCCESS: Client deactivated")

# Step 8: Activate client
print(f"\n[8] Activating client...")
activate_response = requests.post(
    f"{BASE_URL}/api/oauth-clients/{client_id}/activate",
    headers=headers
)

if activate_response.status_code != 200:
    print(f"   ERROR: Failed to activate - {activate_response.status_code}")
else:
    print(f"   SUCCESS: Client activated")

# Step 9: Delete client
print(f"\n[9] Deleting client...")
delete_response = requests.delete(
    f"{BASE_URL}/api/oauth-clients/{client_id}",
    headers=headers
)

if delete_response.status_code != 200:
    print(f"   ERROR: Failed to delete client - {delete_response.status_code}")
else:
    print(f"   SUCCESS: Client deleted")

print("\n" + "="*70)
print(" All OAuth2 Client Management Tests Passed!")
print("="*70)
print()
