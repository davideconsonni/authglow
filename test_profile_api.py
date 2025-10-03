#!/usr/bin/env python
"""Test profile API endpoint."""
import requests
import json

# Get token
response = requests.post(
    "http://127.0.0.1:8000/api/token",
    data={"username": "root@example.com", "password": "Admin123!"},
    headers={"Content-Type": "application/x-www-form-urlencoded"}
)

if response.status_code != 200:
    print(f"Login failed: {response.status_code}")
    print(response.text)
    exit(1)

token = response.json()["access_token"]
print(f"[OK] Got token: {token[:50]}...")

# Test profile endpoint
response = requests.get(
    "http://127.0.0.1:8000/api/profile/me",
    headers={"Authorization": f"Bearer {token}"}
)

print(f"\nProfile API Response ({response.status_code}):")
if response.status_code == 200:
    profile = response.json()
    print(json.dumps(profile, indent=2))
else:
    print(f"Error: {response.text}")
