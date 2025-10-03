#!/usr/bin/env python
"""Test setup flow."""
import requests
import json

# Test setup check
print("1. Checking if setup is needed...")
response = requests.get("http://127.0.0.1:8000/api/setup/check")
print(f"   Status: {response.status_code}")
print(f"   Response: {response.json()}")

# Create admin user
print("\n2. Creating admin user...")
response = requests.post(
    "http://127.0.0.1:8000/api/setup/create-admin",
    json={
        "email": "admin@example.com",
        "password": "Admin123!",
        "first_name": "Admin",
        "last_name": "User"
    }
)
print(f"   Status: {response.status_code}")
if response.status_code == 200:
    print(f"   Response: {response.json()}")
    print("\n[SUCCESS] Admin user created!")
else:
    print(f"   Error: {response.text}")

# Check setup again
print("\n3. Checking if setup is still needed...")
response = requests.get("http://127.0.0.1:8000/api/setup/check")
print(f"   Status: {response.status_code}")
print(f"   Response: {response.json()}")
