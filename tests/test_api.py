"""Basic API tests for AuthGlow."""

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health_check():
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_root_endpoint():
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "AuthGlow" in data["message"]
    assert "version" in data
    assert "docs" in data


def test_docs_available():
    """Test that API documentation is accessible."""
    response = client.get("/docs")
    assert response.status_code == 200


def test_oauth2_authorize_missing_params():
    """Test OAuth2 authorize endpoint with missing parameters."""
    response = client.get("/oauth2/authorize")
    assert response.status_code == 422  # Validation error


def test_token_endpoint_invalid_grant():
    """Test token endpoint with invalid grant type."""
    response = client.post(
        "/oauth2/token",
        data={"grant_type": "invalid_grant"}
    )
    assert response.status_code == 400
