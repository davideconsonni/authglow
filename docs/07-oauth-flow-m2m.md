# Guide: M2M Authentication (Client Credentials)

This guide explains how to authenticate non-interactive services, such as backend APIs, command-line tools, or cron jobs, using the **OAuth 2.0 Client Credentials Flow**.

This flow is used when an application needs to access resources on its own behalf, without any user interaction.

## Use Cases

-   A microservice needing to call another internal API.
-   A data processing script that needs to fetch data from a protected endpoint.
-   Authorizing a CI/CD pipeline to interact with your infrastructure.

## Prerequisites

1.  In the AuthGlow admin panel, create a new **OAuth Client** for your service.
2.  During creation, ensure you enable the **`Client Credentials`** grant type for this client.
3.  Note the **Client ID** and **Client Secret**. Treat the secret like a password.

---

## The Flow

The Client Credentials flow is much simpler than user-centric flows:

1.  **Request**: Your service makes a direct `POST` request to AuthGlow's `/token` endpoint.
2.  **Authentication**: It authenticates itself by providing its `client_id` and `client_secret`.
3.  **Response**: AuthGlow validates the credentials and, if successful, returns an `access_token`.

This `access_token` represents the authority of the client application itself, not a user.

---

## Implementation Examples

### cURL Example

This is the simplest way to demonstrate and test the flow. It's a single, direct API call.

```bash
# Replace placeholders with your client's actual credentials
CLIENT_ID="your-m2m-client-id"
CLIENT_SECRET="your-m2m-client-secret"
AUTHGLOW_URL="http://localhost:8000"

# Optional: Define the scope for the requested token.
# This can be used for fine-grained permissions on your resource server.
# SCOPE="api:read api:write"

curl -X POST "$AUTHGLOW_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  # -d "scope=$SCOPE" # Uncomment to request specific scopes
```

#### Successful Response

If the credentials are valid, AuthGlow will return a JSON payload with an access token:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

-   **`access_token`**: The token your service will use to authenticate with other APIs.
-   **`token_type`**: Always `Bearer`.
-   **`expires_in`**: The lifetime of the token in seconds. Your application should cache this token and only request a new one when it's close to expiring.

---

### Python Example

Here is a simple Python function to get a token using the `requests` library.

```python
import requests
import time

# ---
Configuration ---
CLIENT_ID = "your-m2m-client-id"
CLIENT_SECRET = "your-m2m-client-secret"
AUTHGLOW_URL = "http://localhost:8000"
TOKEN_URL = f"{AUTHGLOW_URL}/oauth/token"

# ---
In-memory cache for the token ---
_cached_token = None
_token_expiry_time = 0

def get_access_token():
    """
    Fetches a valid access token, using a cache to avoid unnecessary requests.
    """
    global _cached_token, _token_expiry_time

    # Check if the token exists and is not about to expire (e.g., within 60s)
    if _cached_token and time.time() < _token_expiry_time - 60:
        print("Returning cached token.")
        return _cached_token

    print("Fetching new access token...")
    payload = {
        'grant_type': 'client_credentials',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'scope': 'api:read' # Example scope
    }

    try:
        response = requests.post(TOKEN_URL, data=payload)
        response.raise_for_status() # Raise an exception for HTTP errors
        
        data = response.json()
        
        # Cache the new token and calculate its expiry time
        _cached_token = data['access_token']
        _token_expiry_time = time.time() + data['expires_in']
        
        print("Successfully fetched new token.")
        return _cached_token

    except requests.exceptions.RequestException as e:
        print(f"Error fetching access token: {e}")
        # In a real application, you should handle this error robustly.
        return None

# ---
Example Usage ---
if __name__ == "__main__":
    token = get_access_token()
    if token:
        print("\nGot Access Token:")
        # print(token) # This would print the long token string
        
        # Example of using the token to call a protected API
        # protected_api_url = "http://api.example.com/data"
        # headers = {"Authorization": f"Bearer {token}"}
        # api_response = requests.get(protected_api_url, headers=headers)
        # print(f"\nAPI Response: {api_response.status_code}")

    # Calling it again should use the cache
    print("\n---", "Calling again", "---")
    token_2 = get_access_token()
```

### Using the Token

Your service should include the obtained `access_token` in the `Authorization` header of every request to the protected resource server (API).

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

The resource server is then responsible for validating this token.
