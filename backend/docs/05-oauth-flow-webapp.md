# Guide: Web App Authentication (Authorization Code + PKCE)

This guide provides a complete, step-by-step walkthrough for integrating a traditional web application (one with a backend) with AuthGlow using the **Authorization Code Flow with PKCE**. This is the most secure and recommended method for this type of application.

ma hWe will use Python with FastAPI and the `requests` library for our examples, but the principles are the same for any language or framework.

## Prerequisites

Before you start, you must have:
1.  An OAuth Client configured in the AuthGlow admin panel.
2.  Your **Client ID** and **Client Secret**.
3.  At least one **Redirect URI** registered (e.g., `http://127.0.0.1:5000/callback`).

---

## The Flow: A High-Level View

1.  **User Action**: The user clicks "Login" in your application.
2.  **PKCE Generation**: Your app generates a `code_verifier` and `code_challenge`.
3.  **Redirect**: Your app redirects the user to AuthGlow's authorization endpoint, passing along the `code_challenge`.
4.  **Authentication**: The user logs in and grants consent on the AuthGlow page.
5.  **Callback**: AuthGlow redirects the user back to your app's `redirect_uri` with an `authorization_code`.
6.  **Token Exchange**: Your app's backend sends the `authorization_code` and the original `code_verifier` to AuthGlow's token endpoint.
7.  **Receive Tokens**: AuthGlow performs a critical security check by hashing the `code_verifier` and comparing it to the `code_challenge` from the start of the flow. If they match, it validates the request and returns an `id_token`, `access_token`, and `refresh_token`.
8.  **Session Creation**: Your app validates the tokens and creates a local session for the user.

---

## Step 1: Setting up the FastAPI App and PKCE Generation

First, you need a basic FastAPI application. Since FastAPI doesn't have built-in sessions like Flask, we'll add Starlette's `SessionMiddleware` to handle session data.

Your `app.py` will start like this:

```python
# app.py (FastAPI Example)
import hashlib
import base64
import os
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI()

# Add session middleware. A strong secret_key is required.
# This key should be loaded from environment variables in a real app.
app.add_middleware(SessionMiddleware, secret_key="your-fastapi-app-secret-key")

def generate_pkce_codes(request: Request):
    """Generates and stores PKCE code verifier and challenge in the session."""
    # 1. Generate a high-entropy random string
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    code_verifier = code_verifier.rstrip('=')

    # 2. Create the SHA256 hash
    sha256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()

    # 3. Base64-URL-encode the hash
    code_challenge = base64.urlsafe_b64encode(sha256).decode('utf-8')
    code_challenge = code_challenge.rstrip('=')

    # 4. Store the verifier in the user's session for later
    request.session['code_verifier'] = code_verifier
    
    return code_challenge
```

## Step 2: The Login Route and Redirect

Create a `/login` route that generates the PKCE codes and redirects the user to AuthGlow.

```python
# app.py (FastAPI Example, continued)
from urllib.parse import urlencode
from fastapi import Depends

# --- AuthGlow Configuration ---
AUTHGLOW_URL = "http://localhost:8000"
CLIENT_ID = "your-client-id-from-authglow"
CLIENT_SECRET = "your-client-secret-from-authglow"
REDIRECT_URI = "http://127.0.0.1:5000/callback"
# ---

# Note: The generate_pkce_codes function needs the request, so we wrap it in a dependency
def pkce_codes_dependency(request: Request):
    return generate_pkce_codes(request)

@app.get('/login')
async def login(request: Request, code_challenge: str = Depends(pkce_codes_dependency)):
    """
    Initiates the OIDC login flow.
    """
    # Generate a random state value and store it in the session
    state = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
    request.session['state'] = state

    # Prepare the query parameters for the authorization request
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid profile email',
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    
    # Construct the full authorization URL and redirect the user
    auth_url = f"{AUTHGLOW_URL}/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(url=auth_url)
```

## Step 3: The Callback Route and Token Exchange

This is the most critical part. Your backend receives the `authorization_code` and securely exchanges it for tokens. During this step, AuthGlow performs the vital PKCE validation. The `code_verifier` you send is hashed by the server and compared against the `code_challenge` stored at the beginning of the flow. If they do not match, or if the `code_verifier` is missing, the request will be rejected. This ensures that only the application that initiated the login can complete it.

### Python (FastAPI) Example
```python
# app.py (continued)
import requests

@app.get('/callback')
async def callback(request: Request):
    # ... (implement state verification by comparing request.query_params.get('state') 
    # with request.session.get('state')) ...

    # Prepare the request to the token endpoint
    token_url = f"{AUTHGLOW_URL}/oauth/token"
    payload = {
        'grant_type': 'authorization_code',
        'code': request.query_params.get('code'),
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': request.session.get('code_verifier')
    }

    # Make the POST request
    response = requests.post(token_url, data=payload)
    tokens = response.json()

    # ... (process tokens and create session) ...
    request.session['user_tokens'] = tokens
    return RedirectResponse(url='/profile') # Redirect to a profile page
```

### cURL Example
You can simulate this server-to-server call using `curl`. This is useful for debugging.

```bash
# Replace placeholders with actual values
AUTH_CODE="the_code_from_the_callback_url"
CODE_VERIFIER="the_original_verifier_stored_in_the_session"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
REDIRECT_URI="http://127.0.0.1:5000/callback"
AUTHGLOW_URL="http://localhost:8000"

curl -X POST "$AUTHGLOW_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "code_verifier=$CODE_VERIFIER"
```

If successful, AuthGlow will respond with a JSON payload containing the tokens:
```json
{
  "access_token": "eyJ...",
  "id_token": "eyJ...",
  "refresh_token": "a_long_opaque_string...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "scope": "openid profile email"
}
```

---

## Step 4: Accessing User Information

Once you have an `access_token`, you can use it to fetch the user's profile information from the standard OIDC `userinfo` endpoint. This is a secure way to get the latest user data.

### cURL Example
```bash
# Replace placeholder with the actual access_token
ACCESS_TOKEN="eyJ..."
AUTHGLOW_URL="http://localhost:8000"

curl -X GET "$AUTHGLOW_URL/oauth/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

The endpoint will return a JSON object with the user's claims, such as:
```json
{
  "sub": "user-id-string",
  "name": "John Doe",
  "email": "john.doe@example.com",
  "email_verified": true
}
```

---

## Step 5: Refreshing Tokens

When the `access_token` expires, use the `refresh_token` to get a new set of tokens without user interaction.

### Python Example
```python
async def refresh_access_token(request: Request, refresh_token: str):
    token_url = f"{AUTHGLOW_URL}/oauth/token"
    payload = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response = requests.post(token_url, data=payload)
    # ... (error handling) ...
    new_tokens = response.json()
    # Important: Update the stored refresh_token if a new one is returned.
    request.session['user_tokens'] = new_tokens
    return new_tokens
```

### cURL Example
```bash
# Replace placeholders with actual values
REFRESH_TOKEN="the_refresh_token_you_stored"
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
AUTHGLOW_URL="http://localhost:8000"

curl -X POST "$AUTHGLOW_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET"
```
