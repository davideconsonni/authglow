# Guide: Web App Authentication (Authorization Code + PKCE)

This guide provides a complete, step-by-step walkthrough for integrating a traditional web application (one with a backend) with AuthGlow using the **Authorization Code Flow with PKCE**. This is the most secure and recommended method for this type of application.

We will use Python with Flask and the `requests` library for our examples, but the principles are the same for any language or framework.

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
7.  **Receive Tokens**: AuthGlow validates the request and returns an `id_token`, `access_token`, and `refresh_token`.
8.  **Session Creation**: Your app validates the tokens and creates a local session for the user.

---

## Step 1: Generating the PKCE Values

Before the login process begins, you need to generate and store the PKCE values.

```python
# app.py (Flask Example)
import hashlib
import base64
import os
from flask import session

def generate_pkce_codes():
    """Generates and stores PKCE code verifier and challenge."""
    # 1. Generate a high-entropy random string
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    code_verifier = code_verifier.rstrip('=')

    # 2. Create the SHA256 hash
    sha256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()

    # 3. Base64-URL-encode the hash
    code_challenge = base64.urlsafe_b64encode(sha256).decode('utf-8')
    code_challenge = code_challenge.rstrip('=')

    # 4. Store the verifier in the user's session for later
    session['code_verifier'] = code_verifier
    
    return code_challenge
```

## Step 2: The Login Route and Redirect

Create a `/login` route that generates the PKCE codes and redirects the user to AuthGlow.

```python
# app.py (Flask Example)
from flask import Flask, redirect, url_for, session
from urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = 'your-flask-app-secret-key' # For session management

# --- AuthGlow Configuration ---
AUTHGLOW_URL = "http://localhost:8000"
CLIENT_ID = "your-client-id-from-authglow"
CLIENT_SECRET = "your-client-secret-from-authglow"
REDIRECT_URI = "http://127.0.0.1:5000/callback"
# ---

@app.route('/login')
def login():
    """
    Initiates the OIDC login flow.
    """
    code_challenge = generate_pkce_codes()
    
    # Generate a random state value and store it in the session
    state = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
    session['state'] = state

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
    return redirect(auth_url)
```

## Step 3: The Callback Route and Token Exchange

This is the most critical part. Your backend receives the `authorization_code` and securely exchanges it for tokens.

### Python (Flask) Example
```python
# app.py (continued)
import requests
from flask import request, jsonify

@app.route('/callback')
def callback():
    # ... (state verification logic from before) ...

    # Prepare the request to the token endpoint
    token_url = f"{AUTHGLOW_URL}/oauth/token"
    payload = {
        'grant_type': 'authorization_code',
        'code': request.args.get('code'),
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code_verifier': session.get('code_verifier')
    }

    # Make the POST request
    response = requests.post(token_url, data=payload)
    tokens = response.json()

    # ... (process tokens and create session) ...
    session['user_tokens'] = tokens
    return redirect(url_for('profile'))
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
def refresh_access_token(refresh_token):
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
    session['user_tokens'] = new_tokens
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
