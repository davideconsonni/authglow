# Protecting Your APIs with AuthGlow

This guide shows you how to integrate AuthGlow authentication into your applications and APIs. You'll learn how to validate JWT tokens, enforce permissions, and secure your endpoints using industry-standard practices.

---

## Overview: The Integration Flow

Once a user authenticates with AuthGlow via OAuth 2.0/OIDC, your application receives:
- **Access Token**: A JWT used to authenticate API requests
- **ID Token**: User identity information (OIDC only)
- **Refresh Token**: Used to obtain new access tokens

Your API must:
1. **Extract** the access token from the `Authorization` header
2. **Validate** the token's signature and claims
3. **Check** permissions/scopes
4. **Allow or deny** the request

```
Client App
   ↓ (sends request with token)
Your API
   ↓ (validates token)
AuthGlow (optional: fetch JWKS or user info)
   ↓ (response)
Your API
   ↓ (grants/denies access)
Client App
```

---

## Understanding JWT Tokens from AuthGlow

### Access Token Structure

AuthGlow issues JWT access tokens with the following claims:

```json
{
  "sub": "117c39e4-8191-4df8-b5ce-104d7b7ecb4a",  // User ID
  "email": "user@example.com",                    // User email
  "scopes": ["read", "write", "admin"],           // Granted scopes
  "exp": 1728123456,                              // Expiration timestamp
  "iat": 1728119856,                              // Issued at timestamp
  "token_type": "access"                          // Token type
}
```

### ID Token (OIDC)

If using OpenID Connect with the `openid` scope, you also receive an ID token:

```json
{
  "iss": "https://auth.yourdomain.com",           // Issuer
  "sub": "117c39e4-8191-4df8-b5ce-104d7b7ecb4a",  // User ID
  "aud": "your-client-id",                        // Audience (client ID)
  "exp": 1728123456,                              // Expiration
  "iat": 1728119856,                              // Issued at
  "email": "user@example.com",                    // User email (if scope granted)
  "name": "John Doe",                             // Full name (if scope granted)
  "email_verified": true                          // Email verification status
}
```

---

## Method 1: Offline JWT Validation (Recommended)

Validate tokens locally using the JWT secret. This is the fastest method and doesn't require calling AuthGlow for every request.

### Python / FastAPI

#### Basic Setup

```python
# api.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from typing import Optional

app = FastAPI()
security = HTTPBearer()

# Configuration - MUST match AuthGlow's settings
JWT_SECRET_KEY = "your-jwt-secret-key-from-authglow"
JWT_ALGORITHM = "HS256"
ISSUER = "https://auth.yourdomain.com"


def decode_token(token: str) -> Optional[dict]:
    """Validate and decode JWT token."""
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Dependency to get current authenticated user."""
    token = credentials.credentials
    payload = decode_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return payload


# Protected endpoint example
@app.get("/api/protected")
def protected_route(current_user: dict = Depends(get_current_user)):
    return {
        "message": f"Hello {current_user['email']}",
        "user_id": current_user["sub"],
        "scopes": current_user["scopes"]
    }
```

#### With Permission Checking

```python
# api.py (continued)

def require_scope(required_scope: str):
    """Dependency to require specific scope."""
    def check_scope(current_user: dict = Depends(get_current_user)) -> dict:
        user_scopes = current_user.get("scopes", [])

        if required_scope not in user_scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required scope: {required_scope}"
            )

        return current_user

    return check_scope


# Endpoint requiring 'admin' scope
@app.delete("/api/users/{user_id}")
def delete_user(
    user_id: str,
    current_user: dict = Depends(require_scope("admin"))
):
    return {"message": f"User {user_id} deleted by admin {current_user['email']}"}
```

#### Complete Production Example

```python
# auth.py - Reusable authentication module
from functools import lru_cache
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from pydantic import BaseModel
from typing import List, Optional

security = HTTPBearer()


class Settings(BaseModel):
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    issuer: str


@lru_cache
def get_settings() -> Settings:
    """Load settings from environment."""
    import os
    return Settings(
        jwt_secret_key=os.getenv("JWT_SECRET_KEY"),
        issuer=os.getenv("ISSUER", "https://auth.yourdomain.com")
    )


class TokenData(BaseModel):
    sub: str
    email: str
    scopes: List[str] = []


class AuthService:
    """JWT authentication service."""

    def __init__(self):
        self.settings = get_settings()

    def decode_token(self, token: str) -> Optional[TokenData]:
        """Validate and decode token."""
        try:
            payload = jwt.decode(
                token,
                self.settings.jwt_secret_key,
                algorithms=[self.settings.jwt_algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iss": True
                },
                issuer=self.settings.issuer
            )

            return TokenData(
                sub=payload["sub"],
                email=payload["email"],
                scopes=payload.get("scopes", [])
            )

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None


# Singleton instance
auth_service = AuthService()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> TokenData:
    """Get authenticated user from token."""
    token = credentials.credentials
    user = auth_service.decode_token(token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return user


def require_scopes(required_scopes: List[str], require_all: bool = False):
    """Require specific scopes."""
    async def dependency(user: TokenData = Depends(get_current_user)) -> TokenData:
        if require_all:
            # User must have ALL required scopes
            missing = [s for s in required_scopes if s not in user.scopes]
            if missing:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing scopes: {', '.join(missing)}"
                )
        else:
            # User must have AT LEAST ONE required scope
            if not any(s in user.scopes for s in required_scopes):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing any of: {', '.join(required_scopes)}"
                )

        return user

    return dependency


# Usage in your API
# main.py
from fastapi import FastAPI, Depends
from auth import get_current_user, require_scopes, TokenData

app = FastAPI()


@app.get("/api/profile")
async def get_profile(user: TokenData = Depends(get_current_user)):
    """Public endpoint - any authenticated user."""
    return {"user_id": user.sub, "email": user.email}


@app.post("/api/posts")
async def create_post(
    user: TokenData = Depends(require_scopes(["write"]))
):
    """Requires 'write' scope."""
    return {"message": "Post created", "author": user.email}


@app.delete("/api/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    user: TokenData = Depends(require_scopes(["admin"]))
):
    """Requires 'admin' scope."""
    return {"message": f"User {user_id} deleted"}
```

---

### Node.js / Express

#### Basic Setup

```javascript
// auth.js
const jwt = require('jsonwebtoken');

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
const JWT_ALGORITHM = 'HS256';
const ISSUER = process.env.ISSUER || 'https://auth.yourdomain.com';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET_KEY, { algorithms: [JWT_ALGORITHM] }, (err, payload) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    // Attach user info to request
    req.user = {
      id: payload.sub,
      email: payload.email,
      scopes: payload.scopes || []
    };

    next();
  });
}

function requireScope(scope) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    if (!req.user.scopes.includes(scope)) {
      return res.status(403).json({
        error: `Insufficient permissions. Required scope: ${scope}`
      });
    }

    next();
  };
}

module.exports = { authenticateToken, requireScope };
```

#### Usage in Express App

```javascript
// app.js
const express = require('express');
const { authenticateToken, requireScope } = require('./auth');

const app = express();
app.use(express.json());

// Public endpoint (no auth)
app.get('/api/public', (req, res) => {
  res.json({ message: 'Public data' });
});

// Protected endpoint (any authenticated user)
app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({
    message: `Hello ${req.user.email}`,
    user_id: req.user.id,
    scopes: req.user.scopes
  });
});

// Requires 'write' scope
app.post('/api/posts', authenticateToken, requireScope('write'), (req, res) => {
  res.json({ message: 'Post created', author: req.user.email });
});

// Requires 'admin' scope
app.delete('/api/users/:id', authenticateToken, requireScope('admin'), (req, res) => {
  res.json({ message: `User ${req.params.id} deleted` });
});

app.listen(3000, () => {
  console.log('API server running on port 3000');
});
```

---

## Method 2: Introspection (Online Validation)

Validate tokens by calling AuthGlow's introspection endpoint. Use this when:
- You don't have access to the JWT secret
- You want real-time token revocation checking
- You're using opaque refresh tokens

### Python Example

```python
import requests
from fastapi import HTTPException, status

AUTHGLOW_URL = "https://auth.yourdomain.com"
CLIENT_ID = "your-api-client-id"
CLIENT_SECRET = "your-api-client-secret"


def introspect_token(token: str) -> dict:
    """Validate token via AuthGlow introspection endpoint."""
    response = requests.post(
        f"{AUTHGLOW_URL}/oauth2/introspect",
        data={
            "token": token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET
        }
    )

    if response.status_code != 200:
        return None

    data = response.json()

    # Check if token is active
    if not data.get("active"):
        return None

    return data


def get_current_user_introspection(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Validate token via introspection."""
    token = credentials.credentials
    token_data = introspect_token(token)

    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

    return {
        "sub": token_data["sub"],
        "email": token_data.get("email"),
        "scopes": token_data.get("scope", "").split()
    }
```

---

## Method 3: UserInfo Endpoint (OIDC)

Fetch user information from AuthGlow's `/oauth2/userinfo` endpoint.

### Python Example

```python
import requests
from fastapi import HTTPException

def get_user_info(access_token: str) -> dict:
    """Fetch user info from OIDC userinfo endpoint."""
    response = requests.get(
        f"{AUTHGLOW_URL}/oauth2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    if response.status_code != 200:
        return None

    return response.json()


# Usage
@app.get("/api/me")
def get_my_info(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user_info = get_user_info(credentials.credentials)

    if not user_info:
        raise HTTPException(status_code=401, detail="Invalid token")

    return user_info
```

### cURL Example

```bash
curl -X GET "https://auth.yourdomain.com/oauth2/userinfo" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## RBAC Integration (Advanced)

If using AuthGlow's RBAC system, validate permissions based on roles.

### Fetching User Permissions

```python
import requests

def get_user_permissions(user_id: str, admin_token: str) -> list:
    """Fetch user permissions from AuthGlow."""
    response = requests.get(
        f"{AUTHGLOW_URL}/api/rbac/users/{user_id}/permissions",
        headers={"Authorization": f"Bearer {admin_token}"}
    )

    if response.status_code == 200:
        return response.json()["permissions"]

    return []


def require_permission(permission: str):
    """Require specific RBAC permission."""
    async def dependency(user: TokenData = Depends(get_current_user)):
        # Option 1: Permissions embedded in token (if configured)
        user_permissions = user.scopes  # Or a separate 'permissions' claim

        # Option 2: Fetch from AuthGlow (cached recommended)
        # user_permissions = get_user_permissions(user.sub, admin_token)

        if permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {permission}"
            )

        return user

    return dependency


# Usage
@app.get("/api/reports")
async def get_reports(user: TokenData = Depends(require_permission("reports.read"))):
    return {"reports": [...]}
```

---

## Best Practices

### 1. Always Use HTTPS

**Never** transmit tokens over HTTP. Always enforce HTTPS in production.

```python
# FastAPI: Redirect HTTP to HTTPS
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

app.add_middleware(HTTPSRedirectMiddleware)
```

### 2. Validate Token Expiration

Always check the `exp` claim. The JWT libraries handle this automatically when you use `verify_exp=True`.

### 3. Check the Issuer

Validate the `iss` claim to ensure the token came from AuthGlow:

```python
jwt.decode(
    token,
    secret,
    algorithms=["HS256"],
    issuer="https://auth.yourdomain.com"  # Must match ISSUER setting
)
```

### 4. Don't Log Tokens

Never log access tokens in production logs. They are credentials.

```python
# ❌ Bad
logger.info(f"User authenticated with token: {token}")

# ✅ Good
logger.info(f"User {user_id} authenticated")
```

### 5. Cache Token Validation Results

For high-traffic APIs, cache decoded tokens to reduce CPU overhead:

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def decode_token_cached(token: str):
    return jwt.decode(token, secret, algorithms=["HS256"])
```

**Warning**: Be careful with caching if using introspection for revocation checks.

### 6. Handle Token Refresh Client-Side

Your API should only validate access tokens. The client app is responsible for:
- Storing the refresh token securely
- Detecting when the access token is expired (from 401 responses)
- Requesting a new access token using the refresh token

### 7. Use Scopes for Coarse Permissions

Use scopes like `read`, `write`, `admin` for general access control. For fine-grained permissions, use AuthGlow's RBAC system.

### 8. Implement Rate Limiting

Protect your API from abuse:

```python
# FastAPI with slowapi
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.get("/api/protected")
@limiter.limit("100/minute")
async def protected_route(request: Request, user: dict = Depends(get_current_user)):
    return {"data": "..."}
```

---

## Troubleshooting

### "Invalid signature" errors

**Cause**: Mismatch between `JWT_SECRET_KEY` in your API and AuthGlow.

**Solution**: Ensure both use the exact same secret key.

```python
# Your API
JWT_SECRET_KEY = "your-secret-from-env"  # Must match AuthGlow's JWT_SECRET_KEY
```

### "Token expired" errors

**Cause**: Access token lifetime exceeded (default: 30 minutes).

**Solution**: Implement token refresh flow in your client app.

### "Missing scope" errors

**Cause**: User doesn't have required scope.

**Solution**:
- Check OAuth client configuration in AuthGlow admin panel
- Ensure scopes are requested during authorization
- Verify user has required scopes assigned

### CORS errors in browser

**Cause**: Your API doesn't allow requests from the frontend origin.

**Solution**: Configure CORS middleware:

```python
# FastAPI
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-frontend.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## Security Considerations

### Symmetric vs Asymmetric Keys

AuthGlow currently uses **HS256** (symmetric key) by default. This means:
- The same secret signs and verifies tokens
- **The JWT secret must be shared** between AuthGlow and your API
- Keep the secret secure and never expose it

**Future enhancement**: For multi-service architectures, consider using **RS256** (asymmetric):
- AuthGlow signs with a private key
- Your API validates with a public key (via JWKS endpoint)
- No need to share secrets

### Token Storage (Client-Side)

**For web apps**:
- Store tokens in memory or secure `HttpOnly` cookies
- **Never** store in `localStorage` (vulnerable to XSS)

**For mobile apps**:
- Use secure storage (Keychain on iOS, Keystore on Android)

**For SPAs with BFF**:
- Let the backend handle tokens
- Frontend never sees the access token

---

## Example: Complete Protected API

```python
# Full example: api/main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import jwt
from pydantic import BaseModel
from typing import List
import os

app = FastAPI(title="Protected API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://myapp.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
JWT_SECRET = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
security = HTTPBearer()


# Models
class TokenData(BaseModel):
    sub: str
    email: str
    scopes: List[str]


# Authentication
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> TokenData:
    token = credentials.credentials

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return TokenData(
            sub=payload["sub"],
            email=payload["email"],
            scopes=payload.get("scopes", [])
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


def require_scope(scope: str):
    def check(user: TokenData = Depends(get_current_user)):
        if scope not in user.scopes:
            raise HTTPException(status_code=403, detail=f"Requires {scope} scope")
        return user
    return check


# Routes
@app.get("/")
def root():
    return {"message": "API is running"}


@app.get("/protected")
def protected(user: TokenData = Depends(get_current_user)):
    return {"message": f"Hello {user.email}"}


@app.post("/data")
def create_data(user: TokenData = Depends(require_scope("write"))):
    return {"message": "Data created"}


@app.delete("/admin/data/{id}")
def delete_data(id: str, user: TokenData = Depends(require_scope("admin"))):
    return {"message": f"Data {id} deleted"}
```

---

## Next Steps

- **[Storage & Backup Guide](./08-storage-backup.md)**: Understand data persistence
- **[Production Deployment](./10-production-deployment.md)**: Deploy securely
- **[Security Configuration](./11-security.md)**: Harden your setup
