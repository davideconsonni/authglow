# AuthGlow

Serverless Customer Identity and Access Management (CIAM) system with OAuth2 support.

## Features

### Core Authentication
- **OAuth2 Support**: Full implementation of OAuth2 with multiple grant types
  - Authorization Code Flow (for web applications)
  - Client Credentials Flow (for service-to-service)
  - Refresh Token Flow
- **JWT Tokens**: Secure, stateless authentication with JWT
- **Invitation-Only Registration**: Users can only be created via admin invitation
- **Configurable Password Policy**: Dynamic password validation rules

### Serverless & Cloud-Ready
- **Stateless Architecture**: No in-memory session storage
- **Multi-Cloud Storage**: Uses fsspec with support for:
  - Local filesystem (development)
  - AWS S3
  - Google Cloud Storage
  - Azure Blob Storage
- **Portable**: Deploy on AWS Lambda, Google Cloud Run, Azure Functions without code changes

### Customizable UI
- Responsive login interface
- Fully customizable via environment variables:
  - Colors (primary, secondary, background, text)
  - Logo
  - Company name
  - Support email
  - Privacy policy & Terms of Service links

## Quick Start

### Prerequisites
- Python 3.9+
- pip

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd authglow
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` and set at minimum:
   ```env
   SECRET_KEY=your-secret-key-min-32-chars-change-this
   JWT_SECRET_KEY=your-jwt-secret-min-32-chars-change-this
   ```

5. **Run the application**
   ```bash
   python main.py
   ```

   The application will be available at `http://localhost:8000`

## Usage

### API Documentation

Once running, visit:
- **Interactive API docs**: http://localhost:8000/docs
- **Alternative docs**: http://localhost:8000/redoc

### Creating the First Admin User

Since AuthGlow uses invitation-only registration, you need to create an admin user manually:

```python
import asyncio
from authglow.models.user import User
from authglow.services.storage import UserStorage
from authglow.services.password import hash_password

async def create_admin():
    storage = UserStorage()
    admin = User(
        email="admin@example.com",
        hashed_password=hash_password("YourSecurePassword123!"),
        scopes=["read", "write", "admin"],
        is_active=True
    )
    await storage.create_user(admin)
    print(f"Admin user created: {admin.email}")

asyncio.run(create_admin())
```

Save this as `create_admin.py` and run:
```bash
python create_admin.py
```

### Testing OAuth2 Flow

1. **Get Authorization Code**

   Visit in browser:
   ```
   http://localhost:8000/oauth2/authorize?response_type=code&client_id=default-client-id&redirect_uri=http://localhost:8000/callback&scope=read&state=xyz
   ```

   Login with your credentials. You'll be redirected with an authorization code.

2. **Exchange Code for Token**

   ```bash
   curl -X POST http://localhost:8000/oauth2/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code" \
     -d "code=YOUR_AUTH_CODE" \
     -d "redirect_uri=http://localhost:8000/callback"
   ```

3. **Use Access Token**

   ```bash
   curl -X GET http://localhost:8000/api/users/me \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
   ```

### Testing with Direct Token Endpoint

For quick testing without OAuth2 flow:

```bash
curl -X POST http://localhost:8000/api/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@example.com" \
  -d "password=YourSecurePassword123!"
```

### Inviting Users

As an admin, invite new users:

```bash
curl -X POST http://localhost:8000/api/users/invite \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "scopes": ["read"],
    "first_name": "John",
    "last_name": "Doe"
  }'
```

## Configuration

### Environment Variables

Key configuration options in `.env`:

#### Application
- `APP_NAME`: Application name (default: "AuthGlow")
- `SECRET_KEY`: Secret key for app (min 32 chars, **required**)
- `JWT_SECRET_KEY`: JWT signing key (min 32 chars, **required**)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: Token lifetime (default: 30)
- `REFRESH_TOKEN_EXPIRE_DAYS`: Refresh token lifetime (default: 7)

#### Storage
- `STORAGE_BACKEND`: `file`, `s3`, `gcs`, or `abfs`
- `STORAGE_PATH`: Path to storage location

For cloud storage, set appropriate credentials (see `.env.example`)

#### Password Policy
- `PASSWORD_MIN_LENGTH`: Minimum password length (default: 8)
- `PASSWORD_REQUIRE_UPPERCASE`: Require uppercase letters (default: true)
- `PASSWORD_REQUIRE_LOWERCASE`: Require lowercase letters (default: true)
- `PASSWORD_REQUIRE_DIGITS`: Require numbers (default: true)
- `PASSWORD_REQUIRE_SPECIAL`: Require special characters (default: true)

#### UI Customization
- `UI_LOGO_URL`: Custom logo URL
- `UI_PRIMARY_COLOR`: Primary color (default: #4F46E5)
- `UI_SECONDARY_COLOR`: Secondary color (default: #06B6D4)
- `UI_COMPANY_NAME`: Company name displayed in UI
- `UI_SUPPORT_EMAIL`: Support contact email

## Project Structure

```
authglow/
├── authglow/
│   ├── api/              # API endpoints
│   │   └── auth.py       # Authentication routes
│   ├── core/             # Core functionality
│   │   └── config.py     # Configuration management
│   ├── models/           # Data models
│   │   ├── user.py       # User models
│   │   └── token.py      # Token models
│   ├── services/         # Business logic
│   │   ├── storage.py    # User storage (fsspec)
│   │   ├── password.py   # Password validation
│   │   ├── jwt.py        # JWT token service
│   │   └── oauth2.py     # OAuth2 service
│   ├── templates/        # HTML templates
│   │   └── login.html    # Login page
│   └── static/           # Static files
│       └── css/
├── tests/                # Test files
├── main.py               # Application entry point
├── requirements.txt      # Dependencies
└── .env.example          # Example configuration
```

## Deployment

### Google Cloud Run

1. Create `Dockerfile`:
   ```dockerfile
   FROM python:3.11-slim
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY . .
   CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
   ```

2. Deploy:
   ```bash
   gcloud run deploy authglow \
     --source . \
     --region us-central1 \
     --allow-unauthenticated
   ```

### AWS Lambda (with Mangum)

Add to `requirements.txt`:
```
mangum==0.17.0
```

Create `lambda_handler.py`:
```python
from mangum import Mangum
from main import app

handler = Mangum(app)
```

Deploy using AWS SAM, Serverless Framework, or CDK.

### Azure Functions

Use Azure Functions Python support with ASGI handler.

## Testing

Create a test file `test_auth.py`:

```python
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "AuthGlow" in response.json()["message"]
```

Run tests:
```bash
pytest
```

## Security Notes

- **Change default secrets**: Always set unique `SECRET_KEY` and `JWT_SECRET_KEY` in production
- **Change OAuth2 credentials**: Set unique `OAUTH2_CLIENT_ID` and `OAUTH2_CLIENT_SECRET`
- **Use HTTPS**: Always use HTTPS in production
- **Secure storage**: Use cloud storage with proper IAM roles/permissions
- **Password policy**: Adjust password requirements based on your security needs
- **Token expiry**: Configure appropriate token lifetimes for your use case

## Roadmap

See `CREATE.md` for planned features:
- MFA with TOTP
- SSO with OpenID Connect
- Passwordless authentication (WebAuthn)
- Admin dashboard
- Security features (brute force protection, anomaly detection)
- Audit logging
- Webhook system

## License

See LICENSE file.

## Support

For issues or questions, open an issue on the repository.


curl -X POST http://localhost:8000/api/users/invite -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1YTQyMTAxNC03NjkzLTQ5ODYtOTA0Yi0yYmE5ZThiNmQzNjciLCJlbWFpbCI6ImRjb25zb25uaUBnbWFpbC5jb20iLCJzY29wZXMiOlsicmVhZCIsIndyaXRlIiwiYWRtaW4iXSwiZXhwIjoxNzU5NDQ3NjE1LCJpYXQiOjE3NTk0NDU4MTUsInRva2VuX3R5cGUiOiJhY2Nlc3MifQ.jGzZ1g39ijAGbigQLGp3DXdDmiveSCXrLJXub80AaSU" -H "Content-Type: application/json" -d"{\"email\":\"newuser@example.com\",\"scopes\":[\"read\"],\"first_name\":\"Test\",\"last_name\":\"User\"}"
