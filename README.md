# AuthGlow

Serverless Customer Identity and Access Management (CIAM) system with OAuth2 support.

## Features

### Core Authentication
- **OAuth2 Support**: Full implementation of OAuth2 with multiple grant types
  - Authorization Code Flow (for web applications)
  - Client Credentials Flow (for service-to-service)
  - Refresh Token Flow
- **JWT Tokens**: Secure, stateless authentication with JWT
- **WebAuthn/Passkeys**: Passwordless authentication with biometrics or security keys
  - FIDO2 compliant
  - Cross-platform and platform authenticators
  - Synced passkeys support
- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA
  - QR code generation
  - Backup codes
  - Recovery options
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

### Admin Portal
- **User Management**: Create, edit, deactivate users
- **Dashboard**: User statistics and activity metrics
- **Audit Logs**: Complete security event logging
- **MFA Management**: Reset user MFA settings
- **Passkey Overview**: View user passkey registrations

### Customizable UI
- Responsive login interface with dark/light mode
- Fully customizable via environment variables:
  - Colors (primary, secondary, background, text)
  - Logo (light and dark variants)
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

### Using Passkeys (WebAuthn)

#### Requirements
- **HTTPS required in production** (localhost works for development)
- Modern browser with WebAuthn support (Chrome, Firefox, Safari, Edge)
- Compatible authenticator:
  - Built-in (Touch ID, Face ID, Windows Hello)
  - External security key (YubiKey, etc.)
  - Phone/tablet with passkey sync

#### Registering a Passkey

1. Login to your account
2. Visit the passkey management page: `http://localhost:8000/passkeys`
3. Click "Add New Passkey"
4. Follow your browser/device prompts to create the passkey
5. Give it a friendly name (e.g., "My iPhone", "YubiKey")

#### Authenticating with Passkey

1. Go to login page: `http://localhost:8000/login`
2. Enter your email address
3. Click "Sign in with Passkey" instead of entering password
4. Authenticate using your fingerprint, face, or security key

#### API Endpoints

**Start Registration:**
```bash
curl -X POST http://localhost:8000/api/passkey/register/begin \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Complete Registration:**
```bash
curl -X POST http://localhost:8000/api/passkey/register/complete \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{...}'  # WebAuthn credential data
```

**Start Authentication:**
```bash
curl -X POST http://localhost:8000/api/passkey/auth/begin \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

**Complete Authentication:**
```bash
curl -X POST http://localhost:8000/api/passkey/auth/complete \
  -H "Content-Type: application/json" \
  -d '{...}'  # WebAuthn assertion data
```

**List User Passkeys:**
```bash
curl -X GET http://localhost:8000/api/passkey/list \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Delete Passkey:**
```bash
curl -X DELETE http://localhost:8000/api/passkey/{credential_id} \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### Using Multi-Factor Authentication (MFA)

#### Enable MFA

1. Login to your account
2. Get your MFA secret and QR code:
```bash
curl -X POST http://localhost:8000/api/mfa/setup \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

3. Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.)

4. Verify and enable MFA:
```bash
curl -X POST http://localhost:8000/api/mfa/verify \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

#### Login with MFA

After entering your password, you'll be prompted for your MFA code.

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

#### WebAuthn/Passkeys
- `PASSKEY_RP_ID`: Relying Party ID - your domain (default: "localhost")
- `PASSKEY_RP_NAME`: Relying Party name (default: "AuthGlow")
- `PASSKEY_ORIGIN`: Full origin URL (default: "http://localhost:8000")

**Production Example:**
```env
PASSKEY_RP_ID=example.com
PASSKEY_RP_NAME=My Company
PASSKEY_ORIGIN=https://auth.example.com
```

**Important:** In production, `PASSKEY_ORIGIN` must be HTTPS. Only localhost can use HTTP.

#### UI Customization
- `UI_LOGO_URL`: Custom logo URL (light theme)
- `UI_LOGO_DARK_URL`: Custom logo URL (dark theme)
- `UI_PRIMARY_COLOR`: Primary color (default: #3498DB)
- `UI_SECONDARY_COLOR`: Secondary color (default: #FF3366)
- `UI_BACKGROUND_COLOR`: Background color light mode (default: #F8F8F8)
- `UI_BACKGROUND_DARK`: Background color dark mode (default: #1A1A1A)
- `UI_TEXT_COLOR`: Text color light mode (default: #2C3E50)
- `UI_TEXT_DARK`: Text color dark mode (default: #F0F0F0)
- `UI_COMPANY_NAME`: Company name displayed in UI
- `UI_SUPPORT_EMAIL`: Support contact email
- `UI_PRIVACY_POLICY_URL`: Privacy policy link
- `UI_TERMS_OF_SERVICE_URL`: Terms of service link

## Project Structure

```
authglow/
├── authglow/
│   ├── api/              # API endpoints
│   │   ├── auth.py       # Authentication routes
│   │   ├── mfa.py        # MFA endpoints
│   │   ├── admin.py      # Admin portal endpoints
│   │   └── passkey.py    # WebAuthn/Passkey endpoints
│   ├── core/             # Core functionality
│   │   └── config.py     # Configuration management
│   ├── models/           # Data models
│   │   ├── user.py       # User models
│   │   ├── token.py      # Token models
│   │   ├── mfa.py        # MFA models
│   │   ├── passkey.py    # Passkey models
│   │   └── admin.py      # Admin models
│   ├── services/         # Business logic
│   │   ├── storage.py    # User storage (fsspec)
│   │   ├── password.py   # Password validation
│   │   ├── jwt.py        # JWT token service
│   │   ├── oauth2.py     # OAuth2 service
│   │   ├── mfa.py        # MFA service
│   │   ├── passkey.py    # Passkey service
│   │   ├── session.py    # Session management
│   │   └── audit.py      # Audit logging
│   ├── templates/        # HTML templates
│   │   ├── login.html    # Login page
│   │   ├── admin_*.html  # Admin portal pages
│   │   ├── mfa_*.html    # MFA pages
│   │   └── passkey_*.html # Passkey management
│   └── static/           # Static files
│       ├── css/
│       │   └── theme.css # Theme with dark/light mode
│       ├── js/
│       │   └── theme.js  # Theme switcher
│       └── images/       # Logos
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
- **Use HTTPS**: Always use HTTPS in production (required for WebAuthn/Passkeys)
- **Secure storage**: Use cloud storage with proper IAM roles/permissions
- **Password policy**: Adjust password requirements based on your security needs
- **Token expiry**: Configure appropriate token lifetimes for your use case
- **WebAuthn domain**: Ensure `PASSKEY_RP_ID` matches your domain exactly
- **Passkey phishing resistance**: Passkeys are bound to your domain and cannot be phished
- **MFA backup codes**: Store backup codes securely when enabling MFA
- **Audit logs**: Review audit logs regularly for suspicious activity

## Admin Portal

Access the admin portal at `http://localhost:8000/admin`

Features:
- **Dashboard**: View user statistics, recent activity, and security events
- **User Management**: Create, edit, and deactivate user accounts
- **Audit Logs**: Complete history of authentication events and admin actions
- **MFA Management**: Reset user MFA settings when needed
- **Passkey Overview**: See which users have passkeys registered

Default admin user must be created manually (see "Creating the First Admin User" section).

## Roadmap

Completed features:
- ✅ MFA with TOTP
- ✅ Passwordless authentication (WebAuthn/Passkeys)
- ✅ Admin dashboard
- ✅ Audit logging

Planned features:
- SSO with OpenID Connect
- Security features (brute force protection, anomaly detection)
- Webhook system
- Email notifications
- Session management
- Advanced role-based access control (RBAC)

## License

See LICENSE file.

## Support

For issues or questions, open an issue on the repository.

## FAQ

### Can I use passkeys on mobile devices?
Yes! Passkeys work on iOS 16+, Android 9+, and modern browsers. They can sync across your devices via iCloud Keychain (Apple) or Google Password Manager (Android).

### What happens if I lose my passkey device?
- If using synced passkeys (iCloud/Google): Your passkeys are automatically available on your other devices
- If using a security key: Register multiple passkeys as backup, or use password + MFA as fallback
- Admin can reset your passkeys from the admin portal

### Can I use both password and passkey?
Yes! Passkeys are an additional authentication method. You can use either password or passkey to login.

### Is WebAuthn secure?
Yes! WebAuthn is a W3C standard that provides strong, phishing-resistant authentication. Private keys never leave your device, and passkeys are bound to your specific domain.

### Do I need special hardware?
No! Most modern devices support passkeys with built-in biometrics (fingerprint, face recognition). External security keys (YubiKey) are optional.
