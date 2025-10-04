# Configuration

AuthGlow is configured using environment variables. For a basic setup, you can copy the provided `.env.example` file to `.env` and start the application. For any production or serious use, it is crucial to review and customize these settings.

---

## General & Server Settings

These variables control the core behavior and network bindings of the application.

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `APP_NAME` | The name of the application, used in titles and emails. | `AuthGlow` | No |
| `APP_ENV` | The application environment. Set to `production` to disable debug features. | `development` | No |
| `DEBUG` | Toggles debug mode. **Must be `false` in production.** | `true` | No |
| `BASE_URL` | The public URL of your AuthGlow instance. This is critical for generating correct links in emails and for OIDC discovery. | `http://localhost:8000` | **Yes** |
| `HOST` | The IP address the server binds to. `0.0.0.0` is recommended for Docker. | `0.0.0.0` | No |
| `PORT` | The port the server listens on. | `8000` | No |

---

## Security Settings

These are critical for securing your AuthGlow instance. **Change them in production.**

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `SECRET_KEY` | A long, random string for cryptographic signing (e.g., session cookies). Min 32 chars. | (none) | **Yes** |
| `JWT_SECRET_KEY` | A long, random string for signing JSON Web Tokens (JWTs). Min 32 chars. | (none) | **Yes** |
| `JWT_ALGORITHM` | The algorithm for signing JWTs. | `HS256` | **Yes** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | The lifespan of an access token in minutes. | `30` | No |
| `REFRESH_TOKEN_EXPIRE_DAYS` | The lifespan of a refresh token in days. | `7` | No |

---

## Storage Settings

Configure where AuthGlow stores its data. The default is the local filesystem.

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `STORAGE_BACKEND` | The storage backend. Options: `file`, `s3`, `gcs`, `abfs`. | `file` | **Yes** |
| `STORAGE_PATH` | The path for data storage (local directory or cloud bucket path). | `./data/users` | **Yes** |

*Note: For cloud storage, you must also set provider-specific credentials like `AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS`, etc., in the environment.*

---

## OAuth 2.0 / OpenID Connect (OIDC)

Configure the OIDC provider functionality.

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `ISSUER` | The OIDC issuer URL. **Must match `BASE_URL`** for OIDC discovery to work. | `http://localhost:8000` | **Yes** |
| `OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES` | The lifespan of an authorization code in minutes. | `10` | No |

---

## Passkey (WebAuthn) Settings

Configure the settings for passwordless authentication.

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `PASSKEY_RP_ID` | The Relying Party ID. In production, this **must be your domain name** (e.g., `auth.example.com`). | `localhost` | **Yes** |
| `PASSKEY_RP_NAME` | The name of your application shown to the user during passkey creation. | `AuthGlow` | **Yes** |
| `PASSKEY_ORIGIN` | The origin URL of your application. **Must match `BASE_URL`** in production. | `http://localhost:8000` | **Yes** |

---

## Email Settings

Configure how transactional emails (verification, password reset, etc.) are sent.

| Variable | Description | Default | Required |
| --- | --- | --- | --- |
| `EMAIL_BACKEND` | `console` (prints to terminal), `file_storage` (saves to disk), `smtp`, `sendgrid`, `mailgun`. | `console` | **Yes** |
| `EMAIL_FROM_ADDRESS`| The "From" email address for outgoing emails. | `noreply@authglow.example.com` | **Yes** |
| `EMAIL_FROM_NAME` | The "From" name for outgoing emails. | `AuthGlow` | No |
| `EMAIL_STORAGE_PATH`| Directory to save emails if `EMAIL_BACKEND` is `file_storage`. | `data/users/emails` | No |

### SMTP Configuration
*Required if `EMAIL_BACKEND=smtp`*
- `SMTP_HOST`
- `SMTP_PORT` (e.g., 587)
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_USE_TLS` (`true` or `false`)

### Third-Party Email Services
- **SendGrid** (`EMAIL_BACKEND=sendgrid`): Requires `SENDGRID_API_KEY`.
- **Mailgun** (`EMAIL_BACKEND=mailgun`): Requires `MAILGUN_API_KEY` and `MAILGUN_DOMAIN`.

---

## Password Policy

Define complexity requirements for user passwords.

| Variable | Description | Default |
| --- | --- | --- |
| `PASSWORD_MIN_LENGTH` | Minimum number of characters. | `8` |
| `PASSWORD_REQUIRE_UPPERCASE` | Must contain an uppercase letter. | `true` |
| `PASSWORD_REQUIRE_LOWERCASE` | Must contain a lowercase letter. | `true` |
| `PASSWORD_REQUIRE_DIGITS` | Must contain a number. | `true` |
| `PASSWORD_REQUIRE_SPECIAL` | Must contain a special character. | `true` |

---

## UI Customization

Customize the look and feel of the AuthGlow user interface.

| Variable | Description | Default |
| --- | --- | --- |
| `UI_COMPANY_NAME` | Name displayed in the UI and emails. | `AuthGlow` |
| `UI_SUPPORT_EMAIL` | Contact email for support inquiries. | `support@example.com` |
| `UI_PRIVACY_POLICY_URL` | Link to your privacy policy. Hidden if empty. | (empty) |
| `UI_TERMS_OF_SERVICE_URL`| Link to your terms of service. Hidden if empty. | (empty) |
| `UI_LOGO_URL` | Path to the logo for light mode. | (default logo) |
| `UI_LOGO_DARK_URL` | Path to the logo for dark mode. | (default logo) |
| `UI_PRIMARY_COLOR` | Primary theme color (hex code). | `#3498DB` |