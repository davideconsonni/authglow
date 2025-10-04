# AuthGlow ✨

AuthGlow is a modern, lightweight, and stateless Identity and Access Management (IAM) solution designed for developers. It provides a complete authentication and user management system that you can run anywhere, from a local machine to a serverless environment.

Built with FastAPI and a flexible `fsspec` storage backend, it supports everything from local file storage for development to S3, Google Cloud Storage, and Azure Blob Storage for production.

---

## 🚀 Key Features

*   **Modern Authentication:**
    *   🔐 **OAuth2 & OpenID Connect:** Secure, standard-based flows for your applications.
    *   🔑 **Passkeys (WebAuthn/FIDO2):** Phishing-resistant, passwordless authentication.
    *   📱 **Multi-Factor Authentication (MFA):** TOTP-based 2FA with QR code setup and backup codes.
*   **Complete User Management:**
    *   👤 **Admin Portal:** A clean, intuitive UI to manage users, view audit logs, and monitor activity.
    *   📧 **Email-Based Workflows:** User invitations, email verification, and password resets.
*   **Developer-Friendly & Flexible:**
    *   🎨 **Customizable Frontend:** Easily change the look and feel with a beige-based, light/dark theme.
    *   ☁️ **Cloud-Native:** Stateless design ready for serverless deployment (AWS Lambda, Google Cloud Run, etc.).
    *   🗄️ **Pluggable Storage:** Use the local filesystem, S3, GCS, or Azure Blob Storage.
*   **Secure by Design:**
    *   📜 **Comprehensive Audit Trails:** Log every important security event.
    *   💪 **Configurable Password Policies:** Enforce strong password requirements.
    *   🔑 **API Key Management:** Securely authenticate machine-to-machine (M2M) services.

---

## 🏁 Getting Started (5 Minutes)

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your-repo/authglow.git
    cd authglow
    ```

2.  **Set Up a Virtual Environment**
    ```bash
    python -m venv .venv
    # On Windows
    .venv\Scripts\activate
    # On macOS/Linux
    source .venv/bin/activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Your Environment**
    Create a `.env` file in the root directory and add the following minimal configuration. **Please use your own secure keys.**

    ```env
    # .env
    SECRET_KEY=generate-a-secure-random-string-32-chars
    JWT_SECRET_KEY=generate-another-secure-random-string-32-chars
    EMAIL_BACKEND=file_storage
    ```
    *Setting `EMAIL_BACKEND=file_storage` will save outgoing emails as `.eml` files in `data/users/emails` for easy development.*

5.  **Run the Application**
    ```bash
    python main.py
    ```
    Your AuthGlow instance is now running at `http://localhost:8000`.

    - **API Docs:** `http://localhost:8000/docs`
    - **Admin Portal:** `http://localhost:8000/admin`

---

## 📦 What's Inside?

### The Admin Portal

AuthGlow comes with a built-in admin portal to manage your users and monitor your application's security.

*   **Dashboard:** Get a quick overview of user sign-ups, login activity, and security events.
*   **User Management:** View, edit, and manage all your users. Deactivate accounts, reset MFA, and more.
*   **Audit Logs:** A detailed, searchable log of every important event that happens in the system.
*   **API Playground:** An interactive tool to test OAuth2, OpenID Connect, and other API flows directly from the browser.

*To access the admin portal, you'll first need to create an admin user. See the [User Management Documentation](docs/USER_MANAGEMENT.md) for instructions.*

### Core Technologies

*   **Backend:** FastAPI
*   **Authentication:** OAuth2, OpenID Connect, Passkeys (WebAuthn)
*   **Data Storage:** `fsspec` (File System, S3, GCS, Azure Blob)
*   **Frontend:** Jinja2 templates with vanilla JavaScript.

---

## ⚙️ Configuration

AuthGlow is configured via environment variables in your `.env` file. Here are a few key settings:

| Variable                      | Description                                                              | Default                               |
| ----------------------------- | ------------------------------------------------------------------------ | ------------------------------------- |
| `SECRET_KEY`                  | A long, random string for application security. **(Required)**           | `""`                                  |
| `JWT_SECRET_KEY`              | A long, random string for signing JWTs. **(Required)**                   | `""`                                  |
| `EMAIL_BACKEND`               | How to handle emails: `console` or `file_storage`.                       | `"console"`                           |
| `STORAGE_BACKEND`             | Where to store data: `file`, `s3`, `gcs`, `abfs`.                        | `"file"`                              |
| `STORAGE_PATH`                | The root directory or bucket for data storage.                           | `"data/users"`                        |
| `PASSKEY_RP_ID`               | Your domain name for Passkey security.                                   | `"localhost"`                         |
| `PASSKEY_ORIGIN`              | The full origin URL where the app is hosted.                             | `"http://localhost:8000"`             |

*For a full list of configuration options, see the `.env.example` file.*

---

## 📚 Deeper Dives

*   [API Key Management](docs/API_KEYS.md)
*   [User Invitation and Management](docs/USER_MANAGEMENT.md)
*   [OAuth2 & OIDC Flows](docs/OAUTH_CLIENT_MANAGEMENT.md)
*   [Password Reset Flow](docs/PASSWORD_RESET.md)
*   [Testing Guide](docs/TESTING.md)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
