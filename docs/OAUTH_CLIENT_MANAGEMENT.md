# OAuth2 Client Management

This document outlines the dynamic OAuth2 client management system in AuthGlow, which replaces a static, hardcoded client with a flexible and scalable database-driven approach.

---

## 🎯 Core Features

### 1. **Dynamic Client Registration**
-   **Full CRUD API:** Administrators can create, read, update, and delete OAuth2 clients programmatically.
-   **Secure Secret Handling:** Client secrets are generated with high entropy and stored as `bcrypt` hashes. The plaintext secret is only ever revealed upon creation or rotation.
-   **Client Lifecycle Management:** Clients can be activated or deactivated, and their secrets can be rotated via the API.

### 2. **Flexible Client Configuration**
-   **Multiple Redirect URIs:** Each client can be configured with a list of allowed redirect URIs for enhanced security.
-   **Scoped Permissions:** Administrators can define which permission scopes (e.g., `read`, `write`, `profile`) a client is allowed to request.
-   **Grant Type Control:** Clients can be restricted to specific grant types (`authorization_code`, `client_credentials`, `refresh_token`).
-   **Custom Token Lifetimes:** Set custom expiration times for access and refresh tokens on a per-client basis.

### 3. **Enhanced Security**
-   **Admin-Only Management:** All client management endpoints are protected and require administrator privileges.
-   **Rate Limiting:** API endpoints for client management are rate-limited to prevent abuse.
-   **Comprehensive Auditing:** All actions performed on an OAuth2 client are recorded in the audit log.

---

## 📋 API Endpoints

All client management endpoints are available under the base path `/api/oauth-clients` and require administrator authentication.

| Method | Endpoint                  | Description                                          |
| ------ | ------------------------- | ---------------------------------------------------- |
| `POST` | `/`                       | Create a new OAuth2 client.                          |
| `GET`  | `/`                       | List all registered OAuth2 clients.                  |
| `GET`  | `/{client_id}`            | Get detailed information for a specific client.      |
| `PUT`  | `/{client_id}`            | Update a client's configuration.                     |
| `DELETE`| `/{client_id}`           | Permanently delete a client.                         |
| `POST` | `/{client_id}/rotate-secret`| Generate a new secret for a client.                  |
| `POST` | `/{client_id}/activate`   | Activate a client.                                   |
| `POST` | `/{client_id}/deactivate` | Deactivate a client, preventing it from being used.  |

---

## 💡 Usage Examples

### 1. Create a New Client

This request creates a new confidential client for a standard web application.

```bash
curl -X POST "http://localhost:8000/api/oauth-clients" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d 
itro{
    "client_name": "My Web App",
    "redirect_uris": ["https://myapp.com/callback"],
    "allowed_scopes": ["openid", "profile", "email"],
    "grant_types": ["authorization_code", "refresh_token"]
  }
```

**Response (Save the `client_secret` value immediately!):**
```json
{
  "client_id": "a1b2c3d4-...",
  "client_secret": "SECRET_IS_ONLY_SHOWN_ONCE",
  "client_name": "My Web App",
  ...
}
```

### 2. List All Active Clients

```bash
curl "http://localhost:8000/api/oauth-clients?active_only=true" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

### 3. Rotate a Client Secret

If a secret is compromised, you can issue a new one.

```bash
curl -X POST "http://localhost:8000/api/oauth-clients/{client_id}/rotate-secret" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

**Response (Save the `new_client_secret` value immediately!):**
```json
{
  "client_id": "a1b2c3d4-...",
  "new_client_secret": "NEW_SECRET_IS_ONLY_SHOWN_ONCE"
}
```

---

## 🔐 Security & Architecture

-   **Storage:** Client configurations are stored as JSON files in the configured storage backend (`data/oauth_clients/` by default). This is compatible with `fsspec` backends like S3 and GCS.
-   **Secret Hashing:** Client secrets are handled with the same `bcrypt` hashing mechanism as user passwords, ensuring they are never stored in plaintext.
-   **Validation:** The core `OAuth2Service` dynamically loads client details from storage to validate incoming authorization requests against the correct `redirect_uri`, `scope`, and `grant_type`.

##  backward Compatibility

The system maintains backward compatibility with the static client defined in environment variables. If a `client_id` from an authorization request is not found in the dynamic storage, the system will fall back to checking the static configuration. This allows for a seamless transition from a single hardcoded client to the dynamic system.