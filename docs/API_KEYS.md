# API Key Management

This document outlines the complete API key management system for AuthGlow, allowing users and services to generate keys for programmatic access to resources.

---

## 🎯 Core Features

### 1. **Secure by Design**
- **Hashed Storage:** Keys are never stored in plaintext. The full key is hashed using `bcrypt`, and only the hash is stored.
- **Short Prefixes:** A non-sensitive 12-character prefix (e.g., `ak_...`) is stored for display and quick identification.
- **Rate Limiting:** All API key operations (create, update, delete) are rate-limited to prevent abuse.
- **Audit Trails:** Every action related to an API key is logged for security monitoring.

### 2. **Flexible and Controllable**
- **Scoped Permissions:** Keys can be granted specific permissions (e.g., `read`, `write`, `admin`) to enforce the principle of least privilege.
- **Expiration Policies:** Keys can be configured to expire after a set number of days (1-365) or to never expire.
- **IP Whitelisting:** Access can be restricted to a specific list of IP addresses for enhanced security.

### 3. **Developer-Friendly API**
- **Dual Authentication:** The system seamlessly handles authentication via both JWT Bearer tokens and API keys.
- **Simple Key Usage:** API keys can be passed in the `Authorization: Bearer <key>` header or an `X-API-Key: <key>` header.
- **Full Management via API:** All aspects of the key lifecycle, from creation to revocation, are manageable through a RESTful API.

---

## 🔑 API Key Format

A generated API key consists of a prefix and a random, URL-safe string.

```
ak_<32 random url-safe characters>
```
**Example:** `ak_8Kx3Nz9mQ1vR7jL5pW2uT6bY4hD0fC1`

- The key has 256 bits of entropy, generated using Python's `secrets` module.
- The plaintext key is **only shown once** upon creation. You must save it securely.

---

## 🔄 Key Lifecycle

1.  **Creation:** A user generates a key via the API. The plaintext key is returned, and its `bcrypt` hash is stored.
2.  **Usage:** A client sends the API key in a header. The system finds the corresponding hash and verifies the key.
3.  **Tracking:** On successful verification, usage metadata (last used time, IP, request count) is updated.
4.  **Revocation:** A user or admin revokes the key, deactivating it immediately.
5.  **Deletion:** A user or admin permanently deletes the key from the system.

---

## 📋 API Endpoints

The following endpoints are available for managing API keys.

### User Endpoints
Base path: `/api/keys`

| Method | Endpoint              | Description                               |
| ------ | --------------------- | ----------------------------------------- |
| `POST` | `/`                   | Create a new API key.                     |
| `GET`  | `/`                   | List all API keys owned by the user.      |
| `GET`  | `/{key_id}`           | Get details for a specific key.           |
| `PATCH`| `/{key_id}`           | Update a key's name, scopes, etc.         |
| `POST` | `/{key_id}/revoke`    | Revoke (deactivate) a key.                |
| `DELETE`| `/{key_id}`          | Permanently delete a key.                 |

### Admin Endpoints
Base path: `/api/admin/keys`

| Method | Endpoint                  | Description                               |
| ------ | ------------------------- | ----------------------------------------- |
| `GET`  | `/`                       | List all API keys across all users.       |
| `GET`  | `/users/{user_id}/keys`   | List all keys for a specific user.        |
| `POST` | `/cleanup`                | Permanently delete all expired keys.      |

---

## 💡 Usage Examples

### 1. Create an API Key

```bash
curl -X POST "http://localhost:8000/api/keys" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d 
  {
    "name": "Production Service Key",
    "scopes": ["read", "write"],
    "expires_in_days": 90,
    "allowed_ips": ["203.0.113.50"]
  }
```

**Response (Save the `api_key` value immediately!):**
```json
{
  "key_id": "a1b2c3d4-...",
  "api_key": "ak_8Kx3Nz9mQ1vR7jL5pW2uT6bY4hD0fC1",
  "key_prefix": "ak_8Kx3Nz9m",
  "name": "Production Service Key",
  "scopes": ["read", "write"],
  "expires_at": "2025-12-31T23:59:59Z",
  ...
}
```

### 2. Authenticate with an API Key

You can use either the `Authorization` header (recommended) or the `X-API-Key` header.

**Using Authorization Header:**
```bash
curl "http://localhost:8000/api/profile/me" \
  -H "Authorization: Bearer ak_8Kx3Nz9mQ1vR7jL5pW2uT6bY4hD0fC1"
```

**Using X-API-Key Header:**
```bash
curl "http://localhost:8000/api/profile/me" \
  -H "X-API-Key: ak_8Kx3Nz9mQ1vR7jL5pW2uT6bY4hD0fC1"
```

### 3. Revoke an API Key

```bash
curl -X POST "http://localhost:8000/api/keys/{key_id}/revoke" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## 🔒 Security Best Practices

-   **Treat keys like passwords.** Never commit them to version control or expose them in client-side code.
-   **Use a secrets manager** or environment variables to store keys securely.
-   **Prefer short-lived keys** and rotate them regularly.
-   **Apply the principle of least privilege** by assigning only the necessary scopes.
-   **Use IP address restrictions** whenever possible to limit where a key can be used.
-   **Monitor audit logs** for unusual activity related to your keys.
