# API Keys - Implementazione Completa ✅

## Panoramica

Sistema completo di gestione API Keys per AuthGlow, che permette agli utenti di generare chiavi API per accesso programmatico alle risorse.

## 🎯 Funzionalità Implementate

### 1. **Modello Dati API Key**
File: `authglow/models/api_key.py`

- ✅ Key ID (UUID auto-generato)
- ✅ Key Prefix (primi 12 caratteri per display)
- ✅ Key Hash (bcrypt-hashed full key)
- ✅ User ID (proprietario)
- ✅ Name & Description
- ✅ Scopes (permissions)
- ✅ Expiration (configurable o never expires)
- ✅ IP restrictions (whitelist opzionale)
- ✅ Usage tracking (last_used_at, total_requests)
- ✅ Status (active/inactive)
- ✅ Audit fields (created_by, revoked_at, revoked_by)

### 2. **Storage Service**
File: `authglow/services/api_key.py`

- ✅ CRUD operations
- ✅ API key generation (`ak_<32 random chars>`)
- ✅ API key hashing (bcrypt)
- ✅ API key verification
- ✅ Prefix-based lookup (fast)
- ✅ Expiration checking
- ✅ IP restriction enforcement
- ✅ Usage tracking
- ✅ Cleanup expired keys
- ✅ File-based storage (fsspec)

### 3. **Authentication**
File: `authglow/api/auth.py`

- ✅ Dual authentication support (JWT + API Key)
- ✅ `X-API-Key` header support
- ✅ Automatic usage tracking
- ✅ Scope enforcement
- ✅ Audit logging
- ✅ IP validation

### 4. **API Endpoints**
File: `authglow/api/api_key.py`

**Base path**: `/api/keys`

#### User Endpoints:

1. **POST `/api/keys`**
   - Create new API key
   - Returns plaintext key (only once!)
   - Rate limit: 10/hour
   - Requires: Authenticated user

2. **GET `/api/keys`**
   - List own API keys
   - Returns: List of keys (no secrets)
   - Requires: Authenticated user

3. **GET `/api/keys/{key_id}`**
   - Get specific API key details
   - Requires: Owner or admin

4. **PATCH `/api/keys/{key_id}`**
   - Update API key (name, description, scopes, etc.)
   - Rate limit: 30/hour
   - Requires: Owner or admin

5. **POST `/api/keys/{key_id}/revoke`**
   - Revoke API key (deactivate)
   - Rate limit: 20/hour
   - Requires: Owner or admin

6. **DELETE `/api/keys/{key_id}`**
   - Permanently delete API key
   - Rate limit: 20/hour
   - Requires: Owner or admin

#### Admin Endpoints:

7. **GET `/api/admin/keys`**
   - List all API keys
   - Pagination support
   - Filter by active status
   - Requires: Admin

8. **GET `/api/admin/users/{user_id}/keys`**
   - List API keys for specific user
   - Requires: Admin

9. **POST `/api/admin/keys/cleanup`**
   - Delete expired & inactive keys
   - Requires: Admin

### 5. **Security Features**

- ✅ API key hashed with bcrypt (never stored in plaintext)
- ✅ Prefix-based lookup for performance
- ✅ Rate limiting on all operations
- ✅ Audit logging for all actions
- ✅ Expiration support (1-365 days or never)
- ✅ IP whitelist support
- ✅ Scope-based permissions
- ✅ Automatic cleanup of expired keys
- ✅ Owner-only access (unless admin)

## 📋 API Key Format

```
ak_<32 random url-safe characters>
```

Example: `ak_8Kx3Nz9mQ1vR7jL5pW2uT6bY4hD0fC1`

- Prefix: `ak_8Kx3Nz9m` (first 12 chars for display)
- Generated with `secrets.token_urlsafe(32)` (256 bits of entropy)

## 💡 Usage Examples

### 1. Create API Key

```bash
curl -X POST "http://localhost:8000/api/keys" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API",
    "description": "API key for production deployment",
    "scopes": ["read", "write"],
    "expires_in_days": 90,
    "allowed_ips": ["203.0.113.0", "198.51.100.0"]
  }'
```

Response:
```json
{
  "key_id": "123e4567-e89b-12d3-a456-426614174000",
  "api_key": "ak_8Kx3Nz9mQ1vR7jL5pW2uT6bY4hD0fC1",  // SAVE THIS!
  "key_prefix": "ak_8Kx3Nz9m",
  "name": "Production API",
  "scopes": ["read", "write"],
  "expires_at": "2026-01-02T00:00:00",
  ...
}
```

### 2. Use API Key

```bash
curl "http://localhost:8000/api/users/me" \
  -H "X-API-Key: ak_8Kx3Nz9mQ1vR7jL5pW2uT6bY4hD0fC1"
```

### 3. List Your Keys

```bash
curl "http://localhost:8000/api/keys" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 4. Revoke Key

```bash
curl -X POST "http://localhost:8000/api/keys/{key_id}/revoke" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🔒 Security Best Practices

1. **Never commit API keys** to version control
2. **Store keys securely** (environment variables, secret managers)
3. **Use short expiration** for high-security environments
4. **Enable IP restrictions** when possible
5. **Rotate keys regularly** (especially after exposure)
6. **Use minimal scopes** (principle of least privilege)
7. **Revoke unused keys** immediately
8. **Monitor usage** via audit logs

## 🔄 Key Lifecycle

1. **Creation**: User creates key → Plaintext shown once → Hash stored
2. **Usage**: Client sends key → System verifies hash → Tracks usage
3. **Expiration**: System checks expiration on each request
4. **Revocation**: Owner/admin revokes → Key deactivated
5. **Cleanup**: Admin cleanup removes expired inactive keys

## 📊 Audit Events

All API key actions are logged:

- `api_key_created` - New key generated
- `api_key_used` - Key used for authentication
- `api_key_updated` - Key settings changed
- `api_key_revoked` - Key deactivated
- `api_key_deleted` - Key permanently removed
- `api_keys_cleanup` - Batch cleanup executed

## 🎨 Admin UI

**TODO**: Create admin interface for:
- View all API keys across users
- Search/filter by user, status, expiration
- Bulk revocation
- Usage statistics dashboard
- Alert on suspicious activity

## 🔧 Configuration

API key settings in `authglow/core/config.py`:

```python
# Storage path
storage_path: str = "../data/users"  # Keys stored in {storage_path}/api_keys/

# Rate limiting (via slowapi)
# Create: 10/hour per IP
# Update: 30/hour per IP
# Revoke/Delete: 20/hour per IP
```

## 📈 Performance

- **Fast lookup**: Prefix-based filtering before hash verification
- **Scalable**: File-based storage works with S3/GCS/Azure
- **Efficient**: Bcrypt verification only on prefix matches

## 🚀 Future Enhancements

1. **Usage Analytics**
   - Request counts per endpoint
   - Response time tracking
   - Error rate monitoring

2. **Advanced Restrictions**
   - Time-based access (only during business hours)
   - Endpoint-specific permissions
   - Rate limiting per key

3. **Notifications**
   - Email on key creation
   - Alert on unusual activity
   - Expiration reminders

4. **Key Rotation**
   - Automatic rotation policies
   - Dual-key period for zero-downtime rotation

## ✅ Testing

```bash
# Create a key
curl -X POST http://localhost:8000/api/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Key","scopes":["read"]}'

# Use the key
curl http://localhost:8000/api/users/me \
  -H "X-API-Key: <your-key>"

# Verify it works!
```

## 📚 Integration Examples

### Python
```python
import requests

API_KEY = "ak_8Kx3Nz9mQ1vR7jL5pW2uT6bY4hD0fC1"
BASE_URL = "http://localhost:8000"

headers = {"X-API-Key": API_KEY}
response = requests.get(f"{BASE_URL}/api/users/me", headers=headers)
print(response.json())
```

### JavaScript
```javascript
const API_KEY = "ak_8Kx3Nz9mQ1vR7jL5pW2uT6bY4hD0fC1";
const BASE_URL = "http://localhost:8000";

fetch(`${BASE_URL}/api/users/me`, {
  headers: {
    "X-API-Key": API_KEY
  }
})
.then(res => res.json())
.then(data => console.log(data));
```

### cURL
```bash
API_KEY="ak_8Kx3Nz9mQ1vR7jL5pW2uT6bY4hD0fC1"
curl "http://localhost:8000/api/users/me" \
  -H "X-API-Key: $API_KEY"
```

---

**Status**: ✅ Backend completamente implementato | ⏳ Admin UI da completare
