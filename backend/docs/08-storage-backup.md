# Storage & Backup Guide

This guide explains how AuthGlow stores data, the file-based architecture, cloud storage options, and how to perform backups and migrations.

---

## Overview: File-Based Storage

AuthGlow uses a **file-based storage system** powered by [fsspec](https://filesystem-spec.readthedocs.io/), making it extremely portable and easy to manage. All application data is stored as JSON files in a structured directory hierarchy.

### Why File-Based Storage?

- **Simplicity**: No database server to configure, maintain, or secure
- **Transparency**: All data is human-readable JSON
- **Portability**: Copy the `data/` directory to migrate your entire system
- **Backup-Friendly**: Standard file backup tools work perfectly
- **Cloud-Ready**: fsspec supports local files, S3, GCS, and Azure Blob Storage

### Trade-offs

File-based storage is excellent for small to medium deployments but has some limitations:

- **Concurrency**: Not optimized for extremely high concurrent write operations
- **Scaling**: For very large user bases (100k+ users), a traditional database may perform better
- **Queries**: Complex queries across users require reading multiple files

---

## Directory Structure

By default, AuthGlow stores all data in the `./data/users` directory. Here's the complete structure:

```
data/
├── keys/
│   ├── private_key.pem               # 🔴 CRITICAL: RSA private key for signing tokens
│   └── public_key.pem                # RSA public key for verification
│
└── users/
    ├── {user_id}.json                # User account files
    ├── email_index.json              # Email-to-UserID lookup index
    │
    ├── api_keys/
    │   └── {api_key_id}.json        # API key records
    │
    ├── audit_logs/
    │   └── {year}/
    │       └── {month}/
    │           └── {log_id}.json        # Audit log entries (organized by date)
    │
    ├── challenges/
    │   └── {challenge_id}.json          # WebAuthn challenges (temporary)
    │
    ├── email_verifications/
    │   └── {token}.json                 # Email verification tokens
    │
    ├── emails/                          # Sent emails (if EMAIL_BACKEND=file_storage)
    │   └── {timestamp}_{id}.json
    │
    ├── mfa/
    │   ├── backup_codes/
    │   │   └── {user_id}.json           # MFA backup codes
    │   └── trusted_devices/
    │       └── {device_id}.json         # Trusted device records
    │
    ├── oauth_clients/
    │   └── {client_id}.json             # OAuth2 client configurations
    │
    ├── oauth_consents/
    │   └── {user_id}_{client_id}.json   # User consent records
    │
    ├── passkeys/
    │   └── {user_id}_{credential_id}.json  # WebAuthn credentials
    │
    ├── password_resets/
    │   └── {token}.json                 # Password reset tokens
    │
    ├── rbac/
    │   ├── permissions/
    │   │   └── {permission_id}.json     # Permission definitions
    │   ├── roles/
    │   │   └── {role_id}.json           # Role definitions
    │   └── user_roles/
    │       └── {user_id}.json           # User-to-role assignments
    │
    ├── refresh_tokens/
    │   └── {token_hash}.json            # OAuth2 refresh tokens
    │
    ├── sessions/
    │   └── {session_id}.json            # User session data
    │
    └── user_preferences/
        └── {user_id}.json               # User UI preferences
```

> **⚠️ CRITICAL: Back Up Your `keys` Directory**
>
> The `data/keys` directory contains the RSA private key used to sign all JWTs (Access Tokens and ID Tokens).
>
> - **If you lose this key, all previously issued tokens will become invalid.**
> - **If this key is compromised, an attacker can sign their own valid tokens.**
>
> Treat this directory with the same level of security as a database password. Ensure it is included in your backup strategy and that access to it is strictly controlled.

### Key Files Explained

#### User Files (`{user_id}.json`)
Each user has a single JSON file containing their complete profile:

```json
{
  "id": "117c39e4-8191-4df8-b5ce-104d7b7ecb4a",
  "email": "user@example.com",
  "hashed_password": "$2b$12$...",
  "is_active": true,
  "created_at": "2025-10-04T07:19:17.203124",
  "updated_at": "2025-10-04T08:03:33.557548",
  "last_login": "2025-10-04T08:03:33.557544",
  "first_name": "John",
  "last_name": "Doe",
  "scopes": ["read", "write"],
  "mfa_enabled": false,
  "email_verified": true,
  "failed_login_attempts": 0,
  "locked_until": null
}
```

#### Email Index (`email_index.json`)
A mapping of email addresses to user IDs for fast lookup:

```json
{
  "user@example.com": "117c39e4-8191-4df8-b5ce-104d7b7ecb4a",
  "admin@example.com": "220bd4fc-9c88-5001-bg33-3df36c7c41f9"
}
```

#### OAuth Clients (`oauth_clients/{client_id}.json`)
OAuth2 client configurations with hashed secrets:

```json
{
  "client_id": "my-web-app",
  "client_secret": "$2b$12$hashed_secret...",
  "client_name": "My Web Application",
  "redirect_uris": ["https://myapp.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scopes": ["openid", "profile", "email"],
  "is_active": true,
  "created_at": "2025-10-01T10:00:00"
}
```

---

## Configuration

### Local File Storage (Default)

The default configuration uses the local filesystem:

```bash
# .env
STORAGE_BACKEND=file
STORAGE_PATH=./data/users
```

This is perfect for:
- Development and testing
- Small to medium deployments
- Single-server setups
- Environments where you have direct filesystem access

### Cloud Storage Backends

AuthGlow supports cloud storage through fsspec. This is ideal for:
- Serverless deployments (AWS Lambda, Azure Functions)
- Multi-region redundancy
- Automatic backups and versioning
- Shared storage across multiple instances

#### Amazon S3

```bash
# .env
STORAGE_BACKEND=s3
STORAGE_PATH=s3://my-authglow-bucket/users

# AWS Credentials
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_REGION=us-east-1
```

**Note**: Ensure your S3 bucket has appropriate permissions and is **not public**.

#### Google Cloud Storage (GCS)

```bash
# .env
STORAGE_BACKEND=gcs
STORAGE_PATH=gs://my-authglow-bucket/users

# Service Account Credentials
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
```

Alternatively, use Workload Identity or default credentials in GCP environments.

#### Azure Blob Storage

```bash
# .env
STORAGE_BACKEND=abfs
STORAGE_PATH=abfs://my-container/users

# Azure Credentials
AZURE_STORAGE_ACCOUNT_NAME=your_account_name
AZURE_STORAGE_ACCOUNT_KEY=your_account_key
```

---

## Backup Strategies

### Method 1: Simple Directory Copy (Local Storage)

The easiest backup method for local file storage:

```bash
# Create a timestamped backup
tar -czf authglow-backup-$(date +%Y%m%d-%H%M%S).tar.gz data/

# Restore from backup
tar -xzf authglow-backup-20251004-120000.tar.gz
```

**Recommended Schedule**: Daily automated backups with a retention policy.

### Method 2: rsync for Incremental Backups

For efficient incremental backups:

```bash
# Backup to remote server
rsync -avz --delete data/ backup-server:/backups/authglow/

# Restore from remote
rsync -avz backup-server:/backups/authglow/ data/
```

### Method 3: Cloud Storage Sync

#### Using AWS S3

```bash
# Backup to S3
aws s3 sync data/ s3://my-backup-bucket/authglow-backup/

# Restore from S3
aws s3 sync s3://my-backup-bucket/authglow-backup/ data/
```

#### Using Google Cloud Storage

```bash
# Backup to GCS
gsutil -m rsync -r data/ gs://my-backup-bucket/authglow-backup/

# Restore from GCS
gsutil -m rsync -r gs://my-backup-bucket/authglow-backup/ data/
```

### Method 4: Git-Based Versioning (Advanced)

For maximum auditability, you can version-control your data directory:

```bash
cd data/
git init
git add .
git commit -m "Backup $(date +%Y%m%d-%H%M%S)"

# Push to a private remote repository
git remote add backup git@github.com:yourorg/authglow-data-backup.git
git push backup main
```

**Warning**: Ensure this repository is **private** and access is strictly controlled.

---

## Migration Between Storage Backends

### From Local to S3

1. **Configure S3 backend** in `.env`:
   ```bash
   STORAGE_BACKEND=s3
   STORAGE_PATH=s3://my-authglow-bucket/users
   AWS_ACCESS_KEY_ID=...
   AWS_SECRET_ACCESS_KEY=...
   ```

2. **Sync local data to S3**:
   ```bash
   aws s3 sync ./data/users/ s3://my-authglow-bucket/users/
   ```

3. **Restart AuthGlow** - it will now use S3 as the storage backend

4. **Verify** by checking logs and testing login functionality

### From S3 to Local (Disaster Recovery)

1. **Download data from S3**:
   ```bash
   aws s3 sync s3://my-authglow-bucket/users/ ./data/users/
   ```

2. **Update `.env`**:
   ```bash
   STORAGE_BACKEND=file
   STORAGE_PATH=./data/users
   ```

3. **Restart AuthGlow**

### Between Cloud Providers

Use intermediate local storage:

```bash
# 1. Download from source
aws s3 sync s3://my-bucket/users/ ./temp-data/

# 2. Upload to destination
gsutil -m rsync -r ./temp-data/ gs://my-new-bucket/users/

# 3. Update configuration
STORAGE_BACKEND=gcs
STORAGE_PATH=gs://my-new-bucket/users
```

---

## Production Best Practices

### 1. Automated Backups

Set up automated daily backups with retention:

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backups/authglow"
RETENTION_DAYS=30

# Create backup
tar -czf "$BACKUP_DIR/authglow-$(date +%Y%m%d-%H%M%S).tar.gz" data/

# Delete old backups
find "$BACKUP_DIR" -name "authglow-*.tar.gz" -mtime +$RETENTION_DAYS -delete
```

Schedule with cron:
```cron
0 2 * * * /path/to/backup.sh
```

### 2. Off-Site Backups

Always maintain backups in a different location:
- If using local storage, sync to cloud storage
- If using cloud storage, replicate to a different region
- Consider a separate cloud provider for disaster recovery

### 3. Test Your Backups

Regularly verify that backups can be restored:

```bash
# Test restore procedure monthly
mkdir test-restore
tar -xzf latest-backup.tar.gz -C test-restore
# Verify file integrity
```

### 4. Monitor Storage Space

For local storage, monitor disk usage:

```bash
# Check storage usage
du -sh data/

# Set up alerts when usage exceeds threshold
```

### 5. Secure Your Backups

- Encrypt backup files if storing off-site
- Use encrypted S3 buckets (SSE-S3 or SSE-KMS)
- Restrict backup access with IAM policies
- Never commit data backups to public repositories

---

## Maintenance

### Cleaning Up Expired Data

AuthGlow automatically removes expired tokens and challenges, but you can perform manual cleanup:

```bash
# Remove expired password reset tokens (older than 1 hour)
find data/users/password_resets/ -name "*.json" -mmin +60 -delete

# Remove old WebAuthn challenges (older than 5 minutes)
find data/users/challenges/ -name "*.json" -mmin +5 -delete

# Remove old audit logs (older than 1 year)
find data/users/audit_logs/ -name "*.json" -mtime +365 -delete
```

### Compact Email Index

If you've deleted many users, rebuild the email index:

```python
# rebuild_index.py
import json
import glob

users = {}
for user_file in glob.glob("data/users/*.json"):
    with open(user_file) as f:
        user = json.load(f)
        users[user["email"].lower()] = user["id"]

with open("data/users/email_index.json", "w") as f:
    json.dump(users, f, indent=2)
```

---

## Troubleshooting

### "Permission denied" errors

Ensure the application has read/write access to the storage directory:

```bash
# Check permissions
ls -la data/

# Fix ownership (if running as a specific user)
chown -R authglow:authglow data/

# Fix permissions
chmod -R 750 data/
```

### Cloud storage authentication issues

**S3**: Verify credentials and bucket access
```bash
aws s3 ls s3://my-authglow-bucket/
```

**GCS**: Check service account permissions
```bash
gsutil ls gs://my-authglow-bucket/
```

### Corrupted JSON files

If a file becomes corrupted:

1. Restore from backup
2. If no backup exists, manually edit the JSON file to fix syntax errors
3. Use a JSON validator: `python -m json.tool data/users/file.json`

### Storage path conflicts

If using cloud storage, ensure `STORAGE_PATH` includes the full path including bucket:

```bash
# ✅ Correct
STORAGE_PATH=s3://my-bucket/authglow/users

# ❌ Incorrect (missing bucket)
STORAGE_PATH=authglow/users
```

---

## Performance Considerations

### Indexing

AuthGlow maintains an `email_index.json` for fast email lookups. For large deployments:

- Keep the email index file small (it's loaded into memory)
- Consider periodic index rebuilds if you suspect corruption

### Concurrency

File-based storage uses file locks to prevent race conditions, but:

- High concurrent writes to the same user file may be slower than a database
- For high-traffic scenarios (1000+ requests/sec), consider load balancing with separate storage paths or switching to a database

### Caching

AuthGlow doesn't cache file reads by default. For production:

- Use a reverse proxy (nginx, Cloudflare) to cache static responses
- Consider implementing Redis/Memcached for session and token caching (future feature)

---

## Next Steps

- **[Email Configuration](./09-email-configuration.md)**: Set up email delivery
- **[Production Deployment](./10-production-deployment.md)**: Deploy AuthGlow securely
- **[Security Configuration](./11-security.md)**: Harden your instance
