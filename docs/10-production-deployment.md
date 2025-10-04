# Production Deployment Guide

This guide covers everything you need to deploy AuthGlow securely in a production environment, including Docker configuration, reverse proxy setup, HTTPS, and security hardening.

---

## Pre-Deployment Checklist

Before deploying to production, ensure you have completed these critical steps:

### 1. Generate Strong Secret Keys

**Never use the default keys from `.env.example` in production.**

Generate cryptographically secure keys:

```bash
# On Linux/macOS
openssl rand -hex 32

# Using Python (works everywhere)
python -c "import secrets; print(secrets.token_hex(32))"

# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

You need **two different** keys:
- `SECRET_KEY`: For signing session cookies
- `JWT_SECRET_KEY`: For signing JWT tokens

### 2. Configure Environment Variables

Create a production `.env` file with the following **required** changes:

```bash
# CRITICAL: Set to production mode
APP_ENV=production
DEBUG=false

# CRITICAL: Set your public domain
BASE_URL=https://auth.yourdomain.com
ISSUER=https://auth.yourdomain.com

# CRITICAL: Strong secret keys (generated above)
SECRET_KEY=your_generated_64_char_hex_string
JWT_SECRET_KEY=your_different_64_char_hex_string

# Server settings (internal - proxied by nginx)
HOST=0.0.0.0
PORT=8000

# Storage backend (choose one)
STORAGE_BACKEND=file
STORAGE_PATH=/app/data/users

# Email backend (configure for production)
EMAIL_BACKEND=smtp  # or sendgrid, mailgun
EMAIL_FROM_ADDRESS=noreply@yourdomain.com
EMAIL_FROM_NAME=Your Company Name

# SMTP settings (if using smtp backend)
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=your_sendgrid_api_key
SMTP_USE_TLS=true

# WebAuthn/Passkey settings
PASSKEY_RP_ID=yourdomain.com
PASSKEY_RP_NAME=Your Company Name
PASSKEY_ORIGIN=https://auth.yourdomain.com

# Token expiration (adjust as needed)
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

### 3. DNS Configuration

Ensure your domain is properly configured:

```
auth.yourdomain.com  →  A Record  →  Your Server IP
```

For high availability, consider:
- Multiple A records for different servers (DNS round-robin)
- CNAME to a load balancer
- CDN with origin pointing to your server

### 4. SSL/TLS Certificate

Obtain an SSL certificate for HTTPS. We recommend using **Let's Encrypt** (free):

```bash
# Install certbot
sudo apt update
sudo apt install certbot python3-certbot-nginx

# Obtain certificate (requires port 80 to be accessible)
sudo certbot certonly --nginx -d auth.yourdomain.com

# Certificate files will be at:
# /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem
# /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem
```

Certbot automatically renews certificates. Verify renewal works:

```bash
sudo certbot renew --dry-run
```

---

## Deployment Method 1: Docker with Nginx Reverse Proxy

This is the recommended approach for most deployments.

### Architecture

```
Internet
   ↓
Nginx (port 443 HTTPS)
   ↓
AuthGlow Docker Container (port 8000)
   ↓
Data Volume (persistent storage)
```

### Step 1: Prepare the Server

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose (optional but recommended)
sudo apt install docker-compose-plugin

# Install Nginx
sudo apt install nginx

# Enable firewall (allow SSH, HTTP, HTTPS)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### Step 2: Build and Run AuthGlow Container

```bash
# Clone repository
cd /opt
sudo git clone https://github.com/yourusername/authglow.git
cd authglow

# Create production .env file
sudo nano .env
# (Paste your production configuration from the checklist above)

# Build Docker image
sudo docker build -t authglow:production .

# Create persistent data directory
sudo mkdir -p /var/authglow/data

# Run container with volume mount
sudo docker run -d \
  --name authglow \
  --restart unless-stopped \
  -p 127.0.0.1:8000:8000 \
  -v /var/authglow/data:/app/data \
  --env-file .env \
  authglow:production
```

**Important**: `-p 127.0.0.1:8000:8000` binds only to localhost, not publicly accessible. Nginx will proxy requests.

### Step 3: Configure Nginx Reverse Proxy

Create Nginx configuration:

```bash
sudo nano /etc/nginx/sites-available/authglow
```

Paste this configuration:

```nginx
# Rate limiting zones
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/s;

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name auth.yourdomain.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name auth.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/auth.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.yourdomain.com/privkey.pem;

    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Max upload size (for profile images, etc.)
    client_max_body_size 10M;

    # Logging
    access_log /var/log/nginx/authglow_access.log;
    error_log /var/log/nginx/authglow_error.log;

    # Rate limiting for authentication endpoints
    location /api/auth/ {
        limit_req zone=auth_limit burst=20 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }

    # Rate limiting for password reset
    location /api/password/ {
        limit_req zone=auth_limit burst=5 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }

    # General API endpoints
    location /api/ {
        limit_req zone=api_limit burst=200 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }

    # OAuth/OIDC endpoints
    location /oauth/ {
        limit_req zone=api_limit burst=50 nodelay;
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
    }

    # Static files (cache aggressively)
    location /static/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_cache_valid 200 1d;
        add_header Cache-Control "public, max-age=86400";
    }

    # All other routes
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;

        # WebSocket support (if needed in the future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Health check endpoint (no rate limiting)
    location /health {
        proxy_pass http://127.0.0.1:8000;
        access_log off;
    }
}
```

Enable the configuration:

```bash
# Create symlink
sudo ln -s /etc/nginx/sites-available/authglow /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

### Step 4: Verify Deployment

```bash
# Check container is running
sudo docker ps

# Check logs
sudo docker logs authglow

# Test health endpoint
curl https://auth.yourdomain.com/health

# Test OIDC discovery
curl https://auth.yourdomain.com/.well-known/openid-configuration
```

---

## Deployment Method 2: Docker Compose

For easier management, use Docker Compose:

### Step 1: Create `docker-compose.yml`

```yaml
version: '3.8'

services:
  authglow:
    build: .
    image: authglow:production
    container_name: authglow
    restart: unless-stopped
    ports:
      - "127.0.0.1:8000:8000"
    volumes:
      - authglow-data:/app/data
    env_file:
      - .env
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  authglow-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /var/authglow/data
```

### Step 2: Deploy with Compose

```bash
# Build and start
sudo docker compose up -d

# View logs
sudo docker compose logs -f

# Stop
sudo docker compose down

# Update and restart
git pull
sudo docker compose build
sudo docker compose up -d
```

---

## Deployment Method 3: Cloud Platforms

### Google Cloud Run

AuthGlow is serverless-ready and works perfectly with Cloud Run.

```bash
# Build and push to Google Container Registry
gcloud builds submit --tag gcr.io/YOUR_PROJECT_ID/authglow

# Deploy to Cloud Run
gcloud run deploy authglow \
  --image gcr.io/YOUR_PROJECT_ID/authglow \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "APP_ENV=production,DEBUG=false" \
  --set-env-vars "BASE_URL=https://authglow-xxxxx.run.app" \
  --set-env-vars "STORAGE_BACKEND=gcs" \
  --set-env-vars "STORAGE_PATH=gs://your-bucket/users" \
  --memory 512Mi \
  --cpu 1 \
  --max-instances 10
```

**Important for Cloud Run**:
- Use GCS for storage (`STORAGE_BACKEND=gcs`)
- Set `BASE_URL` to your Cloud Run URL
- Configure custom domain for production

### AWS Lambda (with Mangum)

Install Mangum adapter:

```bash
pip install mangum
```

Modify `main.py`:

```python
from mangum import Mangum

# ... existing FastAPI app code ...

# Add Lambda handler
handler = Mangum(app)
```

Deploy with AWS SAM or Serverless Framework.

### Azure Container Instances

```bash
# Create resource group
az group create --name authglow-rg --location eastus

# Create container
az container create \
  --resource-group authglow-rg \
  --name authglow \
  --image yourdockerhub/authglow:production \
  --dns-name-label authglow-yourunique \
  --ports 8000 \
  --environment-variables \
    APP_ENV=production \
    DEBUG=false \
    BASE_URL=https://authglow-yourunique.eastus.azurecontainer.io \
    STORAGE_BACKEND=abfs \
    STORAGE_PATH=abfs://authglow@youraccount.dfs.core.windows.net/users
```

---

## Security Hardening

### 1. Firewall Configuration

Only allow necessary ports:

```bash
# UFW (Ubuntu)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH (restrict to your IP if possible)
sudo ufw allow 80/tcp    # HTTP (for Let's Encrypt)
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# iptables (alternative)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP
```

### 2. Restrict SSH Access

Edit SSH config:

```bash
sudo nano /etc/ssh/sshd_config
```

Set:
```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
```

Restart SSH:
```bash
sudo systemctl restart sshd
```

### 3. Fail2Ban for Brute Force Protection

```bash
# Install
sudo apt install fail2ban

# Create Nginx jail
sudo nano /etc/fail2ban/jail.d/nginx-authglow.conf
```

Add:
```ini
[nginx-authglow]
enabled = true
port = http,https
filter = nginx-authglow
logpath = /var/log/nginx/authglow_access.log
maxretry = 5
bantime = 3600
```

Create filter:
```bash
sudo nano /etc/fail2ban/filter.d/nginx-authglow.conf
```

Add:
```ini
[Definition]
failregex = ^<HOST> .* "(POST|GET) /api/auth/login HTTP.*" 401
            ^<HOST> .* "(POST|GET) /api/password/reset HTTP.*" 429
ignoreregex =
```

Restart:
```bash
sudo systemctl restart fail2ban
```

### 4. Regular Security Updates

Automate security updates:

```bash
# Ubuntu/Debian
sudo apt install unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

### 5. Container Security

Run containers with limited privileges:

```bash
# Create dedicated user
sudo useradd -r -s /bin/false authglow

# Run container as non-root
docker run -d \
  --user 1000:1000 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp \
  -v /var/authglow/data:/app/data \
  authglow:production
```

---

## Monitoring and Logging

### 1. Application Logs

View AuthGlow logs:

```bash
# Docker logs
sudo docker logs -f authglow --tail 100

# Docker Compose
sudo docker compose logs -f authglow
```

### 2. Nginx Access Logs

Monitor access patterns:

```bash
# Real-time monitoring
sudo tail -f /var/log/nginx/authglow_access.log

# Analyze with GoAccess
sudo apt install goaccess
goaccess /var/log/nginx/authglow_access.log --log-format=COMBINED
```

### 3. Audit Logs

AuthGlow stores audit logs in `data/users/audit_logs/`. Monitor security events:

```bash
# Find recent login attempts
find /var/authglow/data/audit_logs -type f -mtime -1 -exec cat {} \; | grep "user.login"

# Failed authentication attempts
find /var/authglow/data/audit_logs -type f -mtime -1 -exec cat {} \; | grep "auth.failed"
```

### 4. Health Checks and Uptime Monitoring

Use external monitoring services:
- **UptimeRobot**: Free uptime monitoring
- **Pingdom**: Comprehensive monitoring
- **CloudWatch** (AWS), **Cloud Monitoring** (GCP), **Azure Monitor**

Simple health check script:

```bash
#!/bin/bash
# health_check.sh

URL="https://auth.yourdomain.com/health"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $URL)

if [ $RESPONSE -eq 200 ]; then
    echo "OK"
else
    echo "ALERT: Health check failed - HTTP $RESPONSE"
    # Send alert (email, Slack, PagerDuty, etc.)
fi
```

Schedule with cron:
```cron
*/5 * * * * /opt/authglow/health_check.sh
```

---

## Backup in Production

### Automated Daily Backups

```bash
#!/bin/bash
# /opt/authglow/backup.sh

BACKUP_DIR="/backups/authglow"
DATA_DIR="/var/authglow/data"
RETENTION_DAYS=30

# Create timestamped backup
DATE=$(date +%Y%m%d-%H%M%S)
tar -czf "$BACKUP_DIR/authglow-$DATE.tar.gz" "$DATA_DIR"

# Upload to S3 (optional)
aws s3 cp "$BACKUP_DIR/authglow-$DATE.tar.gz" s3://your-backup-bucket/authglow/

# Delete old local backups
find "$BACKUP_DIR" -name "authglow-*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: authglow-$DATE.tar.gz"
```

Schedule:
```cron
0 3 * * * /opt/authglow/backup.sh >> /var/log/authglow-backup.log 2>&1
```

---

## Updating AuthGlow

### Update Process

```bash
# 1. Backup current data
/opt/authglow/backup.sh

# 2. Pull latest code
cd /opt/authglow
sudo git pull

# 3. Rebuild Docker image
sudo docker build -t authglow:production .

# 4. Stop old container
sudo docker stop authglow
sudo docker rm authglow

# 5. Start new container
sudo docker run -d \
  --name authglow \
  --restart unless-stopped \
  -p 127.0.0.1:8000:8000 \
  -v /var/authglow/data:/app/data \
  --env-file .env \
  authglow:production

# 6. Verify
curl https://auth.yourdomain.com/health
```

### Zero-Downtime Updates (Advanced)

Use Docker Compose with rolling updates or a load balancer with multiple instances.

---

## Troubleshooting

### Container won't start

```bash
# Check logs
sudo docker logs authglow

# Common issues:
# - Invalid .env file (check SECRET_KEY length)
# - Port already in use
# - Volume mount permissions
```

### 502 Bad Gateway (Nginx)

```bash
# Verify container is running
sudo docker ps

# Check if port 8000 is accessible
curl http://127.0.0.1:8000/health

# Check Nginx error logs
sudo tail -f /var/log/nginx/authglow_error.log
```

### SSL certificate errors

```bash
# Renew certificate manually
sudo certbot renew

# Check certificate expiration
sudo certbot certificates
```

### High memory usage

```bash
# Limit container memory
sudo docker run -d \
  --memory="512m" \
  --memory-swap="1g" \
  ...
```

---

## Performance Optimization

### 1. Enable Nginx Caching

Add to Nginx config:

```nginx
proxy_cache_path /var/cache/nginx/authglow levels=1:2 keys_zone=authglow_cache:10m max_size=1g inactive=60m;

location /static/ {
    proxy_cache authglow_cache;
    proxy_cache_valid 200 1d;
    proxy_pass http://127.0.0.1:8000;
}
```

### 2. Use CDN for Static Assets

Configure Cloudflare, AWS CloudFront, or similar to cache static files.

### 3. Horizontal Scaling

Deploy multiple AuthGlow instances behind a load balancer:
- Use shared cloud storage (S3/GCS)
- Session affinity not required (stateless design)

---

## Next Steps

- **[Email Configuration](./09-email-configuration.md)**: Configure email delivery
- **[Security Configuration](./11-security.md)**: Additional security hardening
- **[Protecting Your APIs](./12-protecting-apis.md)**: Integrate AuthGlow with your applications
