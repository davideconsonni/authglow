# Email Configuration Guide

This guide covers how to configure AuthGlow's email system for sending transactional emails like verification emails, password resets, and security notifications.

---

## Overview: Email in AuthGlow

AuthGlow sends transactional emails for the following events:

- **Welcome emails** when a new user registers
- **Email verification** links for confirming email addresses
- **Password reset** links for account recovery
- **Security alerts** for suspicious activities (login from new device, password changes, etc.)
- **MFA setup** notifications

The email system is designed with flexibility in mind, supporting multiple backends for different environments.

---

## Email Backends

AuthGlow supports the following email backends via the `EMAIL_BACKEND` environment variable:

| Backend | Use Case | Configuration Complexity |
|---------|----------|--------------------------|
| `console` | Development - prints to terminal | None (default) |
| `file_storage` | Development - saves to JSON files | Minimal |
| `smtp` | Production - any SMTP server | Medium |
| `sendgrid` | Production - SendGrid API | Low |
| `mailgun` | Production - Mailgun API | Low |

---

## Backend 1: Console (Development)

### Overview

Prints all emails to the console/terminal with nice formatting. Perfect for local development.

### Configuration

```bash
# .env
EMAIL_BACKEND=console
EMAIL_FROM_ADDRESS=noreply@authglow.local
EMAIL_FROM_NAME=AuthGlow Dev
```

### Example Output

When AuthGlow sends an email, you'll see this in your terminal:

```
================================================================================
[EMAIL MESSAGE]
================================================================================
Message ID: console-a3f7c21e-8b9d-4e1a-9c5f-1d2e3f4a5b6c
Timestamp:  2025-10-04T10:30:45.123456Z
Provider:   console

HEADERS:
--------------------------------------------------------------------------------
From:     AuthGlow Dev <noreply@authglow.local>
To:       user@example.com
Subject:  Verify Your Email Address

TEXT VERSION:
--------------------------------------------------------------------------------
Hello John,

Please verify your email address by clicking the link below:
http://localhost:8000/verify-email?token=abc123...

This link will expire in 60 minutes.

================================================================================
```

### Pros & Cons

✅ Zero configuration
✅ Instant visibility during development
✅ Color-coded output for readability

❌ Not suitable for production
❌ Emails are not actually delivered

---

## Backend 2: File Storage (Development)

### Overview

Saves all emails as JSON files to a directory. Useful for inspecting email content during testing or debugging.

### Configuration

```bash
# .env
EMAIL_BACKEND=file_storage
EMAIL_FROM_ADDRESS=noreply@authglow.local
EMAIL_FROM_NAME=AuthGlow Dev
EMAIL_STORAGE_PATH=data/users/emails
```

### Email File Structure

Each email is saved as a JSON file:

```
data/users/emails/
├── 20251004_103045_a3f7c21e.json
├── 20251004_104512_b8e9d32f.json
└── 20251004_110023_c4f1a87d.json
```

Example file content:

```json
{
  "message_id": "file-a3f7c21e-8b9d-4e1a-9c5f-1d2e3f4a5b6c",
  "timestamp": "2025-10-04T10:30:45.123456Z",
  "provider": "file_storage",
  "from": {
    "email": "noreply@authglow.local",
    "name": "AuthGlow Dev"
  },
  "to": ["user@example.com"],
  "subject": "Verify Your Email Address",
  "body_text": "Hello John,\n\nPlease verify your email...",
  "body_html": "<!DOCTYPE html>...",
  "priority": "normal",
  "attachments": []
}
```

### Pros & Cons

✅ Easy to inspect and debug
✅ Can be integrated with automated tests
✅ Useful for auditing during development

❌ Requires manual cleanup
❌ Not suitable for production

---

## Backend 3: SMTP (Production)

### Overview

Use any SMTP server to send real emails. This is the most flexible production option and works with:
- Gmail SMTP
- Office 365 / Outlook
- AWS SES
- Your own mail server
- Any standard SMTP service

### Configuration

```bash
# .env
EMAIL_BACKEND=smtp
EMAIL_FROM_ADDRESS=noreply@yourdomain.com
EMAIL_FROM_NAME=Your Company Name

# SMTP Server Settings
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
```

### Common SMTP Configurations

#### Gmail

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password  # Generate at https://myaccount.google.com/apppasswords
SMTP_USE_TLS=true
```

**Important**: Don't use your regular Gmail password. Create an [App Password](https://support.google.com/accounts/answer/185833).

#### Office 365 / Outlook

```bash
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=your-email@yourdomain.com
SMTP_PASSWORD=your-password
SMTP_USE_TLS=true
```

#### AWS SES (Simple Email Service)

```bash
SMTP_HOST=email-smtp.us-east-1.amazonaws.com
SMTP_PORT=587
SMTP_USERNAME=your-ses-smtp-username
SMTP_PASSWORD=your-ses-smtp-password
SMTP_USE_TLS=true
```

**Note**: You must verify your sender email/domain in AWS SES console first.

#### Custom SMTP Server

```bash
SMTP_HOST=mail.yourdomain.com
SMTP_PORT=587  # or 465 for SSL
SMTP_USERNAME=noreply@yourdomain.com
SMTP_PASSWORD=your-password
SMTP_USE_TLS=true  # or false for port 465 with SSL
```

### Testing SMTP Configuration

Test your SMTP settings manually:

```bash
# Linux/macOS
python3 -c "
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg['From'] = 'noreply@yourdomain.com'
msg['To'] = 'test@example.com'
msg['Subject'] = 'SMTP Test'
msg.set_content('This is a test email.')

with smtplib.SMTP('smtp.gmail.com', 587) as server:
    server.starttls()
    server.login('your-email@gmail.com', 'your-app-password')
    server.send_message(msg)
    print('Email sent successfully!')
"
```

### Troubleshooting SMTP

**"Authentication failed"**
- Verify username and password are correct
- For Gmail, ensure you're using an App Password
- Check if 2FA is enabled (required for App Passwords)

**"Connection refused"**
- Check firewall allows outbound connections on port 587/465
- Verify `SMTP_HOST` is correct
- Try `telnet smtp.gmail.com 587` to test connectivity

**"SSL/TLS errors"**
- Ensure `SMTP_USE_TLS=true` for port 587
- Use `SMTP_USE_TLS=false` for port 465 (implicit SSL)

### Pros & Cons

✅ Works with any SMTP provider
✅ Full control over email delivery
✅ No vendor lock-in

❌ Requires SMTP credentials management
❌ More complex than API-based providers
❌ May have rate limits depending on provider

---

## Backend 4: SendGrid (Production)

### Overview

SendGrid is a cloud-based email delivery service with excellent deliverability and analytics.

### Setup

1. **Create a SendGrid account** at [sendgrid.com](https://sendgrid.com)
2. **Create an API key**:
   - Go to Settings → API Keys
   - Click "Create API Key"
   - Choose "Full Access" or "Restricted Access" with "Mail Send" permission
   - Copy the API key (you won't see it again!)
3. **Verify your sender identity**:
   - Go to Settings → Sender Authentication
   - Verify a single sender email OR authenticate your domain

### Configuration

```bash
# .env
EMAIL_BACKEND=sendgrid
EMAIL_FROM_ADDRESS=noreply@yourdomain.com
EMAIL_FROM_NAME=Your Company Name

SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Testing SendGrid

```bash
curl -X POST https://api.sendgrid.com/v3/mail/send \
  -H "Authorization: Bearer YOUR_SENDGRID_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "personalizations": [{"to": [{"email": "test@example.com"}]}],
    "from": {"email": "noreply@yourdomain.com"},
    "subject": "SendGrid Test",
    "content": [{"type": "text/plain", "value": "Test email"}]
  }'
```

### Pricing (as of 2025)

- **Free tier**: 100 emails/day forever
- **Essentials**: Starting at $19.95/month for 50,000 emails
- **Pro**: Starting at $89.95/month for 100,000 emails

### Pros & Cons

✅ Excellent deliverability
✅ Easy API integration
✅ Free tier for small projects
✅ Advanced analytics and tracking

❌ Requires account signup
❌ Free tier limited to 100 emails/day

---

## Backend 5: Mailgun (Production)

### Overview

Mailgun is a developer-friendly email service with powerful APIs and great documentation.

### Setup

1. **Create a Mailgun account** at [mailgun.com](https://www.mailgun.com)
2. **Get your API credentials**:
   - Go to Settings → API Keys
   - Copy your "Private API Key"
3. **Set up your domain**:
   - Add and verify your sending domain
   - Or use the sandbox domain for testing (limited to 300 emails)

### Configuration

```bash
# .env
EMAIL_BACKEND=mailgun
EMAIL_FROM_ADDRESS=noreply@yourdomain.com
EMAIL_FROM_NAME=Your Company Name

MAILGUN_API_KEY=your-private-api-key
MAILGUN_DOMAIN=yourdomain.com  # or mg.yourdomain.com
```

### Testing Mailgun

```bash
curl -s --user 'api:YOUR_MAILGUN_API_KEY' \
  https://api.mailgun.net/v3/yourdomain.com/messages \
  -F from='noreply@yourdomain.com' \
  -F to='test@example.com' \
  -F subject='Mailgun Test' \
  -F text='Test email from Mailgun'
```

### Pricing (as of 2025)

- **Trial**: 5,000 emails free for 3 months
- **Foundation**: $35/month for 50,000 emails
- **Growth**: Starting at $80/month for 100,000 emails

### Pros & Cons

✅ Developer-friendly API
✅ Excellent logs and debugging tools
✅ Generous trial period
✅ Built-in email validation

❌ No permanent free tier
❌ Domain verification required for production

---

## Email Templates

AuthGlow includes pre-built email templates in both HTML and plain text formats.

### Available Templates

Located in `authglow/templates/emails/`:

- `welcome.html` / `welcome.txt` - New user registration
- `email_verification.html` / `email_verification.txt` - Email confirmation
- `password_reset.html` / `password_reset.txt` - Password recovery
- `security_alert.html` / `security_alert.txt` - Security notifications

### Template Variables

Each template receives specific context variables. For example, `password_reset.html`:

```html
<!DOCTYPE html>
<html>
<body>
    <h1>Password Reset Request</h1>
    <p>Hello{{ user_name }},</p>
    <p>Click the link below to reset your password:</p>
    <a href="{{ reset_url }}">Reset Password</a>
    <p>This link expires in {{ expires_in_minutes }} minutes.</p>
    <p>Sent from {{ company_name }}</p>
</body>
</html>
```

Variables available:
- `user_name` - User's full name
- `email` - User's email
- `reset_url` - Password reset link
- `expires_in_minutes` - Link expiration time
- `company_name` - From `UI_COMPANY_NAME` setting

### Customizing Templates

To customize email templates:

1. **Edit existing templates** in `authglow/templates/emails/`
2. **Use Jinja2 syntax** for dynamic content
3. **Provide both HTML and TXT versions** for better compatibility

Example customization:

```html
<!-- authglow/templates/emails/welcome.html -->
<!DOCTYPE html>
<html>
<head>
    <style>
        .header { background: {{ primary_color }}; color: white; padding: 20px; }
        .content { padding: 30px; font-family: Arial, sans-serif; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to {{ company_name }}!</h1>
    </div>
    <div class="content">
        <p>Hi {{ user_name }},</p>
        <p>Thanks for joining! Your account is ready.</p>
        <a href="{{ login_url }}" style="background: {{ primary_color }}; color: white; padding: 10px 20px; text-decoration: none;">
            Get Started
        </a>
    </div>
</body>
</html>
```

---

## Environment Variables Reference

Complete list of email-related settings:

```bash
# General Email Settings
EMAIL_BACKEND=console              # console, file_storage, smtp, sendgrid, mailgun
EMAIL_FROM_ADDRESS=noreply@yourdomain.com
EMAIL_FROM_NAME=Your Company Name

# File Storage Backend
EMAIL_STORAGE_PATH=data/users/emails

# SMTP Backend
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-password
SMTP_USE_TLS=true

# SendGrid Backend
SENDGRID_API_KEY=SG.xxxxxx...

# Mailgun Backend
MAILGUN_API_KEY=key-xxxxxx...
MAILGUN_DOMAIN=yourdomain.com

# Base URL for email links
BASE_URL=https://auth.yourdomain.com
COMPANY_NAME=Your Company Name
```

---

## Production Best Practices

### 1. Use a Dedicated Sending Domain

Set up a subdomain for transactional emails:
- `noreply@auth.yourdomain.com`
- `notifications@accounts.yourdomain.com`

This isolates your transactional email reputation from your main domain.

### 2. Authenticate Your Domain

Configure SPF, DKIM, and DMARC records:

**SPF Record** (for SendGrid):
```
v=spf1 include:sendgrid.net ~all
```

**DKIM**: Follow your provider's instructions (SendGrid, Mailgun, etc.)

**DMARC** (basic):
```
v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com
```

### 3. Monitor Email Delivery

Track key metrics:
- **Delivery rate**: % of emails successfully delivered
- **Bounce rate**: % of emails that failed (should be < 2%)
- **Spam complaint rate**: % marked as spam (should be < 0.1%)

Most providers (SendGrid, Mailgun) offer dashboards for this.

### 4. Handle Bounces and Complaints

Implement webhook handlers to:
- Mark bounced email addresses as invalid
- Remove users who mark emails as spam
- Alert admins of delivery issues

### 5. Use Environment-Specific Settings

```bash
# Development
EMAIL_BACKEND=console

# Staging
EMAIL_BACKEND=file_storage  # or smtp with test domain

# Production
EMAIL_BACKEND=sendgrid  # or mailgun, smtp
```

### 6. Rate Limiting

Be mindful of provider limits:
- **Gmail SMTP**: ~500 emails/day
- **SendGrid Free**: 100 emails/day
- **Mailgun Trial**: 300 emails/month to sandbox domain

### 7. Test Email Rendering

Test on multiple clients before going live:
- Gmail (web, mobile)
- Outlook (desktop, web)
- Apple Mail
- Mobile devices (iOS, Android)

Use tools like [Litmus](https://www.litmus.com/) or [Email on Acid](https://www.emailonacid.com/) for comprehensive testing.

---

## Troubleshooting

### Emails not being sent

**Check 1: Verify configuration**
```bash
# View current email provider
curl http://localhost:8000/health

# Or check logs
docker logs authglow | grep email
```

**Check 2: Test backend independently**
```python
# test_email.py
from authglow.services.email.factory import get_email_service
from authglow.models.email import EmailMessage

async def test():
    service = get_email_service()
    result = await service.send(EmailMessage(
        to=["test@example.com"],
        subject="Test Email",
        body_text="This is a test."
    ))
    print(f"Success: {result.success}")
    if not result.success:
        print(f"Error: {result.error}")

import asyncio
asyncio.run(test())
```

### Emails going to spam

**Solutions**:
1. Authenticate your domain (SPF, DKIM, DMARC)
2. Use a dedicated IP address (available with paid plans)
3. Avoid spam trigger words in subject/body
4. Ensure unsubscribe links (for marketing emails)
5. Warm up your domain (gradually increase sending volume)

### SendGrid/Mailgun API errors

**401 Unauthorized**: Invalid API key
- Regenerate key and update `.env`

**403 Forbidden**: Sender not verified
- Verify your sender email or domain in provider console

**429 Too Many Requests**: Rate limit exceeded
- Upgrade plan or reduce sending frequency

---

## Migration Between Backends

### From Console/File to Production

1. **Choose a production backend** (SMTP, SendGrid, or Mailgun)
2. **Update `.env`** with new credentials
3. **Test with a single email**
4. **Restart AuthGlow**
5. **Monitor first few emails** in provider dashboard

### From SMTP to SendGrid/Mailgun

1. **Set up account** and verify domain
2. **Update environment variables**:
   ```bash
   # Old SMTP config (comment out)
   # EMAIL_BACKEND=smtp
   # SMTP_HOST=...

   # New SendGrid config
   EMAIL_BACKEND=sendgrid
   SENDGRID_API_KEY=SG.xxxxxx
   ```
3. **Restart application**
4. **Verify delivery** in SendGrid dashboard

---

## Next Steps

- **[Production Deployment](./10-production-deployment.md)**: Deploy AuthGlow securely
- **[Security Configuration](./11-security.md)**: Harden your email and authentication flows
- **[Storage & Backup](./08-storage-backup.md)**: Understand where email logs are stored
