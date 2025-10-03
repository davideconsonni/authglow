# Password Reset System

This document provides a comprehensive overview of the password reset system in AuthGlow, which allows users to securely regain access to their accounts via email-based tokens.

---

## 🎯 Core Features

### 1. **Secure Token-Based Flow**
-   **Secure Tokens:** Reset tokens are high-entropy (256-bit) random strings.
-   **Hashed Storage:** Tokens are never stored in plaintext. They are hashed using `bcrypt` before being saved, making them impossible to reverse-engineer.
-   **One-Time Use:** Each token is valid for a single password reset and is marked as used immediately after.
-   **Time-Limited:** Tokens automatically expire after a short, configurable period (default: 30 minutes) to reduce the window of opportunity for misuse.

### 2. **Robust API and UI**
-   **Full API Control:** Endpoints are provided for requesting a reset, confirming a reset, and changing a password for an authenticated user.
-   **User-Friendly Pages:** Clean, responsive pages for "Forgot Password" and "Reset Password" guide the user through the process.
-   **Real-time Password Strength:** The reset page includes a real-time indicator to help users choose a strong new password.
-   **Admin Oversight:** A dedicated section in the admin portal allows administrators to view, manage, and revoke active reset tokens.

### 3. **Security Best Practices**
-   **Rate Limiting:** All password reset endpoints are strictly rate-limited to prevent email spamming and brute-force attacks.
-   **Email Enumeration Prevention:** The "request reset" endpoint always returns a generic success message, regardless of whether the email exists in the system, to prevent attackers from discovering valid user emails.
-   **Comprehensive Auditing:** Every step of the reset process, from request to completion (or failure), is logged for security analysis.

---

## 🔄 The User Flow

1.  **Request:** The user enters their email address on the `/password/forgot` page.
2.  **Email:** The system generates a secure, single-use reset token and sends a reset link to the user's email.
3.  **Verify:** The user clicks the link, which directs them to the `/password/reset?token=...` page.
4.  **Confirm:** The user enters and confirms their new password, which is validated against the configured strength policy.
5.  **Completion:** The password is updated, and all other active reset tokens for that user are automatically revoked.

---

## 📋 API Endpoints

### Public Endpoints

| Method | Endpoint                        | Description                                      |
| ------ | ------------------------------- | ------------------------------------------------ |
| `POST` | `/api/password/reset/request`   | Initiates the password reset process for an email. |
| `POST` | `/api/password/reset/confirm`   | Sets a new password using a valid reset token.   |
| `POST` | `/api/password/change`          | Allows an authenticated user to change their password. |

### UI Endpoints

| Method | Endpoint              | Description                               | 
| ------ | --------------------- | ----------------------------------------- |
| `GET`  | `/password/forgot`    | Displays the "Forgot Password" page.      |
| `GET`  | `/password/reset`     | Displays the "Reset Password" page.       |

### Admin Endpoints

| Method | Endpoint                               | Description                                      |
| ------ | -------------------------------------- | ------------------------------------------------ |
| `GET`  | `/api/admin/password-resets`           | List all password reset tokens.                  |
| `POST` | `/api/admin/users/{user_id}/revoke-resets` | Revoke all active tokens for a specific user.    |
| `POST` | `/api/admin/password-resets/cleanup`   | Clean up (delete) all expired and used tokens.   |

---

## 💡 Usage Examples

### 1. Request a Password Reset

```bash
curl -X POST "http://localhost:8000/api/password/reset/request" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

**Response (Always returns success):**
```json
{
  "message": "If this email exists, a password reset link will be sent",
  "email": "user@example.com"
}
```

### 2. Confirm a Password Reset

After the user receives the token via email.

```bash
curl -X POST "http://localhost:8000/api/password/reset/confirm" \
  -H "Content-Type: application/json" \
  -d 
  {
    "token": "THE_SECURE_TOKEN_FROM_THE_EMAIL_LINK",
    "new_password": "NewSecurePassword123!"
  }
```

**Response:**
```json
{
  "message": "Password reset successful"
}
```

### 3. Change Password (Authenticated)

```bash
curl -X POST "http://localhost:8000/api/password/change" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d 
  {
    "current_password": "OldPassword123!",
    "new_password": "NewerAndBetterPassword456!"
  }
```
