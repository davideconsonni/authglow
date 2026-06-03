# Plan: Add OAuth Authorize Page to Frontend & Fix Playground

## Problem

The playground builds the authorize URL as:
```
http://localhost:5173/oauth2/authorize?client_id=...&redirect_uri=...
```
(pointing to `window.location.origin` = the frontend)

But the frontend has no route for `/oauth2/authorize` → the user sees `Not Found`.

## Root Cause

The backend endpoint `POST /oauth2/authorize` is a **POST** endpoint (needs email + password form data), not a GET. The playground's "Open in Browser" anchor tag navigates via GET, which can't work with a POST endpoint. There is no frontend page to handle the authorize flow.

## Solution

Create a frontend page at `/oauth2/authorize` that:
1. Renders a login form (email + password)
2. POSTs form data to the backend `POST /oauth2/authorize`
3. If response has `consent_required: true` + `consent_url` → redirect to the consent page
4. If response has `redirect_url` directly (when `require_consent=false`) → redirect there
5. If response has `mfa_required: true` → (stretch: redirect to MFA; minimal: show error)
6. On error, show inline error on the login form

## Concrete Steps

### 1. Create `frontend/src/pages/OAuthAuthorizePage.tsx`
New file with an `OAuthAuthorizePage` component that:
- Reads `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`, `nonce` from URL query params
- Renders a centered login card (email, password fields + "Sign In" button)
- On submit, posts form via `api.postForm()` to `/oauth2/authorize`
- Handles 3 response paths:
  - `consent_required: true` → `window.location.href = consent_url`
  - `redirect_url` directly → `window.location.href = redirect_url`
  - Error → show friendly error
- Loading state on the button
- Follows DESIGN.md glassmorphism + dark theme

### 2. Add route in `frontend/src/App.tsx`
Add route `path="/oauth2/authorize"` before the catch-all `*` route.

### 3. No backend changes needed
The backend `POST /oauth2/authorize` already works correctly — it returns the consent redirect info. The fix is purely frontend: providing a page that calls this endpoint and handles the response.

## After This Fix

The playground flow becomes:
1. Step "Authorize" → click "Open in Browser" → opens `/oauth2/authorize?...` (now works!)
2. Login page appears → enter email/password
3. ConsentScreen appears → approve + "Remember this decision"
4. Redirect to callback → copy `?code=...` from URL
5. Back in playground → paste code → exchange for tokens

This is also the correct production OAuth authorize flow (not just for playground testing).