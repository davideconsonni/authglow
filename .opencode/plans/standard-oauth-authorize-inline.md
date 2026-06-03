# Plan: Standard OAuth 2.0 Authorize Flow — Inline Login + Consent

## Problem

Current flow is non-standard (two separate pages):
```
GET /oauth2/authorize → login page → redirect → /oauth/consent → consent page → redirect callback
```

Standard OAuth 2.0 has login + consent on the **same page**:
```
GET /oauth2/authorize → login + consent inline → redirect callback
```

For a commercial IDP/CIAM product, OAuth 2.0 standards compliance is non-negotiable.

## Target Flow (RFC 6749 compliant)

```
1. GET /oauth2/authorize?client_id=...&redirect_uri=...&scope=...&state=...
   → Frontend calls GET /api/oauth2/authorize-info?client_id=... (new endpoint)
   → Shows: client logo + name + "wants to access: [scopes]"
   → Shows: login form (email + password)

2. User fills login → POST /oauth2/authorize (form: email, password, client_id, redirect_uri, scope, state)
   → Backend validates credentials + client + scope
   → If require_consent=false → returns redirect_url directly → browser redirects
   → If require_consent=true → returns { consent_required: true, client_name, logo_uri, scopes, ... }
   → Frontend transitions to consent phase INLINE (same page, no URL change)

3. User sees consent screen inline:
   → Logo, app name, description, scopes with descriptions
   → Remember checkbox
   → Approve / Deny buttons
   → Branding links (homepage, terms, privacy)

4. User clicks Approve → POST /oauth2/consent (form: session_token, approved=true, remember=true/false)
   → Backend processes, saves consent if remember, creates auth code
   → Returns { redirect_url: "...?code=..." }
   → window.location.href = redirect_url

5. Browser redirects to client's redirect_uri with ?code=...&state=...
```

## Backend Changes

### A. New endpoint: `GET /api/oauth2/authorize-info` (public, no auth)

**File**: `backend/authglow/api/oauth_consent_handler.py`

```python
@router.get("/api/oauth2/authorize-info")
async def get_authorize_info(
    client_id: str,
    client_storage: OAuth2ClientStorage = Depends(lambda: OAuth2ClientStorage()),
):
    """Return public client info for the authorize page."""
    client = await client_storage.get_client(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    return {
        "client_name": client.client_name,
        "client_description": client.description,
        "client_logo_uri": client.logo_uri,
        "client_homepage_uri": client.homepage_uri,
        "client_terms_uri": client.terms_uri,
        "client_privacy_uri": client.privacy_uri,
    }
```

**Reason**: The authorize page needs to show who's requesting access **before** the user logs in (visual trust). Currently we only get client data after login via the consent check endpoint.

### B. Update `POST /oauth2/authorize` response (auth.py line 304-307)

When consent is required, the response should include all the data the frontend needs to show the consent screen inline — **no more redirect to another page**:

```python
# Fetch client for branding info
client_info = await oauth2_service.client_storage.get_client(client_id)

SCOPE_DESCRIPTIONS = { ... }  # same as consent handler

return {
    "consent_required": True,
    "session_token": consent_session["session_token"],
    "client_name": client_info.client_name if client_info else client_id,
    "client_description": client_info.description if client_info else None,
    "client_logo_uri": client_info.logo_uri if client_info else None,
    "client_homepage_uri": client_info.homepage_uri if client_info else None,
    "client_terms_uri": client_info.terms_uri if client_info else None,
    "client_privacy_uri": client_info.privacy_uri if client_info else None,
    "scopes": [
        {"name": s, "description": SCOPE_DESCRIPTIONS.get(s, f"Access to {s}")}
        for s in (validated_scope.split() if validated_scope else ["read"])
    ],
}
```

### C. Remove `consent_url` field entirely

The `consent_url` field was the bridge to the separate page. With inline consent, it's no longer needed. The frontend handles the transition internally.

## Frontend Changes

### D. Rewrite `OAuthAuthorizePage.tsx` as state-machine

Three states: `loading` → `login` → `consent`

```
State: loading
  → fetch client info via GET /api/oauth2/authorize-info?client_id=...
  → on success → state: login
  → on error → show error

State: login
  → show client branding (logo, name, "wants to access: ...")
  → show email + password form
  → on submit → POST /oauth2/authorize (form body)
  → if redirect_url returned → window.location.href = redirect_url (no consent needed)
  → if consent_required returned → state: consent (save sessionToken + client data)

State: consent
  → render ConsentScreen inline with sessionToken + client data from the POST response
  → on approve → POST /oauth2/consent → redirect
  → on deny → POST /oauth2/consent → redirect
```

### E. Remove dead code

| Remove | File |
|---|---|
| `OAuthConsentPage` component | `frontend/src/pages/OAuthConsentPage.tsx` |
| `OAUTH_CONSENT` route constant | `frontend/src/lib/constants.ts` |
| Route in `<Routes>` | `frontend/src/App.tsx` |
| Import of `OAuthConsentPage` | `frontend/src/App.tsx` |

### F. `ConsentScreen` stays as-is

Already supports `preview` mode and branding fields. No changes needed — just reused inline within `OAuthAuthorizePage`.

## What Does NOT Change

- `POST /oauth2/consent` — still processes the decision
- `GET /api/oauth2/consent/check` — still handles auto-skip for pre-existing consents (backend-only, no frontend page needed anymore)
- Admin consents listing + revoke
- Admin OAuth clients + preview modal
- Playground — the authorize URL is still `GET /oauth2/authorize?client_id=...`, which now loads the unified page

## File Summary

| File | Action |
|---|---|
| `backend/authglow/api/oauth_consent_handler.py` | ADD `GET /api/oauth2/authorize-info` endpoint |
| `backend/authglow/api/auth.py` | UPDATE `POST /oauth2/authorize` response to include client branding + scopes; REMOVE `consent_url` |
| `frontend/src/pages/OAuthAuthorizePage.tsx` | REWRITE as 3-state machine (loading → login → consent) |
| `frontend/src/pages/OAuthConsentPage.tsx` | DELETE |
| `frontend/src/lib/constants.ts` | REMOVE `OAUTH_CONSENT` |
| `frontend/src/App.tsx` | REMOVE route + import for OAuthConsentPage |

## Estimated LOC Impact

| Category | Lines |
|---|---|
| New backend code | ~30 |
| Modified backend code | ~30 |
| New frontend code (rewrite) | ~200 |
| Deleted frontend code | ~100 |
| **Net delta** | **~+160** |