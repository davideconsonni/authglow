// When VITE_API_URL is unset (the single-container/Cloud Run build) the SPA
// uses relative, same-origin paths. Use ?? so an explicitly-empty value is kept
// instead of falling back to the local dev backend.
export const API_URL = import.meta.env.VITE_API_URL ?? ''

export const ROUTES = {
  AUTH: {
    LOGIN: '/auth/login',
    CALLBACK: '/auth/callback',
    REGISTER: '/auth/register',
    FORGOT_PASSWORD: '/auth/forgot-password',
    RESET_PASSWORD: '/auth/reset-password',
    MFA_VERIFY: '/auth/mfa-verify',
    VERIFY_EMAIL: '/auth/verify-email',
    PASSWORD_EXPIRED: '/auth/password-expired',
  },
  OAUTH_AUTHORIZE: '/oauth2/authorize',
  OAUTH_DEVICE_VERIFY: '/oauth2/device/verify',
  SETUP: '/setup',
  DASHBOARD: '/dashboard',
  PROFILE: '/profile',
  SECURITY: '/security',
  SESSIONS: '/sessions',
  API_KEYS: '/api-keys',
  DEVICE_AUTHORIZATIONS: '/device-authorizations',
  ADMIN: {
    DASHBOARD: '/admin',
    USERS: '/admin/users',
    OAUTH_CLIENTS: '/admin/oauth-clients',
    SESSIONS: '/admin/sessions',
    CONSENTS: '/admin/consents',
    API_KEYS: '/admin/api-keys',
    RBAC: '/admin/rbac',
    JWK_KEYS: '/admin/jwk-keys',
    PASSWORD_RESETS: '/admin/password-resets',
    PLAYGROUND: '/admin/playground',
    PLAYGROUND_OAUTH_CALLBACK: '/admin/playground/oauth/callback',
    FEDERATION: '/admin/federation',
    DEVICE_AUTHORIZATIONS: '/admin/device-authorizations',
    DEVICE_AUTHORIZATIONS_NEW: '/admin/device-authorizations/new',
    SETTINGS: '/admin/settings',
    RATE_LIMITS: '/admin/rate-limits',
  },
} as const
