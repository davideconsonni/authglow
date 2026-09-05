// Per-row action button convention (keep in sync with
// AdminApiKeysPage / ApiKeysPage / AdminJwkKeysPage):
//
//   rotate  → RefreshCw 14px, hover text-brand-accent
//   edit    → Pencil    14px, hover text-text-secondary
//   delete  → Trash2    14px, hover text-semantic-error
//
// Each row composes its own <button>; we only share the icon +
// hover-color mapping (no shared component by design).
import { useState } from 'react'
import { Trash2, RefreshCw, Plus, Loader2, Save, Globe, Cog, Smartphone, ChevronDown, ChevronRight, Edit, AlertTriangle, Eye, KeyRound, Monitor, Tv, ArrowRight, ArrowLeft, ExternalLink, Terminal, Code, FileText, CheckCircle2, X } from 'lucide-react'
import { api } from '../../lib/api'
import { useApiQuery } from '../../hooks/useApi'
import { cn } from '../../lib/utils'
import { ConfirmDialog } from '../../components/shared/ConfirmDialog'
import { RotateSecretDialog } from '../../components/admin/RotateSecretDialog'
import { Banner } from '../../components/shared/Banner'
import { FieldError } from '../../components/shared/FieldError'
import { PageHeader } from '../../components/layout/PageHeader'
import { CopyButton } from '../../components/shared/CopyButton'
import { ConsentScreen } from '../../components/oauth/ConsentScreen'
import { TokenClaimsTab } from '../../components/admin/TokenClaimsTab'
import { ScopePicker } from '../../components/shared/ScopePicker'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { notify } from '../../stores/toastStore'

interface OAuthClient {
  id?: string
  client_id: string
  client_name?: string
  name?: string
  is_confidential: boolean
  redirect_uris: string[]
  allowed_post_logout_redirect_uris?: string[]
  grant_types: string[]
  scopes?: string[]
  allowed_scopes?: string[]
  is_active: boolean
  require_pkce?: boolean
  require_consent?: boolean
  description?: string
  logo_uri?: string
  homepage_uri?: string
  terms_uri?: string
  privacy_uri?: string
  access_token_lifetime?: number
  refresh_token_lifetime?: number
  custom_css?: string | null
  branding?: Record<string, unknown> | null
  token_endpoint_auth_method?: string
  has_client_secret_jwt_key?: boolean
  public_jwk?: Record<string, unknown> | null
  dpop_bound?: boolean
}

type GrantType = 'authorization_code' | 'client_credentials' | 'refresh_token'
// T.2: extended to cover the FAPI 2.0 / RFC 7521 alternatives.
type AuthMethod = 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt' | 'private_key_jwt' | 'none'

const ALL_GRANT_TYPES: { id: GrantType; label: string; desc: string }[] = [
  { id: 'authorization_code', label: 'Authorization Code', desc: 'User logs in via browser redirect' },
  { id: 'client_credentials', label: 'Client Credentials', desc: 'Machine-to-machine, no user' },
  { id: 'refresh_token', label: 'Refresh Token', desc: 'Issue long-lived refresh tokens' },
]

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Verify your identity',
  profile: 'Access your profile information (name, picture)',
  email: 'Access your email address',
  phone: 'Access your phone number',
  address: 'Access your physical address',
  offline_access: 'Allow offline access (refresh tokens)',
  read: 'Read access to your data',
  write: 'Write access to your data',
}

function getScopeLabel(scope: string): string {
  return SCOPE_DESCRIPTIONS[scope] || `Access to ${scope}`
}

interface Template {
  id: string
  label: string
  desc: string
  icon: typeof Globe
  grant_types: GrantType[]
  is_confidential: boolean
  auth_method: AuthMethod
  require_pkce: boolean
  require_consent: boolean
  show_redirect_uris: boolean
  show_logout_uris: boolean
  access_token_lifetime: number
  refresh_token_lifetime: number
}

const TEMPLATES: Template[] = [
  {
    id: 'web', label: 'Web App', desc: 'Traditional server-rendered app with backend', icon: Globe,
    grant_types: ['authorization_code', 'refresh_token'], is_confidential: true,
    auth_method: 'client_secret_basic', require_pkce: false, require_consent: true,
    show_redirect_uris: true, show_logout_uris: true, access_token_lifetime: 3600, refresh_token_lifetime: 2592000,
  },
  {
    id: 'spa', label: 'Single-Page App', desc: 'React/Vue/Svelte SPA — PKCE enforced', icon: Monitor,
    grant_types: ['authorization_code', 'refresh_token'], is_confidential: false,
    auth_method: 'none', require_pkce: true, require_consent: true,
    show_redirect_uris: true, show_logout_uris: true, access_token_lifetime: 3600, refresh_token_lifetime: 2592000,
  },
  {
    id: 'mobile', label: 'Mobile / Native', desc: 'iOS/Android app — PKCE + custom scheme redirect', icon: Smartphone,
    grant_types: ['authorization_code', 'refresh_token'], is_confidential: false,
    auth_method: 'none', require_pkce: true, require_consent: true,
    show_redirect_uris: true, show_logout_uris: true, access_token_lifetime: 3600, refresh_token_lifetime: 2592000,
  },
  {
    id: 'service', label: 'API / Service', desc: 'Machine-to-machine (client_credentials)', icon: Cog,
    grant_types: ['client_credentials', 'refresh_token'], is_confidential: true,
    auth_method: 'client_secret_basic', require_pkce: false, require_consent: false,
    show_redirect_uris: false, show_logout_uris: false, access_token_lifetime: 3600, refresh_token_lifetime: 2592000,
  },
  {
    id: 'device', label: 'Device Flow', desc: 'TV/CLI/IoT — no browser on device', icon: Tv,
    grant_types: ['device_code', 'refresh_token'], is_confidential: false,
    auth_method: 'none', require_pkce: false, require_consent: false,
    show_redirect_uris: false, show_logout_uris: false, access_token_lifetime: 3600, refresh_token_lifetime: 2592000,
  },
]

function friendlyError(raw: string): string {
  if (raw.includes('client_name') && raw.includes('Field required')) return 'Application name is required.'
  if (raw.includes('redirect_uris') && raw.includes('List should have at least')) return 'Add at least one redirect URI.'
  if (raw.includes('grant_types') && raw.includes('List should have at least')) return 'Select at least one grant type.'
  return raw
}

function ColorField(props: {
  label: string
  value: string
  swatchFallback: string
  placeholder?: string
  onChange: (v: string) => void
}) {
  const { label, value, swatchFallback, placeholder, onChange } = props
  return (
    <div>
      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">{label}</label>
      <div className="flex gap-2">
        <input
          type="color"
          value={value || swatchFallback}
          onChange={(e) => onChange(e.target.value)}
          className="h-8 w-8 rounded border border-surface-2 bg-surface-1 cursor-pointer"
          aria-label={`${label} color picker`}
        />
        <input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className="flex-1 rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
        />
      </div>
    </div>
  )
}

function TextInput(props: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  'data-testid'?: string
  type?: string
  autoFocus?: boolean
}) {
  return (
    <input
      type={props.type || 'text'}
      value={props.value}
      onChange={(e) => props.onChange(e.target.value)}
      placeholder={props.placeholder}
      data-testid={props['data-testid']}
      autoFocus={props.autoFocus}
      className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20"
    />
  )
}

export function AdminOAuthClientsPage() {
  useDocumentTitle('OAuth Clients')
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  // Token Claims policy editor modal — opened from the row
  // actions. Tracks the client so the modal can call the
  // /api/admin/oauth-clients/{id}/claim-policy endpoint.
  const [claimsClient, setClaimsClient] = useState<{ id: string; name: string } | null>(null)

  // Form fields
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [grantTypes, setGrantTypes] = useState<GrantType[]>([])
  const [isConfidential, setIsConfidential] = useState(true)
  const [authMethod, setAuthMethod] = useState<AuthMethod>('client_secret_basic')
  const [redirectUris, setRedirectUris] = useState<string[]>([''])
  const [allowedPostLogoutRedirectUris, setAllowedPostLogoutRedirectUris] = useState<string[]>([''])
  const [requirePkce, setRequirePkce] = useState(false)
  const [requireConsent, setRequireConsent] = useState(true)
  const [homepageUri, setHomepageUri] = useState('')
  const [logoUri, setLogoUri] = useState('')
  const [termsUri, setTermsUri] = useState('')
  const [privacyUri, setPrivacyUri] = useState('')
  const [allowedScopes, setAllowedScopes] = useState('openid profile email')
  const [accessTokenLifetime, setAccessTokenLifetime] = useState(3600)
  const [refreshTokenLifetime, setRefreshTokenLifetime] = useState(2592000)
  const [customCss, setCustomCss] = useState('')
  const [branding, setBranding] = useState<Record<string, string>>({})
  const [brandingLight, setBrandingLight] = useState<Record<string, string>>({})
  const [brandingDark, setBrandingDark] = useState<Record<string, string>>({})
  const [brandingMode, setBrandingMode] = useState<'base' | 'light' | 'dark'>('base')

  const [showAdvanced, setShowAdvanced] = useState(false)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [formErrors, setFormErrors] = useState<Record<string, string>>({})
  const [secretModal, setSecretModal] = useState<string | null>(null)
  // T.2: when creating a ``client_secret_jwt`` client the backend
  // returns the plaintext symmetric key in the same envelope as
  // the regular client_secret. We display it once in the same modal
  // so the operator can hand it to the client developer.
  const [jwtKeyModal, setJwtKeyModal] = useState<string | null>(null)
  // Rotate actions are destructive (invalidate the live credential)
  // and are gated behind a server-issued safeword. The state holds
  // the target client_id while the dialog is open; the destructive
  // POST only fires after the operator types the safeword back.
  const [rotateTarget, setRotateTarget] = useState<string | null>(null)
  const [rotateJwtKeyTarget, setRotateJwtKeyTarget] = useState<string | null>(null)
  const [newClientId, setNewClientId] = useState('')
  const [editClientId, setEditClientId] = useState<string | null>(null)
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null)
  const [previewClient, setPreviewClient] = useState<OAuthClient | null>(null)
  const [originalGrantTypes, setOriginalGrantTypes] = useState<GrantType[]>([])
  const [originalIsConfidential, setOriginalIsConfidential] = useState(true)
  // T.2: client-controlled public JWK (textarea). Empty string means
  // "not provided" — the server only persists the field when the
  // auth method requires it.
  const [publicJwkText, setPublicJwkText] = useState('')
  const [publicJwkError, setPublicJwkError] = useState<string | null>(null)
  // T.3: DPoP binding toggle. Default false for back-compat.
  const [dpopBound, setDpopBound] = useState(false)

  // Wizard state
  const [wizardStep, setWizardStep] = useState(1)
  const [showSuccess, setShowSuccess] = useState(false)
  const [createdClientData, setCreatedClientData] = useState<{
    client_id: string
    client_secret: string
    client_secret_jwt_key?: string | null
  } | null>(null)

  const modeBrand = brandingMode === 'base' ? branding : brandingMode === 'light' ? brandingLight : brandingDark
  const setModeBrand = (patch: Record<string, string>) => {
    if (brandingMode === 'base') setBranding((p) => ({ ...p, ...patch }))
    else if (brandingMode === 'light') setBrandingLight((p) => ({ ...p, ...patch }))
    else setBrandingDark((p) => ({ ...p, ...patch }))
  }

  const { data, refetch } = useApiQuery<OAuthClient[]>(['admin-oauth-clients'], '/api/oauth-clients')
  const clients: OAuthClient[] = Array.isArray(data) ? data : ((data as { items?: OAuthClient[] } | undefined)?.items as OAuthClient[]) ?? []

  const resetForm = () => {
    setName(''); setDescription(''); setGrantTypes([]); setIsConfidential(true)
    setAuthMethod('client_secret_basic'); setRedirectUris(['']); setAllowedPostLogoutRedirectUris([''])
    setRequirePkce(false); setRequireConsent(true)
    setHomepageUri(''); setLogoUri(''); setTermsUri(''); setPrivacyUri('')
    setAllowedScopes('openid profile email'); setCustomCss('')
    setBranding({}); setBrandingLight({}); setBrandingDark({}); setBrandingMode('base')
    setAccessTokenLifetime(3600); setRefreshTokenLifetime(2592000)
    setShowAdvanced(false); setFormErrors({}); setSelectedTemplate(null)
    setEditClientId(null); setOriginalGrantTypes([]); setOriginalIsConfidential(true)
    setPublicJwkText(''); setPublicJwkError(null)
    setDpopBound(false)
    setJwtKeyModal(null)
    setFormError(null)
    // Reset wizard state
    setWizardStep(1)
    setShowSuccess(false)
    setCreatedClientData(null)
  }

  const applyTemplate = (t: Template) => {
    setSelectedTemplate(t.id)
    setGrantTypes(t.grant_types)
    setIsConfidential(t.is_confidential)
    setAuthMethod(t.auth_method)
    setRequirePkce(t.require_pkce)
    setRequireConsent(t.require_consent)
    setAccessTokenLifetime(t.access_token_lifetime)
    setRefreshTokenLifetime(t.refresh_token_lifetime)
    if (t.show_redirect_uris) {
      setRedirectUris([''])
    } else {
      setRedirectUris([])
    }
    if (t.show_logout_uris) {
      setAllowedPostLogoutRedirectUris([''])
    } else {
      setAllowedPostLogoutRedirectUris([])
    }
    setFormErrors({})
    // T.2: a template switch implies a fresh symmetric key will be
    // minted server-side, so drop any leftover JWK content.
    setPublicJwkText('')
    setPublicJwkError(null)
  }

  const openEdit = (c: OAuthClient) => {
    const initialGrants = (c.grant_types || []) as GrantType[]
    setEditClientId(c.client_id)
    setOriginalGrantTypes(initialGrants)
    setOriginalIsConfidential(c.is_confidential)
    setName(c.client_name || c.name || '')
    setDescription(c.description || '')
    setGrantTypes(initialGrants)
    setIsConfidential(c.is_confidential)
    setAuthMethod((c.token_endpoint_auth_method as AuthMethod) || (c.is_confidential ? 'client_secret_basic' : 'none'))
    setRedirectUris(c.redirect_uris?.length ? c.redirect_uris : [''])
    setAllowedPostLogoutRedirectUris(c.allowed_post_logout_redirect_uris?.length ? c.allowed_post_logout_redirect_uris : [''])
    setRequirePkce(c.require_pkce ?? false)
    setRequireConsent(c.require_consent ?? true)
    setHomepageUri(c.homepage_uri || '')
    setLogoUri(c.logo_uri || '')
    setTermsUri(c.terms_uri || '')
    setPrivacyUri(c.privacy_uri || '')
    setCustomCss(c.custom_css || '')
    const b = (c.branding as Record<string, unknown>) || {}
    const { light: bLight, dark: bDark, ...bBase } = b
    setBranding(bBase as Record<string, string>)
    setBrandingLight((bLight as Record<string, string>) || {})
    setBrandingDark((bDark as Record<string, string>) || {})
    setBrandingMode('base')
    setAllowedScopes((c.scopes || c.allowed_scopes || []).join(' ') || 'openid profile email')
    setAccessTokenLifetime(c.access_token_lifetime ?? 3600)
    setRefreshTokenLifetime(c.refresh_token_lifetime ?? 2592000)
    setPublicJwkText(c.public_jwk ? JSON.stringify(c.public_jwk, null, 2) : '')
    setPublicJwkError(null)
    setDpopBound(c.dpop_bound ?? false)
    setShowForm(true)
    setShowAdvanced(true)
    setFormErrors({})
    // Reset wizard for edit mode
    setWizardStep(1)
    setShowSuccess(false)
    setCreatedClientData(null)
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try { await api.delete(`/api/oauth-clients/${deleteId}`); setDeleteId(null); notify.success('Client deleted.'); await refetch() }
    catch (e) { notify.error(e instanceof Error ? e.message : 'Failed') }
  }

  const handleToggle = async (id: string, active: boolean) => {
    try { await api.post(`/api/oauth-clients/${id}/${active ? 'deactivate' : 'activate'}`); await refetch() }
    catch (e) { notify.error(e instanceof Error ? e.message : 'Failed') }
  }

  // Rotate-secret and rotate-jwt-key are now handled by
  // <RotateSecretDialog>, which performs the safeword handshake
  // internally and calls back via onRotated/onError. The state
  // hooks setRotateTarget / setRotateJwtKeyTarget are kept in this
  // component purely to control the dialog's open prop.

  // Pure validation without side effects - for use in render (e.g., disabled props)
  const checkFormValid = (): boolean => {
    if (!name.trim()) return false
    if (grantTypes.length === 0) return false
    if (grantTypes.includes('authorization_code')) {
      const uris = redirectUris.map(u => u.trim()).filter(Boolean)
      if (uris.length === 0) return false
    }
    if (authMethod === 'private_key_jwt' && !publicJwkText.trim()) return false
    if (authMethod === 'private_key_jwt') {
      try { JSON.parse(publicJwkText) } catch { return false }
    }
    return true
  }

  // Full validation with side effects - for use in event handlers
  const validateForm = (): boolean => {
    const errs: Record<string, string> = {}
    if (!name.trim()) errs.name = 'Application name is required.'
    if (grantTypes.length === 0) errs.grant_types = 'Select at least one grant type.'
    if (grantTypes.includes('authorization_code')) {
      const uris = redirectUris.map(u => u.trim()).filter(Boolean)
      if (uris.length === 0) errs.redirect_uris = 'Redirect URIs are required for authorization_code.'
    }
    // T.2: ``private_key_jwt`` requires a public JWK; ``client_secret_jwt``
    // mints the symmetric key server-side (no client input needed).
    if (authMethod === 'private_key_jwt' && !publicJwkText.trim()) {
      errs.public_jwk = 'A public JWK is required for private_key_jwt clients.'
    } else if (authMethod === 'private_key_jwt') {
      try {
        JSON.parse(publicJwkText)
        setPublicJwkError(null)
      } catch {
        errs.public_jwk = 'public_jwk is not valid JSON.'
        setPublicJwkError('public_jwk is not valid JSON.')
      }
    } else {
      setPublicJwkError(null)
    }
    setFormErrors(errs)
    return Object.keys(errs).length === 0
  }

  // Step-specific validation
  const validateStep = (step: number): boolean => {
    const errs: Record<string, string> = {}
    switch (step) {
      case 1:
        if (!selectedTemplate) errs.template = 'Please select a template.'
        break
      case 2:
        if (!name.trim()) errs.name = 'Application name is required.'
        break
      case 3:
        if (grantTypes.length === 0) errs.grant_types = 'Select at least one grant type.'
        if (grantTypes.includes('authorization_code')) {
          const uris = redirectUris.map(u => u.trim()).filter(Boolean)
          if (uris.length === 0) errs.redirect_uris = 'Redirect URIs are required for authorization_code.'
        }
        if (authMethod === 'private_key_jwt' && !publicJwkText.trim()) {
          errs.public_jwk = 'A public JWK is required for private_key_jwt clients.'
        } else if (authMethod === 'private_key_jwt') {
          try {
            JSON.parse(publicJwkText)
          } catch {
            errs.public_jwk = 'public_jwk is not valid JSON.'
          }
        }
        break
      case 4:
        // All optional fields
        break
    }
    setFormErrors(errs)
    return Object.keys(errs).length === 0
  }

  const nextStep = () => {
    if (validateStep(wizardStep)) {
      setWizardStep(prev => Math.min(prev + 1, 4))
    }
  }

  const prevStep = () => {
    setWizardStep(prev => Math.max(prev - 1, 1))
  }

  const canGoNext = () => {
    switch (wizardStep) {
      case 1: return !!selectedTemplate
      case 2: return name.trim().length > 0
      case 3: return grantTypes.length > 0 && (!grantTypes.includes('authorization_code') || redirectUris.some(u => u.trim()))
      case 4: return true
      default: return false
    }
  }

  const buildPayload = () => {
    const payload: Record<string, unknown> = {
      client_name: name,
      description: description || undefined,
      grant_types: grantTypes,
      is_confidential: isConfidential,
      token_endpoint_auth_method: authMethod,
      require_pkce: isConfidential ? requirePkce : true,
      require_consent: requireConsent,
      homepage_uri: homepageUri || undefined,
      logo_uri: logoUri || undefined,
      terms_uri: termsUri || undefined,
      privacy_uri: privacyUri || undefined,
      custom_css: customCss || undefined,
      branding: (() => {
        const clean = (o: Record<string, string>) =>
          Object.fromEntries(Object.entries(o).filter(([, v]) => typeof v === 'string' && v))
        const base = clean(branding)
        const light = clean(brandingLight)
        const dark = clean(brandingDark)
        const merged: Record<string, unknown> = { ...base }
        if (Object.keys(light).length > 0) merged.light = light
        if (Object.keys(dark).length > 0) merged.dark = dark
        return Object.keys(merged).length > 0 ? merged : undefined
      })(),
      allowed_scopes: allowedScopes.trim().split(/\s+/).filter(Boolean),
      access_token_lifetime: accessTokenLifetime,
      refresh_token_lifetime: refreshTokenLifetime,
      // T.3: opt-in DPoP binding. The server stores this as a
      // boolean flag on the client.
      dpop_bound: dpopBound,
    }
    if (grantTypes.includes('authorization_code')) {
      payload.redirect_uris = redirectUris.map(u => u.trim()).filter(Boolean)
      payload.allowed_post_logout_redirect_uris = allowedPostLogoutRedirectUris.map(u => u.trim()).filter(Boolean)
    }
    // T.2: attach the public_jwk only when the selected method
    // requires it. The textarea is JSON-encoded; validation
    // happens client-side before the payload is sent.
    if (authMethod === 'private_key_jwt' && publicJwkText.trim()) {
      try {
        payload.public_jwk = JSON.parse(publicJwkText)
      } catch {
        // The form-level validation should prevent this; if it
        // slips through we surface a friendly error before
        // dispatching.
        throw new Error('public_jwk is not valid JSON')
      }
    }
    return payload
  }

  const handleCreate = async () => {
    if (!validateForm()) return
    setSaving(true); setFormError(null)
    try {
      const res = await api.post<{
        client_id: string
        client_secret: string
        // T.2: server returns the symmetric key in plaintext at
        // creation time. May be ``null`` for non-JWT methods.
        client_secret_jwt_key?: string | null
      }>('/api/oauth-clients', buildPayload())
      setCreatedClientData({
        client_id: res.client_id,
        client_secret: res.client_secret,
        client_secret_jwt_key: res.client_secret_jwt_key ?? null,
      })
      setShowSuccess(true)
      setShowForm(false)
      resetForm()
      notify.success('Client created.')
      await refetch()
    } catch (err: unknown) {
      setFormError(friendlyError(err instanceof Error ? err.message : 'Failed to create client'))
    } finally { setSaving(false) }
  }

  const handleUpdate = async () => {
    if (!editClientId || !validateForm()) return
    setSaving(true); setFormError(null)
    try {
      await api.put(`/api/oauth-clients/${editClientId}`, buildPayload())
      setShowForm(false)
      resetForm()
      notify.success('Client updated.')
      await refetch()
    } catch (err: unknown) {
      setFormError(friendlyError(err instanceof Error ? err.message : 'Failed to update client'))
    } finally { setSaving(false) }
  }

  const handleSubmit = async () => {
    if (editClientId) await handleUpdate()
    else await handleCreate()
  }

  // Code snippets for success screen
  const getCodeSnippet = (framework: string, client: { client_id: string; client_secret: string; client_secret_jwt_key?: string | null }): string => {
    const { client_id, client_secret, client_secret_jwt_key } = client
    const baseUrl = typeof window !== 'undefined' ? window.location.origin : 'https://your-authglow.example.com'
    const authUrl = `${baseUrl}/oauth/authorize`
    const tokenUrl = `${baseUrl}/oauth/token`
    const jwksUrl = `${baseUrl}/oauth/jwks`
    const scopes = 'openid profile email offline_access'

    switch (framework) {
      case 'nextjs':
        return `# .env.local
AUTH_SECRET=$(openssl rand -base64 32)
AUTH_AUTHGLOW_ID=${client_id}
AUTH_AUTHGLOW_SECRET=${client_secret}
AUTH_AUTHGLOW_ISSUER=${baseUrl}

# app/api/auth/[...nextauth]/route.ts
import NextAuth from "next-auth"
import AuthGlow from "next-auth/providers/authglow"

export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [AuthGlow({
    clientId: process.env.AUTH_AUTHGLOW_ID,
    clientSecret: process.env.AUTH_AUTHGLOW_SECRET,
    issuer: process.env.AUTH_AUTHGLOW_ISSUER,
  })],
})`

      case 'react':
        return `# .env
VITE_AUTHGLOW_CLIENT_ID=${client_id}
VITE_AUTHGLOW_ISSUER=${baseUrl}

# main.tsx / App.tsx
import { AuthGlowProvider, useAuthGlow } from 'react-authglow'

<AuthGlowProvider
  clientId={import.meta.env.VITE_AUTHGLOW_CLIENT_ID}
  issuer={import.meta.env.VITE_AUTHGLOW_ISSUER}
  redirectUri={window.location.origin + '/callback'}
  scopes="${scopes}"
>
  <App />
</AuthGlowProvider>

// In your component:
const { login, logout, user, accessToken } = useAuthGlow()`

      case 'python':
        return `# requirements.txt
authlib==1.3.1
python-dotenv==1.0.1

# .env
AUTHGLOW_CLIENT_ID=${client_id}
AUTHGLOW_CLIENT_SECRET=${client_secret}
AUTHGLOW_ISSUER=${baseUrl}
AUTHGLOW_REDIRECT_URI=http://localhost:8000/callback

# main.py
from authlib.integrations.starlette_client import OAuth
from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
import os

app = Starlette()
app.add_middleware(SessionMiddleware, secret_key=os.urandom(32))

oauth = OAuth()
oauth.register(
  name='authglow',
  client_id=os.getenv('AUTHGLOW_CLIENT_ID'),
  client_secret=os.getenv('AUTHGLOW_CLIENT_SECRET'),
  server_metadata_url=f"{os.getenv('AUTHGLOW_ISSUER')}/.well-known/openid-configuration",
  client_kwargs={'scope': '${scopes}'}
)

@app.route('/login')
async def login(request):
  redirect_uri = os.getenv('AUTHGLOW_REDIRECT_URI')
  return await oauth.authglow.authorize_redirect(request, redirect_uri)

@app.route('/callback')
async def auth_callback(request):
  token = await oauth.authglow.authorize_access_token(request)
  user = token.get('userinfo')
  request.session['user'] = user
  return RedirectResponse(url='/')`

      case 'node':
        return `# npm i openid-client express-session dotenv
# .env
AUTHGLOW_CLIENT_ID=${client_id}
AUTHGLOW_CLIENT_SECRET=${client_secret}
AUTHGLOW_ISSUER=${baseUrl}
AUTHGLOW_REDIRECT_URI=http://localhost:3000/callback
SESSION_SECRET=$(openssl rand -base64 32)

// app.js
import { Issuer, generators } from 'openid-client'
import express from 'express'
import session from 'express-session'
import dotenv from 'dotenv'
dotenv.config()

const app = express()
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: true }))

const issuer = await Issuer.discover(process.env.AUTHGLOW_ISSUER)
const client = new issuer.Client({
  client_id: process.env.AUTHGLOW_CLIENT_ID,
  client_secret: process.env.AUTHGLOW_CLIENT_SECRET,
  redirect_uris: [process.env.AUTHGLOW_REDIRECT_URI],
  response_types: ['code'],
})

app.get('/login', (req, res) => {
  const codeVerifier = generators.codeVerifier()
  const codeChallenge = generators.codeChallenge(codeVerifier)
  req.session.codeVerifier = codeVerifier
  res.redirect(client.authorizationUrl({ scope: '${scopes}', code_challenge: codeChallenge, code_challenge_method: 'S256' }))
})

app.get('/callback', async (req, res) => {
  const params = client.callbackParams(req)
  const tokenSet = await client.callback(process.env.AUTHGLOW_REDIRECT_URI, params, { code_verifier: req.session.codeVerifier })
  req.session.user = tokenSet.claims()
  res.redirect('/')
})`

      case 'go':
        return `# go get github.com/coreos/go-oidc/v3/oidc golang.org/x/oauth2

package main

import (
  "context"
  "net/http"
  "github.com/coreos/go-oidc/v3/oidc"
  "golang.org/x/oauth2"
)

var (
  clientID     = "${client_id}"
  clientSecret = "${client_secret}"
  issuerURL    = "${baseUrl}"
  redirectURL  = "http://localhost:8080/callback"
)

func main() {
  ctx := context.Background()
  provider, _ := oidc.NewProvider(ctx, issuerURL)
  oauth2Config := &oauth2.Config{
    ClientID:     clientID,
    ClientSecret: clientSecret,
    RedirectURL:  redirectURL,
    Endpoint:     provider.Endpoint(),
    Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "offline_access"},
  }

  http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
    http.Redirect(w, r, oauth2Config.AuthCodeURL("state", oauth2.AccessTypeOffline), http.StatusFound)
  })

  http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
    token, _ := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
    // Use token.AccessToken, token.RefreshToken
  })

  http.ListenAndServe(":8080", nil)
}`

      case 'dotnet':
        return `# NuGet: Microsoft.AspNetCore.Authentication.OpenIdConnect

// appsettings.json
{
  "AuthGlow": {
    "ClientId": "${client_id}",
    "ClientSecret": "${client_secret}",
    "Authority": "${baseUrl}",
    "CallbackPath": "/signin-oidc",
    "Scopes": ["openid", "profile", "email", "offline_access"]
  }
}

// Program.cs
builder.Services.AddAuthentication(options => {
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
  })
  .AddCookie()
  .AddOpenIdConnect("AuthGlow", options => {
    var cfg = builder.Configuration.GetSection("AuthGlow");
    options.ClientId = cfg["ClientId"];
    options.ClientSecret = cfg["ClientSecret"];
    options.Authority = cfg["Authority"];
    options.CallbackPath = cfg["CallbackPath"];
    options.ResponseType = "code";
    options.SaveTokens = true;
    foreach (var scope in cfg.GetSection("Scopes").Get<string[]>())
      options.Scope.Add(scope);
  });

app.UseAuthentication();
app.UseAuthorization();`

      default:
        return ''
    }
  }

  const getDocUrl = (framework: string): string => {
    const docs: Record<string, string> = {
      nextjs: 'https://next-auth.js.org/providers/authglow',
      react: 'https://github.com/authglow/react-authglow',
      python: 'https://docs.authlib.org/en/latest/client/oidc.html',
      node: 'https://github.com/panva/node-openid-client',
      go: 'https://github.com/coreos/go-oidc',
      dotnet: 'https://learn.microsoft.com/aspnet/core/security/authentication/oidc',
    }
    return docs[framework] || '#'
  }

  const toggleGrantType = (g: GrantType) => {
    setGrantTypes(prev => prev.includes(g) ? prev.filter(x => x !== g) : [...prev, g])
    setFormErrors({ ...formErrors, grant_types: '' })
    if (g === 'authorization_code' && !redirectUris.length) setRedirectUris([''])
  }

  const addRedirectUri = () => setRedirectUris([...redirectUris, ''])
  const removeRedirectUri = (i: number) => setRedirectUris(redirectUris.filter((_, idx) => idx !== i))
  const updateRedirectUri = (i: number, v: string) => {
    const next = [...redirectUris]; next[i] = v
    setRedirectUris(next); setFormErrors({...formErrors, redirect_uris: ''})
  }

  const addLogoutUri = () => setAllowedPostLogoutRedirectUris([...allowedPostLogoutRedirectUris, ''])
  const removeLogoutUri = (i: number) => setAllowedPostLogoutRedirectUris(allowedPostLogoutRedirectUris.filter((_, idx) => idx !== i))
  const updateLogoutUri = (i: number, v: string) => {
    const next = [...allowedPostLogoutRedirectUris]; next[i] = v
    setAllowedPostLogoutRedirectUris(next)
  }

  const showRedirectUris = grantTypes.includes('authorization_code')
  const showLogoutUris = grantTypes.includes('authorization_code')
  const showBreakingChangeWarning = editClientId && (
    JSON.stringify([...grantTypes].sort()) !== JSON.stringify([...originalGrantTypes].sort()) ||
    isConfidential !== originalIsConfidential
  )

  const clientDisplayName = (c: OAuthClient) => c.client_name || c.name || c.client_id
  const clientGrantTypes = (c: OAuthClient) => c.grant_types || []
  const clientScopes = (c: OAuthClient) => c.scopes || c.allowed_scopes || []

  return (
    <div className="space-y-6">
      <PageHeader
        title="OAuth Clients"
        description="Applications that authenticate users through AuthGlow."
        actions={
          <button onClick={() => { resetForm(); setShowForm(true) }} data-testid="create-oauth-client-btn" className="flex items-center gap-1.5 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98]">
            <Plus size={16} /> Create Client
          </button>
        }
      />

      {!clients || clients.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-surface-2 bg-surface-1 py-16 text-center">
          <div className="rounded-2xl bg-surface-2 p-4"><KeyRound className="h-8 w-8 text-text-muted" /></div>
          <h3 className="mt-4 text-lg font-semibold text-text-primary">No OAuth clients yet</h3>
          <p className="mt-2 max-w-sm text-sm text-text-muted">Create your first client to let applications authenticate users.</p>
          <button onClick={() => { resetForm(); setShowForm(true) }} className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98]">
            <Plus size={16} /> Create Client
          </button>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Name</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Client ID</th>
                <th className="hidden md:table-cell px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Redirect URIs</th>
                <th className="hidden md:table-cell px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Grants</th>
                <th className="hidden md:table-cell px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Scopes</th>
                <th className="hidden md:table-cell px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase w-20">Type</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase w-20">Status</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {clients.map((c, idx) => (
                <tr key={c.client_id || idx} className="hover:bg-surface-2/50">
                  <td className="px-4 py-2.5 text-sm font-medium text-text-primary">{clientDisplayName(c)}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <code className="text-xs font-mono text-text-secondary">{c.client_id}</code>
                      <CopyButton text={c.client_id} />
                    </div>
                  </td>
                  <td className="hidden md:table-cell px-4 py-2.5">
                    <div className="flex flex-wrap gap-1 max-w-[200px]">
                      {(c.redirect_uris || []).slice(0, 2).map(u => (
                        <span key={u} className="truncate rounded-lg bg-surface-2 px-2 py-0.5 text-[10px] font-mono text-text-secondary" title={u}>
                          {u.length > 25 ? u.slice(0, 25) + '...' : u}
                        </span>
                      ))}
                      {(c.redirect_uris || []).length > 2 && <span className="text-[10px] text-text-muted">+{c.redirect_uris.length - 2} more</span>}
                    </div>
                  </td>
                  <td className="hidden md:table-cell px-4 py-2.5"><div className="flex flex-wrap gap-1">{clientGrantTypes(c).map(g => <span key={g} className="rounded-lg bg-surface-2 px-2 py-0.5 text-[10px] text-text-secondary">{g}</span>)}</div></td>
                  <td className="hidden md:table-cell px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {clientScopes(c).slice(0, 3).map((s: string) => <span key={s} className="rounded-lg bg-surface-2 px-2 py-0.5 text-[10px] text-text-secondary">{s}</span>)}
                      {clientScopes(c).length > 3 && <span className="text-[10px] text-text-muted">+{clientScopes(c).length - 3} more</span>}
                      {clientScopes(c).length === 0 && <span className="text-[10px] text-text-muted">-</span>}
                    </div>
                  </td>
                  <td className="hidden md:table-cell px-4 py-2.5"><span className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${c.is_confidential ? 'bg-brand-wash text-brand-accent' : 'bg-surface-2 text-text-muted'}`}>{c.is_confidential ? 'Confidential' : 'Public'}{c.dpop_bound ? <span className="ml-1 inline-flex rounded-lg bg-semantic-info/10 px-1.5 py-0.5 text-[10px] font-semibold text-semantic-info" data-testid="dpop-badge">DPoP</span> : null}</span></td>
                  <td className="px-4 py-2.5">
                    <button onClick={() => handleToggle(c.client_id, c.is_active)} className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium ${c.is_active ? 'bg-semantic-success/10 text-semantic-success' : 'bg-semantic-error/10 text-semantic-error'}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${c.is_active ? 'bg-semantic-success' : 'bg-semantic-error'}`} />
                      {c.is_active ? 'On' : 'Off'}
                    </button>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex gap-2">
                      {c.require_consent !== false && (
                        <button onClick={() => setPreviewClient(c)} className="text-text-muted hover:text-text-secondary" title="Preview consent screen"><Eye size={14} /></button>
                      )}
                      <button
                        onClick={() => setClaimsClient({ id: c.client_id, name: clientDisplayName(c) })}
                        data-testid="open-claims-btn"
                        className="text-text-muted hover:text-brand-accent"
                        title="Token Claims (customize JWT claims)"
                      >
                        <KeyRound size={14} />
                      </button>
                      <button onClick={() => openEdit(c)} className="text-text-muted hover:text-text-secondary" title="Edit client"><Edit size={14} /></button>
                      <button onClick={() => setRotateTarget(c.client_id)} data-testid="rotate-secret-btn" className="text-text-muted hover:text-text-secondary" title="Rotate secret"><RefreshCw size={14} /></button>
                      {/* T.2: rotate the JWT key for client_secret_jwt clients. */}
                      {c.token_endpoint_auth_method === 'client_secret_jwt' && c.has_client_secret_jwt_key && (
                        <button
                          onClick={() => setRotateJwtKeyTarget(c.client_id)}
                          data-testid="rotate-jwt-key-btn"
                          className="text-text-muted hover:text-brand-accent"
                          title="Rotate JWT key"
                        >
                          <RefreshCw size={14} />
                        </button>
                      )}
                      <button onClick={() => setDeleteId(c.client_id || idx.toString())} data-testid="delete-client-btn" className="text-text-muted hover:text-semantic-error" title="Delete"><Trash2 size={14} /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog open={!!deleteId} title="Delete OAuth Client" message="All tokens for this client will be revoked. This action cannot be undone." confirmLabel="Delete" variant="danger" onConfirm={handleDelete} onCancel={() => setDeleteId(null)} />

      {/* Rotate secret — destructive, gated by a server-issued
          safeword. The dialog walks the operator through three
          phases: confirm, safeword (challenge issued + typed back),
          error/retry. The destructive POST only fires on success. */}
      <RotateSecretDialog
        open={!!rotateTarget}
        targetId={rotateTarget}
        targetLabel={
          data?.find?.((x) => x?.client_id === rotateTarget)?.client_name
        }
        purpose="secret"
        onClose={() => setRotateTarget(null)}
        onSuccess={(newCredential) => {
          if (newCredential) setSecretModal(newCredential)
        }}
        onError={(msg) => notify.error(msg)}
      />

      {/* Rotate JWT key — T.2, same destructive semantics. */}
      <RotateSecretDialog
        open={!!rotateJwtKeyTarget}
        targetId={rotateJwtKeyTarget}
        targetLabel={
          data?.find?.((x) => x?.client_id === rotateJwtKeyTarget)?.client_name
        }
        purpose="jwt_key"
        onClose={() => setRotateJwtKeyTarget(null)}
        onSuccess={(newCredential) => {
          if (newCredential) setJwtKeyModal(newCredential)
        }}
        onError={(msg) => notify.error(msg)}
      />

      {/* Secret modal */}
      {secretModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => { setSecretModal(null); setNewClientId('') }} />
          <div className="relative z-10 w-full max-w-md sm:max-w-2xl rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-accent" data-testid="client-created-secret">
            <h3 className="text-lg font-semibold text-text-primary">{newClientId ? 'Client Created' : 'New Secret'}</h3>
            {newClientId && <p className="text-xs text-text-muted">Client ID: <code className="text-text-secondary">{newClientId}</code></p>}
            <p className="text-xs text-semantic-warning">Copy this secret now. You will not be able to see it again.</p>
            <div className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-2 px-4 py-3">
              <code className="flex-1 min-w-0 break-words text-sm font-mono text-text-primary sm:whitespace-nowrap sm:break-normal">{secretModal}</code>
              <CopyButton text={secretModal} label="Copy" className="flex-shrink-0" />
            </div>
            {/* T.2: client_secret_jwt clients also receive a symmetric
                key in the same envelope. Display it in the same modal
                so the admin can hand both secrets to the operator in
                one step. */}
            {jwtKeyModal && (
              <div className="space-y-2 border-t border-surface-2 pt-4">
                <p className="text-xs font-semibold text-text-secondary">JWT signing key (HS256)</p>
                <p className="text-xs text-semantic-warning">Copy this key now. It will not be shown again.</p>
                <div className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-2 px-4 py-3">
                  <code className="flex-1 min-w-0 break-words text-sm font-mono text-text-primary sm:whitespace-nowrap sm:break-normal" data-testid="client-jwt-key">{jwtKeyModal}</code>
                  <CopyButton text={jwtKeyModal} label="Copy" className="flex-shrink-0" />
                </div>
              </div>
            )}
            <button onClick={() => { setSecretModal(null); setNewClientId(''); setJwtKeyModal(null) }} data-testid="client-created-done" className="w-full rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2">Close</button>
          </div>
        </div>
      )}

      {/* T.2: standalone modal for ``rotate-jwt-key`` (no client_id
          is shown because the admin is mid-rotation on an existing
          client). */}
      {jwtKeyModal && !secretModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setJwtKeyModal(null)} />
          <div className="relative z-10 w-full max-w-md sm:max-w-2xl rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-accent" data-testid="client-rotated-jwt-key">
            <h3 className="text-lg font-semibold text-text-primary">New JWT Signing Key</h3>
            <p className="text-xs text-semantic-warning">
              The previous key is now invalid. Copy the new key and hand it to the client operator immediately.
            </p>
            <div className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-2 px-4 py-3">
              <code className="flex-1 min-w-0 break-words text-sm font-mono text-text-primary sm:whitespace-nowrap sm:break-normal">{jwtKeyModal}</code>
              <CopyButton text={jwtKeyModal} label="Copy" className="flex-shrink-0" />
            </div>
            <button onClick={() => setJwtKeyModal(null)} data-testid="jwt-key-rotated-done" className="w-full rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2">Close</button>
          </div>
        </div>
      )}

      {/* Preview consent screen modal */}
      {previewClient && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-8">
          <div className="absolute inset-0 bg-black/50" onClick={() => setPreviewClient(null)} />
          <div className="relative z-10 flex w-full max-w-lg flex-col rounded-2xl border border-surface-2 bg-bg-primary shadow-glow-accent max-h-[calc(100vh-4rem)]">
            <div className="flex flex-shrink-0 items-center justify-between border-b border-surface-2 px-6 py-4">
              <h3 className="text-lg font-semibold text-text-primary">Consent Screen Preview</h3>
              <button onClick={() => setPreviewClient(null)} className="rounded-lg px-3 py-1.5 text-sm text-text-muted hover:bg-surface-2 hover:text-text-secondary transition-colors">Close</button>
            </div>
            <div className="flex-1 overflow-y-auto">
              <ConsentScreen
                clientName={previewClient.client_name || previewClient.name || 'Untitled'}
                clientDescription={previewClient.description}
                clientLogoUri={previewClient.logo_uri}
                clientHomepageUri={previewClient.homepage_uri}
                clientTermsUri={previewClient.terms_uri}
                clientPrivacyUri={previewClient.privacy_uri}
                redirectUri={previewClient.redirect_uris?.[0]}
                scopes={(previewClient.allowed_scopes || previewClient.scopes || ['openid', 'profile', 'email']).map(s => ({
                  name: s,
                  description: getScopeLabel(s),
                }))}
                branding={previewClient.branding}
                preview
              />
            </div>
          </div>
        </div>
      )}

      {/* Create / Edit Client Modal - Wizard Version */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-8" onClick={(e) => { if (e.target === e.currentTarget) { setShowForm(false); resetForm() } }}>
          <div className="absolute inset-0 bg-black/50" onClick={() => { setShowForm(false); resetForm() }} />
          <div className="relative z-10 flex w-full max-w-3xl flex-col rounded-2xl border border-surface-2 bg-surface-1 shadow-glow-accent max-h-[calc(100vh-4rem)]">
            {/* Header - matches TokenClaimsTab style */}
            <div className="flex flex-shrink-0 items-center justify-between border-b border-surface-2 px-6 py-4">
              <div>
                <h3 className="text-lg font-semibold text-text-primary">
                  {editClientId ? 'Edit OAuth Client' : 'New OAuth Client'}
                </h3>
                {editClientId && (
                  <p className="mt-0.5 text-xs text-text-muted">
                    <code className="text-text-secondary">{editClientId}</code>
                  </p>
                )}
              </div>
              <button
                onClick={() => { setShowForm(false); resetForm() }}
                className="rounded-lg p-1.5 text-text-muted hover:bg-surface-2 hover:text-text-secondary"
                aria-label="Close"
              >
                <X size={16} />
              </button>
            </div>
            {/* Stepper */}
            {!editClientId && !showSuccess && (
              <div className="flex-shrink-0 border-b border-surface-2 px-6 py-4" role="navigation" aria-label="Wizard steps">
                <div className="flex items-center gap-2">
                  {[
                    { num: 1, label: 'Template' },
                    { num: 2, label: 'Identity' },
                    { num: 3, label: 'Security' },
                    { num: 4, label: 'Tokens & Branding' },
                  ].map((step, idx) => (
                    <div key={step.num} className="flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => step.num <= wizardStep && setWizardStep(step.num)}
                        disabled={step.num > wizardStep}
                        className={cn(
                          'flex items-center gap-1.5 text-[11px] font-medium transition-colors',
                          step.num === wizardStep
                            ? 'text-brand-accent'
                            : step.num < wizardStep
                            ? 'text-semantic-success'
                            : 'text-text-muted cursor-not-allowed'
                        )}
                        aria-current={step.num === wizardStep ? 'step' : undefined}
                      >
                        <span className={cn(
                          'flex h-6 w-6 items-center justify-center rounded-full text-[10px] font-semibold',
                          step.num === wizardStep
                            ? 'bg-brand-wash text-brand-accent border border-brand-accent'
                            : step.num < wizardStep
                            ? 'bg-semantic-success/10 text-semantic-success border border-semantic-success'
                            : 'bg-surface-2 text-text-muted border border-surface-3'
                        )}>
                          {step.num < wizardStep ? <CheckCircle2 size={10} /> : step.num}
                        </span>
                        <span className="hidden sm:inline">{step.label}</span>
                      </button>
                      {idx < 3 && (
                        <div className={cn(
                          'flex-1 h-0.5 rounded',
                          idx + 1 < wizardStep ? 'bg-semantic-success' : 'bg-surface-2'
                        )} />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div className="flex-1 overflow-y-auto p-6">
              {formError && (
                <div className="mb-4">
                  <Banner
                    variant="error"
                    sticky
                    onDismiss={() => setFormError(null)}
                    data-testid="oauth-client-form-error"
                  >
                    {formError}
                  </Banner>
                </div>
              )}
              {!editClientId && !showSuccess && wizardStep === 1 && (
                <div className="mb-6">
                  <p className="mb-3 text-sm text-text-muted">Choose a template to pre-fill recommended settings</p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {TEMPLATES.map(t => (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => { applyTemplate(t); setWizardStep(2); }}
                        data-testid={`template-${t.id}`}
                        className={cn(
                          'flex flex-col items-start gap-2 rounded-xl border p-4 transition-all text-left',
                          selectedTemplate === t.id
                            ? 'border-brand-accent bg-brand-wash shadow-glow-accent/20'
                            : 'border-surface-2 hover:border-surface-3 hover:bg-surface-2'
                        )}
                      >
                        <div className="flex items-center gap-2">
                          <div className={cn(
                            'flex h-8 w-8 items-center justify-center rounded-lg',
                            selectedTemplate === t.id ? 'bg-brand-accent text-white' : 'bg-surface-2 text-text-secondary'
                          )}>
                            <t.icon size={16} />
                          </div>
                          <div>
                            <p className="font-medium text-sm text-text-primary">{t.label}</p>
                            <p className="text-[11px] text-text-muted">{t.desc}</p>
                          </div>
                        </div>
                        {selectedTemplate === t.id && (
                          <div className="flex w-full items-center justify-end">
                            <CheckCircle2 size={16} className="text-brand-accent" />
                          </div>
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* Breaking change warning in edit mode */}
              {showBreakingChangeWarning && (
                <div className="flex items-start gap-2 rounded-xl border border-semantic-warning/30 bg-semantic-warning/10 px-4 py-3 text-xs text-semantic-warning mb-5" data-testid="breaking-change-warning">
                  <AlertTriangle size={16} className="mt-0.5 shrink-0" />
                  <div>
                    <p className="font-semibold">Heads up: changing grant types or client type can break existing integrations.</p>
                    <p className="mt-1 text-text-muted">Apps currently using this client may stop working. Consider rotating the secret or notifying clients first.</p>
                  </div>
                </div>
              )}

              {/* Wizard Step 2: Identity */}
              {!editClientId && !showSuccess && wizardStep === 2 && (
                <div className="space-y-4">
                  <div>
                    <label className="mb-1 block text-[11px] font-medium text-text-secondary">Application name <span className="text-semantic-error">*</span></label>
                    <TextInput value={name} onChange={v => { setName(v); setFormErrors({...formErrors, name: ''}) }} placeholder="My Application" data-testid="client-name-input" autoFocus />
                    {formErrors.name && <FieldError id="client-name-error">{formErrors.name}</FieldError>}
                  </div>

                  <div>
                    <label className="mb-1 block text-[11px] font-medium text-text-secondary">Description</label>
                    <textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="What does this client do?" rows={2} className="w-full rounded-xl border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20 resize-y" />
                  </div>
                </div>
              )}

              {/* Wizard Step 3: Security */}
              {!editClientId && !showSuccess && wizardStep === 3 && (
                <div className="space-y-4">
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-secondary">Grant types <span className="text-semantic-error">*</span></label>
                    <div className="space-y-1">
                      {ALL_GRANT_TYPES.map(g => (
                        <label key={g.id} className={cn(
                          'flex items-center gap-2 rounded-lg px-2.5 py-1.5 cursor-pointer transition-colors',
                          grantTypes.includes(g.id) ? 'bg-brand-wash' : 'hover:bg-surface-2'
                        )}>
                          <input
                            type="checkbox"
                            checked={grantTypes.includes(g.id)}
                            onChange={() => toggleGrantType(g.id)}
                            data-testid={`grant-${g.id}`}
                            className="h-3.5 w-3.5 rounded border-surface-3 text-brand-accent focus:ring-brand-accent/20"
                          />
                          <span className="text-xs text-text-primary">{g.label}</span>
                        </label>
                      ))}
                    </div>
                    {formErrors.grant_types && <FieldError id="client-grants-error">{formErrors.grant_types}</FieldError>}
                  </div>

                  <div className="rounded-xl border border-surface-2 bg-nested-panel p-4 space-y-4">
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Client type</label>
                      <div className="flex gap-1.5">
                        <button
                          type="button"
                          onClick={() => { setIsConfidential(true); setAuthMethod('client_secret_basic') }}
                          data-testid="client-type-confidential"
                          className={cn(
                            'flex-1 rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors',
                            isConfidential ? 'border-brand-accent bg-brand-wash text-brand-accent' : 'border-surface-2 text-text-muted hover:bg-surface-1'
                          )}
                        >
                          Confidential
                        </button>
                        <button
                          type="button"
                          onClick={() => { setIsConfidential(false); setAuthMethod('none'); setRequirePkce(true) }}
                          data-testid="client-type-public"
                          className={cn(
                            'flex-1 rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors',
                            !isConfidential ? 'border-brand-accent bg-brand-wash text-brand-accent' : 'border-surface-2 text-text-muted hover:bg-surface-1'
                          )}
                        >
                          Public
                        </button>
                      </div>
                      <p className="mt-1 text-[10px] text-text-muted">
                        {isConfidential ? 'Has a client secret. Server-side apps.' : 'No secret. SPAs / mobile. PKCE required.'}
                      </p>
                    </div>

                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Auth method</label>
                      <select
                        value={authMethod}
                        onChange={e => setAuthMethod(e.target.value as AuthMethod)}
                        disabled={!isConfidential}
                        className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-[11px] text-text-primary focus:border-brand-accent focus:outline-none btn-cta disabled:cursor-not-allowed"
                      >
                        <option value="client_secret_basic">client_secret_basic</option>
                        <option value="client_secret_post">client_secret_post</option>
                        {/* T.2: FAPI 2.0 / RFC 7521 alternatives. */}
                        <option value="client_secret_jwt">client_secret_jwt (HS256)</option>
                        <option value="private_key_jwt">private_key_jwt (RS256)</option>
                        {!isConfidential && <option value="none">none (public)</option>}
                      </select>
                      <p className="mt-1 text-[10px] text-text-muted">
                        {authMethod === 'client_secret_jwt' && 'Symmetric key is generated server-side and shown once.'}
                        {authMethod === 'private_key_jwt' && 'Upload the public JWK below. Sign client_assertions with the matching private key.'}
                        {(authMethod === 'client_secret_basic' || authMethod === 'client_secret_post') && 'Shared secret — the operator stores it.'}
                      </p>
                    </div>

                    {/* T.2: client_secret_jwt key indicator (read-only). */}
                    {authMethod === 'client_secret_jwt' && (
                      <div className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-[10px] text-text-muted">
                        {editClientId
                          ? 'A symmetric key is configured. Use Rotate JWT key to issue a new one (the old key is invalidated immediately).'
                          : 'A symmetric key will be generated and shown once after creation.'}
                      </div>
                    )}

{/* T.2: public JWK input for private_key_jwt. */}
                    {authMethod === 'private_key_jwt' && (
                      <div>
                        <label className="mb-1.5 block text-[11px] font-medium text-text-muted">
                          Public JWK (JSON)
                        </label>
                        <textarea
                          value={publicJwkText}
                          onChange={e => { setPublicJwkText(e.target.value); setPublicJwkError(null); setFormErrors({ ...formErrors, public_jwk: '' }) }}
                          placeholder={'{\n  "kty": "RSA",\n  "n": "...",\n  "e": "AQAB"\n}'}
                          rows={5}
                          data-testid="public-jwk-input"
                          className="w-full rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] font-mono text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
                        />
                        {publicJwkError && <FieldError id="public-jwk-error">{publicJwkError}</FieldError>}
                        {!publicJwkError && formErrors.public_jwk && <FieldError id="public-jwk-error">{formErrors.public_jwk}</FieldError>}
                      </div>
                    )}

                    {showRedirectUris && (
                      <div>
                        <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Redirect URIs <span className="text-semantic-error">*</span></label>
                        <div className="space-y-1.5">
                          {redirectUris.map((uri, i) => (
                            <div key={i} className="flex items-center gap-1.5">
                              <input value={uri} onChange={e => updateRedirectUri(i, e.target.value)} placeholder={`https://app.example.com/cb${i+1}`} data-testid={`client-uri-input-${i}`} type="url" spellCheck={false} autoComplete="off" className="flex-1 rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] font-mono text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                              {redirectUris.length > 1 && <button type="button" onClick={() => removeRedirectUri(i)} className="shrink-0 text-text-muted hover:text-semantic-error"><Trash2 size={12} /></button>}
                            </div>
                          ))}
                        </div>
                        <button type="button" onClick={addRedirectUri} className="mt-1.5 text-[11px] text-brand-accent hover:text-brand-cool font-medium">+ Add URI</button>
                        {formErrors.redirect_uris && <FieldError id="client-redirect-uris-error">{formErrors.redirect_uris}</FieldError>}
                      </div>
                    )}

                    {showLogoutUris && (
                      <div>
                        <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Logout Redirect URIs <span className="text-text-muted">(optional)</span></label>
                        <p className="mb-1.5 text-[10px] text-text-muted">Where to redirect users after logout (OIDC post_logout_redirect_uri)</p>
                        <div className="space-y-1.5">
{allowedPostLogoutRedirectUris.map((uri, i) => (
                            <div key={i} className="flex items-center gap-1.5">
                              <input value={uri} onChange={e => updateLogoutUri(i, e.target.value)} placeholder={`https://app.example.com/logout${i+1}`} data-testid={`client-logout-uri-input-${i}`} autoComplete="off" className="flex-1 rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] font-mono text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                              {allowedPostLogoutRedirectUris.length > 1 && <button type="button" onClick={() => removeLogoutUri(i)} className="shrink-0 text-text-muted hover:text-semantic-error"><Trash2 size={12} /></button>}
                            </div>
                          ))}
                        </div>
                        <button type="button" onClick={addLogoutUri} className="mt-1.5 text-[11px] text-brand-accent hover:text-brand-cool font-medium">+ Add URI</button>
                      </div>
                    )}

                    <div className="space-y-2 pt-1 border-t border-surface-2">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={isConfidential ? requirePkce : true}
                          onChange={e => setRequirePkce(e.target.checked)}
                          disabled={!isConfidential}
                          className="h-3.5 w-3.5 rounded border-surface-3 text-brand-accent focus:ring-brand-accent/20 btn-cta"
                        />
                        <span className={cn('text-[11px]', !isConfidential && 'text-text-muted')}>
                          Require PKCE
                          {!isConfidential && <span className="ml-1 text-[10px]">(required)</span>}
                        </span>
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={requireConsent}
                          onChange={e => setRequireConsent(e.target.checked)}
                          className="h-3.5 w-3.5 rounded border-surface-3 text-brand-accent focus:ring-brand-accent/20"
                        />
                        <span className="text-[11px] text-text-primary">Require consent screen</span>
                      </label>

                      {/* T.3: DPoP binding toggle (RFC 9449). */}
                      <label className="flex items-center gap-2 cursor-pointer" data-testid="dpop-bound-label">
                        <input
                          type="checkbox"
                          checked={dpopBound}
                          onChange={e => setDpopBound(e.target.checked)}
                          data-testid="dpop-bound-toggle"
                          className="h-3.5 w-3.5 rounded border-surface-3 text-brand-accent focus:ring-brand-accent/20"
                        />
                        <span className="text-[11px] text-text-primary">
                          DPoP-bound tokens
                          <span className="ml-1 text-[10px] text-text-muted">(FAPI 2.0)</span>
                        </span>
                      </label>
                      {dpopBound && (
                        <p className="text-[10px] text-text-muted pl-5">
                          Client must generate an ES256 key pair and sign a DPoP proof JWT on every request.
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Wizard Step 4: Tokens & Branding (Advanced) */}
              {!editClientId && !showSuccess && wizardStep === 4 && (
                <div className="space-y-4">
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Allowed scopes</label>
                    <ScopePicker value={allowedScopes} onChange={setAllowedScopes} placeholder="Add custom scope" />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Homepage URI</label>
                      <input value={homepageUri} onChange={e => setHomepageUri(e.target.value)} placeholder="https://app.example.com" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                    </div>
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Logo URI</label>
                      <input value={logoUri} onChange={e => setLogoUri(e.target.value)} placeholder="https://app.example.com/logo.png" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                    </div>
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Terms URI</label>
                      <input value={termsUri} onChange={e => setTermsUri(e.target.value)} placeholder="https://app.example.com/tos" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                    </div>
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Privacy URI</label>
                      <input value={privacyUri} onChange={e => setPrivacyUri(e.target.value)} placeholder="https://app.example.com/privacy" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                    </div>
                  </div>

                  <div className="pt-3 border-t border-surface-2">
                    <div className="mb-1 flex items-center justify-between">
                      <h4 className="text-[11px] font-semibold text-text-muted uppercase tracking-wider">Consent Page Branding</h4>
                      <div className="flex items-center gap-1" role="tablist" aria-label="Branding variant">
                        {([['base', 'Shared'], ['light', 'Light'], ['dark', 'Dark']] as const).map(([m, l]) => (
                          <button
                            key={m}
                            type="button"
                            role="tab"
                            aria-selected={brandingMode === m}
                            data-testid={`branding-mode-${m}`}
                            onClick={() => setBrandingMode(m)}
                            className={cn(
                              'rounded-lg px-2.5 py-1 text-[11px] font-medium transition-colors',
                              brandingMode === m ? 'bg-brand-wash text-brand-accent' : 'text-text-muted hover:bg-surface-2',
                            )}
                          >
                            {l}
                          </button>
                        ))}
                      </div>
                    </div>
                    <p className="mb-3 text-[10px] text-text-muted">
                      {brandingMode === 'base'
                        ? 'Defaults for both themes: use these when the client has a single palette. The variants below only override the fields you fill in.'
                        : brandingMode === 'light'
                          ? 'Only set these if the light theme should differ from the Shared values. Leave empty to inherit.'
                          : 'Only set these if the dark theme should differ from the Shared values. A light Shared surface inherited here is automatically darkened.'}
                    </p>
                    <div className="grid grid-cols-2 gap-3">
                      <ColorField
                        label="Primary color"
                        value={modeBrand.primary_color || ''}
                        swatchFallback={brandingMode === 'base' ? '#6366f1' : (branding.primary_color || '#6366f1')}
                        placeholder={brandingMode === 'base' ? '#6366f1' : (branding.primary_color ? `shared: ${branding.primary_color}` : '#6366f1')}
                        onChange={(v) => setModeBrand({ primary_color: v })}
                      />
                      <ColorField
                        label="Surface color"
                        value={modeBrand.surface_color || ''}
                        swatchFallback={brandingMode === 'base' ? '#ffffff' : (branding.surface_color || '#ffffff')}
                        placeholder={brandingMode === 'base' ? '#ffffff' : (branding.surface_color ? `shared: ${branding.surface_color}` : '#ffffff')}
                        onChange={(v) => setModeBrand({ surface_color: v })}
                      />
                      <ColorField
                        label="Text color"
                        value={modeBrand.text_color || ''}
                        swatchFallback={brandingMode === 'base' ? '#1a1a2e' : (branding.text_color || '#1a1a2e')}
                        placeholder={brandingMode === 'base' ? 'auto (contrast)' : (branding.text_color ? `shared: ${branding.text_color}` : 'auto (contrast)')}
                        onChange={(v) => setModeBrand({ text_color: v })}
                      />
                      <div>
                        <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Border radius</label>
                        <input
                          value={modeBrand.border_radius || ''}
                          onChange={(e) => setModeBrand({ border_radius: e.target.value })}
                          placeholder={brandingMode === 'base' ? '12px' : (branding.border_radius ? `shared: ${branding.border_radius}` : '12px')}
                          className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
                        />
                      </div>
                    </div>
                    {brandingMode === 'base' && (
                      <div className="grid grid-cols-2 gap-3 mt-3">
                        <div>
                          <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Font family (both themes)</label>
                          <input value={branding.font_family || ''} onChange={e => setBranding({...branding, font_family: e.target.value})} placeholder="Inter, sans-serif" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                        </div>
                        <div>
                          <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Logo URL</label>
                          <input value={branding.logo_url || ''} onChange={e => setBranding({...branding, logo_url: e.target.value})} placeholder="https://app.example.com/logo.png" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                        </div>
                      </div>
                    )}
                    <p className="mt-2 text-[10px] text-text-muted">Button text color is auto-derived from contrast when unset. The preview follows the current theme.</p>
                  </div>

                  <div className="grid grid-cols-2 gap-3 pt-3 border-t border-surface-2">
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Access token lifetime (s)</label>
                      <input type="number" min={300} max={86400} value={accessTokenLifetime} onChange={e => setAccessTokenLifetime(Number(e.target.value))} className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary focus:border-brand-accent focus:outline-none" />
                      <p className="mt-1 text-[10px] text-text-muted">5 min – 24 hours</p>
                    </div>
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Refresh token lifetime (s)</label>
                      <input type="number" min={3600} max={7776000} value={refreshTokenLifetime} onChange={e => setRefreshTokenLifetime(Number(e.target.value))} className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary focus:border-brand-accent focus:outline-none" />
                      <p className="mt-1 text-[10px] text-text-muted">1 hour – 90 days</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Edit mode: show all fields (original behavior) */}
              {editClientId && (
                <div className="grid grid-cols-2 gap-5 mb-5">
                {/* Left column: Application identity */}
                <div className="space-y-3">
                  <p className="text-xs font-medium text-text-muted uppercase tracking-wider">Identity</p>

                  <div>
                    <label className="mb-1 block text-[11px] font-medium text-text-secondary">Application name <span className="text-semantic-error">*</span></label>
                    <TextInput value={name} onChange={v => { setName(v); setFormErrors({...formErrors, name: ''}) }} placeholder="My Application" data-testid="client-name-input" autoFocus />
                    {formErrors.name && <FieldError id="client-name-error">{formErrors.name}</FieldError>}
                  </div>

                  <div>
                    <label className="mb-1 block text-[11px] font-medium text-text-secondary">Description</label>
                    <textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="What does this client do?" rows={2} className="w-full rounded-xl border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20 resize-y" />
                  </div>

                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-secondary">Grant types <span className="text-semantic-error">*</span></label>
                    <div className="space-y-1">
                      {ALL_GRANT_TYPES.map(g => (
                        <label key={g.id} className={cn(
                          'flex items-center gap-2 rounded-lg px-2.5 py-1.5 cursor-pointer transition-colors',
                          grantTypes.includes(g.id) ? 'bg-brand-wash' : 'hover:bg-surface-2'
                        )}>
                          <input
                            type="checkbox"
                            checked={grantTypes.includes(g.id)}
                            onChange={() => toggleGrantType(g.id)}
                            data-testid={`grant-${g.id}`}
                            className="h-3.5 w-3.5 rounded border-surface-3 text-brand-accent focus:ring-brand-accent/20"
                          />
                          <span className="text-xs text-text-primary">{g.label}</span>
                        </label>
                      ))}
                    </div>
                    {formErrors.grant_types && <FieldError id="client-grants-error">{formErrors.grant_types}</FieldError>}
                  </div>
                </div>

              {/* Right column: Security configuration */}
              <div className="space-y-4">
                <p className="text-xs font-medium text-text-muted uppercase tracking-wider">Security</p>

                <div className="rounded-xl border border-surface-2 bg-nested-panel p-4 space-y-4">
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Client type</label>
                    <div className="flex gap-1.5">
                      <button
                        type="button"
                        onClick={() => { setIsConfidential(true); setAuthMethod('client_secret_basic') }}
                        data-testid="client-type-confidential"
                        className={cn(
                          'flex-1 rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors',
                          isConfidential ? 'border-brand-accent bg-brand-wash text-brand-accent' : 'border-surface-2 text-text-muted hover:bg-surface-1'
                        )}
                      >
                        Confidential
                      </button>
                      <button
                        type="button"
                        onClick={() => { setIsConfidential(false); setAuthMethod('none'); setRequirePkce(true) }}
                        data-testid="client-type-public"
                        className={cn(
                          'flex-1 rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors',
                          !isConfidential ? 'border-brand-accent bg-brand-wash text-brand-accent' : 'border-surface-2 text-text-muted hover:bg-surface-1'
                        )}
                      >
                        Public
                      </button>
                    </div>
                    <p className="mt-1 text-[10px] text-text-muted">
                      {isConfidential ? 'Has a client secret. Server-side apps.' : 'No secret. SPAs / mobile. PKCE required.'}
                    </p>
                  </div>

                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Auth method</label>
                    <select
                      value={authMethod}
                      onChange={e => setAuthMethod(e.target.value as AuthMethod)}
                      disabled={!isConfidential}
                      className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-[11px] text-text-primary focus:border-brand-accent focus:outline-none btn-cta disabled:cursor-not-allowed"
                    >
                      <option value="client_secret_basic">client_secret_basic</option>
                      <option value="client_secret_post">client_secret_post</option>
                      {/* T.2: FAPI 2.0 / RFC 7521 alternatives. */}
                      <option value="client_secret_jwt">client_secret_jwt (HS256)</option>
                      <option value="private_key_jwt">private_key_jwt (RS256)</option>
                      {!isConfidential && <option value="none">none (public)</option>}
                    </select>
                    <p className="mt-1 text-[10px] text-text-muted">
                      {authMethod === 'client_secret_jwt' && 'Symmetric key is generated server-side and shown once.'}
                      {authMethod === 'private_key_jwt' && 'Upload the public JWK below. Sign client_assertions with the matching private key.'}
                      {(authMethod === 'client_secret_basic' || authMethod === 'client_secret_post') && 'Shared secret — the operator stores it.'}
                    </p>
                  </div>

                  {/* T.2: client_secret_jwt key indicator (read-only). */}
                  {authMethod === 'client_secret_jwt' && (
                    <div className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-[10px] text-text-muted">
                      {editClientId
                        ? 'A symmetric key is configured. Use Rotate JWT key to issue a new one (the old key is invalidated immediately).'
                        : 'A symmetric key will be generated and shown once after creation.'}
                    </div>
                  )}

                  {/* T.2: public JWK input for private_key_jwt. */}
                  {authMethod === 'private_key_jwt' && (
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">
                        Public JWK (JSON)
                      </label>
                      <textarea
                        value={publicJwkText}
                        onChange={e => { setPublicJwkText(e.target.value); setPublicJwkError(null); setFormErrors({ ...formErrors, public_jwk: '' }) }}
                        placeholder={'{\n  "kty": "RSA",\n  "n": "...",\n  "e": "AQAB"\n}'}
                        rows={5}
                        data-testid="public-jwk-input"
                        className="w-full rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] font-mono text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
                      />
{publicJwkError && <FieldError id="public-jwk-error">{publicJwkError}</FieldError>}
                      {!publicJwkError && formErrors.public_jwk && <FieldError id="public-jwk-error">{formErrors.public_jwk}</FieldError>}
                    </div>
                  )}

                  {showRedirectUris && (
                      <div>
                        <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Redirect URIs <span className="text-semantic-error">*</span></label>
                        <div className="space-y-1.5">
                          {redirectUris.map((uri, i) => (
                            <div key={i} className="flex items-center gap-1.5">
                              <input value={uri} onChange={e => updateRedirectUri(i, e.target.value)} placeholder={`https://app.example.com/cb${i+1}`} data-testid={`client-uri-input-${i}`} spellCheck={false} autoComplete="off" className="flex-1 rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] font-mono text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                              {redirectUris.length > 1 && <button type="button" onClick={() => removeRedirectUri(i)} className="shrink-0 text-text-muted hover:text-semantic-error"><Trash2 size={12} /></button>}
                            </div>
                          ))}
                        </div>
                        <button type="button" onClick={addRedirectUri} className="mt-1.5 text-[11px] text-brand-accent hover:text-brand-cool font-medium">+ Add URI</button>
                        {formErrors.redirect_uris && <FieldError id="client-redirect-uris-error">{formErrors.redirect_uris}</FieldError>}
                      </div>
                    )}

                  {showLogoutUris && (
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Logout Redirect URIs <span className="text-text-muted">(optional)</span></label>
                      <p className="mb-1.5 text-[10px] text-text-muted">Where to redirect users after logout (OIDC post_logout_redirect_uri)</p>
                      <div className="space-y-1.5">
{allowedPostLogoutRedirectUris.map((uri, i) => (
                            <div key={i} className="flex items-center gap-1.5">
                              <input value={uri} onChange={e => updateLogoutUri(i, e.target.value)} placeholder={`https://app.example.com/logout${i+1}`} data-testid={`client-logout-uri-input-${i}`} autoComplete="off" className="flex-1 rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] font-mono text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                              {allowedPostLogoutRedirectUris.length > 1 && <button type="button" onClick={() => removeLogoutUri(i)} className="shrink-0 text-text-muted hover:text-semantic-error"><Trash2 size={12} /></button>}
                            </div>
                          ))}
                      </div>
                      <button type="button" onClick={addLogoutUri} className="mt-1.5 text-[11px] text-brand-accent hover:text-brand-cool font-medium">+ Add URI</button>
                    </div>
                  )}

                  <div className="space-y-2 pt-1 border-t border-surface-2">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={isConfidential ? requirePkce : true}
                        onChange={e => setRequirePkce(e.target.checked)}
                        disabled={!isConfidential}
                        className="h-3.5 w-3.5 rounded border-surface-3 text-brand-accent focus:ring-brand-accent/20 btn-cta"
                      />
                      <span className={cn('text-[11px]', !isConfidential && 'text-text-muted')}>
                        Require PKCE
                        {!isConfidential && <span className="ml-1 text-[10px]">(required)</span>}
                      </span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={requireConsent}
                        onChange={e => setRequireConsent(e.target.checked)}
                        className="h-3.5 w-3.5 rounded border-surface-3 text-brand-accent focus:ring-brand-accent/20"
                      />
                      <span className="text-[11px] text-text-primary">Require consent screen</span>
                    </label>

                    {/* T.3: DPoP binding toggle (RFC 9449). */}
                    <label className="flex items-center gap-2 cursor-pointer" data-testid="dpop-bound-label">
                      <input
                        type="checkbox"
                        checked={dpopBound}
                        onChange={e => setDpopBound(e.target.checked)}
                        data-testid="dpop-bound-toggle"
                        className="h-3.5 w-3.5 rounded border-surface-3 text-brand-accent focus:ring-brand-accent/20"
                      />
                      <span className="text-[11px] text-text-primary">
                        DPoP-bound tokens
                        <span className="ml-1 text-[10px] text-text-muted">(FAPI 2.0)</span>
                      </span>
                    </label>
                    {dpopBound && (
                      <p className="text-[10px] text-text-muted pl-5">
                        Client must generate an ES256 key pair and sign a DPoP proof JWT on every request.
                      </p>
                    )}
                  </div>
                </div>
              </div>
            </div>
            )}

            {/* Advanced (collapsible) */}
            <button type="button" onClick={() => setShowAdvanced(!showAdvanced)} className="flex w-full items-center gap-1.5 text-xs font-medium text-text-muted hover:text-text-secondary transition-colors mb-5">
              {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              Advanced: branding, scopes, token lifetimes
            </button>

            {showAdvanced && (
              <div className="space-y-4 rounded-xl border border-surface-2 bg-nested-panel p-4 mb-5">
                <div>
                  <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Allowed scopes</label>
                  <ScopePicker value={allowedScopes} onChange={setAllowedScopes} placeholder="Add custom scope" />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Homepage URI</label>
                    <input value={homepageUri} onChange={e => setHomepageUri(e.target.value)} placeholder="https://app.example.com" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Logo URI</label>
                    <input value={logoUri} onChange={e => setLogoUri(e.target.value)} placeholder="https://app.example.com/logo.png" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Terms URI</label>
                    <input value={termsUri} onChange={e => setTermsUri(e.target.value)} placeholder="https://app.example.com/tos" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Privacy URI</label>
                    <input value={privacyUri} onChange={e => setPrivacyUri(e.target.value)} placeholder="https://app.example.com/privacy" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                  </div>
                </div>

                <div className="pt-3 border-t border-surface-2">
                  <div className="mb-1 flex items-center justify-between">
                    <h4 className="text-[11px] font-semibold text-text-muted uppercase tracking-wider">Consent Page Branding</h4>
                    <div className="flex items-center gap-1" role="tablist" aria-label="Branding variant">
                      {([['base', 'Shared'], ['light', 'Light'], ['dark', 'Dark']] as const).map(([m, l]) => (
                        <button
                          key={m}
                          type="button"
                          role="tab"
                          aria-selected={brandingMode === m}
                          data-testid={`branding-mode-${m}`}
                          onClick={() => setBrandingMode(m)}
                          className={cn(
                            'rounded-lg px-2.5 py-1 text-[11px] font-medium transition-colors',
                            brandingMode === m ? 'bg-brand-wash text-brand-accent' : 'text-text-muted hover:bg-surface-2',
                          )}
                        >
                          {l}
                        </button>
                      ))}
                    </div>
                  </div>
                  <p className="mb-3 text-[10px] text-text-muted">
                    {brandingMode === 'base'
                      ? 'Defaults for both themes: use these when the client has a single palette. The variants below only override the fields you fill in.'
                      : brandingMode === 'light'
                        ? 'Only set these if the light theme should differ from the Shared values. Leave empty to inherit.'
                        : 'Only set these if the dark theme should differ from the Shared values. A light Shared surface inherited here is automatically darkened.'}
                  </p>
                  <div className="grid grid-cols-2 gap-3">
                    <ColorField
                      label="Primary color"
                      value={modeBrand.primary_color || ''}
                      swatchFallback={brandingMode === 'base' ? '#6366f1' : (branding.primary_color || '#6366f1')}
                      placeholder={brandingMode === 'base' ? '#6366f1' : (branding.primary_color ? `shared: ${branding.primary_color}` : '#6366f1')}
                      onChange={(v) => setModeBrand({ primary_color: v })}
                    />
                    <ColorField
                      label="Surface color"
                      value={modeBrand.surface_color || ''}
                      swatchFallback={brandingMode === 'base' ? '#ffffff' : (branding.surface_color || '#ffffff')}
                      placeholder={brandingMode === 'base' ? '#ffffff' : (branding.surface_color ? `shared: ${branding.surface_color}` : '#ffffff')}
                      onChange={(v) => setModeBrand({ surface_color: v })}
                    />
                    <ColorField
                      label="Text color"
                      value={modeBrand.text_color || ''}
                      swatchFallback={brandingMode === 'base' ? '#1a1a2e' : (branding.text_color || '#1a1a2e')}
                      placeholder={brandingMode === 'base' ? 'auto (contrast)' : (branding.text_color ? `shared: ${branding.text_color}` : 'auto (contrast)')}
                      onChange={(v) => setModeBrand({ text_color: v })}
                    />
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Border radius</label>
                      <input
                        value={modeBrand.border_radius || ''}
                        onChange={(e) => setModeBrand({ border_radius: e.target.value })}
                        placeholder={brandingMode === 'base' ? '12px' : (branding.border_radius ? `shared: ${branding.border_radius}` : '12px')}
                        className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
                      />
                    </div>
                  </div>
                  {brandingMode === 'base' && (
                    <div className="grid grid-cols-2 gap-3 mt-3">
                      <div>
                        <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Font family (both themes)</label>
                        <input value={branding.font_family || ''} onChange={e => setBranding({...branding, font_family: e.target.value})} placeholder="Inter, sans-serif" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                      </div>
                      <div>
                        <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Logo URL</label>
                        <input value={branding.logo_url || ''} onChange={e => setBranding({...branding, logo_url: e.target.value})} placeholder="https://app.example.com/logo.png" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                      </div>
                    </div>
                  )}
                  <p className="mt-2 text-[10px] text-text-muted">Button text color is auto-derived from contrast when unset. The preview follows the current theme.</p>
                </div>

                <div className="grid grid-cols-2 gap-3 pt-3 border-t border-surface-2">
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Access token lifetime (s)</label>
                    <input type="number" min={300} max={86400} value={accessTokenLifetime} onChange={e => setAccessTokenLifetime(Number(e.target.value))} className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary focus:border-brand-accent focus:outline-none" />
                    <p className="mt-1 text-[10px] text-text-muted">5 min – 24 hours</p>
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Refresh token lifetime (s)</label>
                    <input type="number" min={3600} max={7776000} value={refreshTokenLifetime} onChange={e => setRefreshTokenLifetime(Number(e.target.value))} className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary focus:border-brand-accent focus:outline-none" />
                    <p className="mt-1 text-[10px] text-text-muted">1 hour – 90 days</p>
                  </div>
                </div>
              </div>
            )}

            {/* Wizard Footer */}
            {!editClientId && !showSuccess && (
              <div className="flex flex-shrink-0 gap-3 border-t border-surface-2 p-4">
                <button
                  type="button"
                  onClick={prevStep}
                  disabled={wizardStep === 1}
                  className="flex-1 rounded-xl border border-surface-2 px-4 py-2.5 text-sm text-text-secondary hover:bg-surface-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ArrowLeft size={14} className="inline mr-1" /> Back
                </button>
                <button
                  type="button"
                  onClick={nextStep}
                  disabled={!canGoNext() || wizardStep === 4}
                  className="flex-1 rounded-xl border border-surface-2 px-4 py-2.5 text-sm text-text-secondary hover:bg-surface-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next <ArrowRight size={14} className="inline ml-1" />
                </button>
                <button
                  type="button"
                  onClick={handleSubmit}
                  disabled={wizardStep !== 4 || saving || !checkFormValid()}
                  data-testid="create-client-submit"
                  className="btn-cta flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2.5 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] disabled:hover:scale-100 disabled:opacity-50"
                >
                  {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                  Create
                </button>
              </div>
            )}

            {/* Edit mode footer */}
            {editClientId && (
              <div className="flex flex-shrink-0 gap-3 border-t border-surface-2 p-4">
                <button type="button" onClick={() => { setShowForm(false); resetForm() }} className="flex-1 rounded-xl border border-surface-2 px-4 py-2.5 text-sm text-text-secondary hover:bg-surface-2 transition-colors">Cancel</button>
                <button type="button" onClick={handleSubmit} disabled={saving} data-testid="create-client-submit" className="btn-cta flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2.5 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] disabled:hover:scale-100">
                  {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                  Update
                </button>
              </div>
            )}

            {/* Success Screen */}
            {showSuccess && createdClientData && (
              <div className="flex-1 overflow-y-auto p-6">
                <div className="text-center py-8">
                  <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-semantic-success/10">
                    <CheckCircle2 size={32} className="text-semantic-success" />
                  </div>
                  <h3 className="text-lg font-semibold text-text-primary">Client Created Successfully</h3>
                  <p className="mt-2 text-sm text-text-muted">Your OAuth client is ready. Copy the credentials below — they won't be shown again.</p>
                </div>

                <div className="space-y-4 mb-6">
                  <div className="rounded-xl border border-surface-2 bg-surface-1 p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-medium text-text-muted uppercase">Client ID</span>
                      <CopyButton text={createdClientData.client_id} label="Copy" className="flex-shrink-0" />
                    </div>
                    <code className="block w-full break-words rounded-lg bg-surface-2 px-3 py-2 text-sm font-mono text-text-primary">{createdClientData.client_id}</code>
                  </div>

                  <div className="rounded-xl border border-surface-2 bg-surface-1 p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-medium text-text-muted uppercase">Client Secret</span>
                      <CopyButton text={createdClientData.client_secret} label="Copy" className="flex-shrink-0" />
                    </div>
                    <code className="block w-full break-words rounded-lg bg-surface-2 px-3 py-2 text-sm font-mono text-text-primary">{createdClientData.client_secret}</code>
                    <p className="mt-1 text-xs text-semantic-warning">Store this securely. It cannot be recovered.</p>
                  </div>

                  {createdClientData.client_secret_jwt_key && (
                    <div className="rounded-xl border border-surface-2 bg-surface-1 p-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-medium text-text-muted uppercase">JWT Signing Key (HS256)</span>
                        <CopyButton text={createdClientData.client_secret_jwt_key} label="Copy" className="flex-shrink-0" />
                      </div>
                      <code className="block w-full break-words rounded-lg bg-surface-2 px-3 py-2 text-sm font-mono text-text-primary">{createdClientData.client_secret_jwt_key}</code>
                      <p className="mt-1 text-xs text-semantic-warning">Used for client_secret_jwt auth. Store securely.</p>
                    </div>
                  )}
                </div>

                {/* Code Snippets */}
                <div className="border-t border-surface-2 pt-6">
                  <h4 className="mb-4 text-sm font-semibold text-text-primary">Quick Start — Copy-Paste Config</h4>
                  <div className="space-y-3" role="tablist" aria-label="Framework examples">
                    {[
                      { id: 'nextjs', label: 'Next.js (App Router)', icon: FileText },
                      { id: 'react', label: 'React SPA', icon: Code },
                      { id: 'python', label: 'Python / FastAPI', icon: Terminal },
                      { id: 'node', label: 'Node / Express', icon: Terminal },
                      { id: 'go', label: 'Go', icon: Terminal },
                      { id: 'dotnet', label: 'ASP.NET Core', icon: Terminal },
                    ].map((fw) => (
                      <details key={fw.id} className="group rounded-xl border border-surface-2 bg-surface-1">
                        <summary className="flex items-center gap-3 p-3 cursor-pointer list-none text-sm font-medium text-text-primary hover:bg-surface-2">
                          <fw.icon size={16} className="text-text-muted" />
                          {fw.label}
                          <ChevronDown size={14} className="ml-auto text-text-muted group-open:rotate-180 transition-transform" />
                        </summary>
                        <div className="p-3 border-t border-surface-2 bg-surface-2">
                          <pre className="overflow-x-auto text-[11px] font-mono text-text-primary"><code>{getCodeSnippet(fw.id, createdClientData)}</code></pre>
                          <div className="mt-2 flex gap-2">
                            <CopyButton text={getCodeSnippet(fw.id, createdClientData)} label="Copy" className="text-[11px]" />
                            <a href={getDocUrl(fw.id)} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-[11px] text-brand-accent hover:underline">
                              <ExternalLink size={12} /> Docs
                            </a>
                          </div>
                        </div>
                      </details>
                    ))}
                  </div>
                </div>

                <div className="mt-6 flex gap-3">
                  <button onClick={() => { setShowSuccess(false); setShowForm(false); resetForm() }} className="btn-cta flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2.5 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02]">
                    Done
                  </button>
                  <a href={`/admin/playground?client_id=${createdClientData.client_id}`} target="_blank" rel="noopener noreferrer" className="btn-cta flex-1 items-center justify-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm font-semibold text-text-primary shadow-glow-accent transition-all hover:scale-[1.02]">
                    <ExternalLink size={14} /> Test in Playground
                  </a>
                </div>
              </div>
            )}

          </div>
        </div>
      </div>
      )}

      {/* Token Claims policy editor — opened from the per-row
          KeyRound button. Renders above the OAuth-client form
          (z-50 modal) so the admin can move between editing
          identity and editing claims. */}
      {claimsClient && (
        <TokenClaimsTab
          clientId={claimsClient.id}
          clientName={claimsClient.name}
          onClose={() => setClaimsClient(null)}
        />
      )}
    </div>
  )
}
