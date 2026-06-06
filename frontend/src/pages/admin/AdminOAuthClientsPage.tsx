import { useState, useEffect } from 'react'
import { Trash2, RefreshCw, Plus, Loader2, Save, Globe, Cog, Smartphone, Sparkles, ChevronDown, ChevronRight, Edit, AlertTriangle, Check, Eye } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { cn } from '@/lib/utils'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { CopyButton } from '@/components/shared/CopyButton'
import { ConsentScreen } from '@/components/oauth/ConsentScreen'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

interface OAuthClient {
  id?: string
  client_id: string
  client_name?: string
  name?: string
  is_confidential: boolean
  redirect_uris: string[]
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
  token_endpoint_auth_method?: string
}

type GrantType = 'authorization_code' | 'client_credentials' | 'refresh_token'
type AuthMethod = 'client_secret_basic' | 'client_secret_post' | 'none'

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
  access_token_lifetime: number
  refresh_token_lifetime: number
}

const TEMPLATES: Template[] = [
  {
    id: 'web', label: 'Web App', desc: 'Backend server with users',
    icon: Globe, grant_types: ['authorization_code', 'refresh_token'], is_confidential: true,
    auth_method: 'client_secret_basic', require_pkce: false, require_consent: true,
    show_redirect_uris: true, access_token_lifetime: 3600, refresh_token_lifetime: 2592000,
  },
  {
    id: 'service', label: 'Service / API', desc: 'Machine-to-machine',
    icon: Cog, grant_types: ['client_credentials', 'refresh_token'], is_confidential: true,
    auth_method: 'client_secret_basic', require_pkce: false, require_consent: false,
    show_redirect_uris: false, access_token_lifetime: 3600, refresh_token_lifetime: 2592000,
  },
  {
    id: 'mobile', label: 'Mobile / SPA', desc: 'No backend, PKCE secured',
    icon: Smartphone, grant_types: ['authorization_code', 'refresh_token'], is_confidential: false,
    auth_method: 'none', require_pkce: true, require_consent: true,
    show_redirect_uris: true, access_token_lifetime: 3600, refresh_token_lifetime: 2592000,
  },
]

function friendlyError(raw: string): string {
  if (raw.includes('client_name') && raw.includes('Field required')) return 'Application name is required.'
  if (raw.includes('redirect_uris') && raw.includes('List should have at least')) return 'Add at least one redirect URI.'
  if (raw.includes('grant_types') && raw.includes('List should have at least')) return 'Select at least one grant type.'
  return raw
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
      className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20"
    />
  )
}

export function AdminOAuthClientsPage() {
  useDocumentTitle('OAuth Clients')
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)

  // Form fields
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [grantTypes, setGrantTypes] = useState<GrantType[]>([])
  const [isConfidential, setIsConfidential] = useState(true)
  const [authMethod, setAuthMethod] = useState<AuthMethod>('client_secret_basic')
  const [redirectUris, setRedirectUris] = useState<string[]>([''])
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

  const [showAdvanced, setShowAdvanced] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [formErrors, setFormErrors] = useState<Record<string, string>>({})
  const [success, setSuccess] = useState('')
  const [secretModal, setSecretModal] = useState<string | null>(null)
  const [newClientId, setNewClientId] = useState('')
  const [editClientId, setEditClientId] = useState<string | null>(null)
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null)
  const [previewClient, setPreviewClient] = useState<OAuthClient | null>(null)
  const [originalGrantTypes, setOriginalGrantTypes] = useState<GrantType[]>([])
  const [originalIsConfidential, setOriginalIsConfidential] = useState(true)

  const { data, refetch } = useApiQuery<OAuthClient[]>(['admin-oauth-clients'], '/api/oauth-clients')
  const clients: OAuthClient[] = Array.isArray(data) ? data : ((data as any)?.items as OAuthClient[]) ?? []

  useEffect(() => { if (success) { const t = setTimeout(() => setSuccess(''), 3000); return () => clearTimeout(t) } }, [success])

  const resetForm = () => {
    setName(''); setDescription(''); setGrantTypes([]); setIsConfidential(true)
    setAuthMethod('client_secret_basic'); setRedirectUris([''])
    setRequirePkce(false); setRequireConsent(true)
    setHomepageUri(''); setLogoUri(''); setTermsUri(''); setPrivacyUri('')
    setAllowedScopes('openid profile email'); setCustomCss('')
    setAccessTokenLifetime(3600); setRefreshTokenLifetime(2592000)
    setShowAdvanced(false); setFormErrors({}); setSelectedTemplate(null)
    setEditClientId(null); setOriginalGrantTypes([]); setOriginalIsConfidential(true)
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
    setFormErrors({})
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
    setRequirePkce(c.require_pkce ?? false)
    setRequireConsent(c.require_consent ?? true)
    setHomepageUri(c.homepage_uri || '')
    setLogoUri(c.logo_uri || '')
    setTermsUri(c.terms_uri || '')
    setPrivacyUri(c.privacy_uri || '')
    setCustomCss(c.custom_css || '')
    setAllowedScopes((c.scopes || c.allowed_scopes || []).join(' ') || 'openid profile email')
    setAccessTokenLifetime(c.access_token_lifetime ?? 3600)
    setRefreshTokenLifetime(c.refresh_token_lifetime ?? 2592000)
    setShowForm(true)
    setShowAdvanced(true)
    setFormErrors({})
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try { setError(''); await api.delete(`/api/oauth-clients/${deleteId}`); setDeleteId(null); setSuccess('Client deleted.'); await refetch() }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed') }
  }

  const handleToggle = async (id: string, active: boolean) => {
    try { await api.post(`/api/oauth-clients/${id}/${active ? 'deactivate' : 'activate'}`); await refetch() }
    catch { /* ignore */ }
  }

  const handleRotate = async (id: string) => {
    try {
      const res = await api.post<{ secret: string }>(`/api/oauth-clients/${id}/rotate-secret`)
      setSecretModal(res.secret)
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed') }
  }

  const validateForm = (): boolean => {
    const errs: Record<string, string> = {}
    if (!name.trim()) errs.name = 'Application name is required.'
    if (grantTypes.length === 0) errs.grant_types = 'Select at least one grant type.'
    if (grantTypes.includes('authorization_code')) {
      const uris = redirectUris.map(u => u.trim()).filter(Boolean)
      if (uris.length === 0) errs.redirect_uris = 'Redirect URIs are required for authorization_code.'
    }
    setFormErrors(errs)
    return Object.keys(errs).length === 0
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
      allowed_scopes: allowedScopes.trim().split(/\s+/).filter(Boolean),
      access_token_lifetime: accessTokenLifetime,
      refresh_token_lifetime: refreshTokenLifetime,
    }
    if (grantTypes.includes('authorization_code')) {
      payload.redirect_uris = redirectUris.map(u => u.trim()).filter(Boolean)
    }
    return payload
  }

  const handleCreate = async () => {
    if (!validateForm()) return
    setSaving(true); setError('')
    try {
      const { client_id, client_secret } = await api.post<{ client_id: string; client_secret: string }>('/api/oauth-clients', buildPayload())
      setNewClientId(client_id)
      setSecretModal(client_secret)
      setShowForm(false)
      resetForm()
      await refetch()
    } catch (err: unknown) {
      setError(friendlyError(err instanceof Error ? err.message : 'Failed to create client'))
    } finally { setSaving(false) }
  }

  const handleUpdate = async () => {
    if (!editClientId || !validateForm()) return
    setSaving(true); setError('')
    try {
      await api.put(`/api/oauth-clients/${editClientId}`, buildPayload())
      setShowForm(false)
      resetForm()
      setSuccess('Client updated.')
      await refetch()
    } catch (err: unknown) {
      setError(friendlyError(err instanceof Error ? err.message : 'Failed to update client'))
    } finally { setSaving(false) }
  }

  const handleSubmit = async () => {
    if (editClientId) await handleUpdate()
    else await handleCreate()
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

  const showRedirectUris = grantTypes.includes('authorization_code')
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
          <button onClick={() => { resetForm(); setShowForm(true) }} data-testid="create-oauth-client-btn" className="flex items-center gap-1.5 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]">
            <Plus size={16} /> Create Client
          </button>
        }
      />

      {error && <div className="rounded-xl bg-semantic-error/10 px-4 py-3 text-sm text-semantic-error" role="alert">{error}</div>}
      {success && <div className="rounded-xl bg-semantic-success/10 px-4 py-3 text-sm text-semantic-success">{success}</div>}

      {!clients || clients.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-surface-2 bg-surface-1 py-16 text-center">
          <div className="rounded-2xl bg-surface-2 p-4"><Sparkles className="h-8 w-8 text-text-muted" /></div>
          <h3 className="mt-4 text-lg font-semibold text-text-primary">No OAuth clients yet</h3>
          <p className="mt-2 max-w-sm text-sm text-text-muted">Create your first client to let applications authenticate users.</p>
          <button onClick={() => { resetForm(); setShowForm(true) }} className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]">
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
                  <td className="hidden md:table-cell px-4 py-2.5"><span className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${c.is_confidential ? 'bg-brand-violet/10 text-brand-violet' : 'bg-surface-2 text-text-muted'}`}>{c.is_confidential ? 'Confidential' : 'Public'}</span></td>
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
                      <button onClick={() => openEdit(c)} className="text-text-muted hover:text-text-secondary" title="Edit client"><Edit size={14} /></button>
                      <button onClick={() => handleRotate(c.client_id)} data-testid="rotate-secret-btn" className="text-text-muted hover:text-text-secondary" title="Rotate secret"><RefreshCw size={14} /></button>
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

      {/* Secret modal */}
      {secretModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => { setSecretModal(null); setNewClientId('') }} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet" data-testid="client-created-secret">
            <h3 className="text-lg font-semibold text-text-primary">{newClientId ? 'Client Created' : 'New Secret'}</h3>
            {newClientId && <p className="text-xs text-text-muted">Client ID: <code className="text-text-secondary">{newClientId}</code></p>}
            <p className="text-xs text-semantic-warning">Copy this secret now. You will not be able to see it again.</p>
            <div className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-2 px-4 py-3">
              <code className="flex-1 break-all text-sm text-text-primary">{secretModal}</code>
              <CopyButton text={secretModal} label="Copy" />
            </div>
            <button onClick={() => { setSecretModal(null); setNewClientId('') }} data-testid="client-created-done" className="w-full rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2">Close</button>
          </div>
        </div>
      )}

      {/* Preview consent screen modal */}
      {previewClient && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto py-8">
          <div className="absolute inset-0 bg-black/50" onClick={() => setPreviewClient(null)} />
          <div className="relative z-10 w-full max-w-lg rounded-2xl border border-surface-2 bg-bg-primary p-6 shadow-glow-violet my-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-text-primary">Consent Screen Preview</h3>
              <button onClick={() => setPreviewClient(null)} className="text-text-muted hover:text-text-secondary text-sm">Close</button>
            </div>
            <div className="max-h-[70vh] overflow-y-auto">
              <ConsentScreen
                clientName={previewClient.client_name || previewClient.name || 'Untitled'}
                clientDescription={previewClient.description}
                clientLogoUri={previewClient.logo_uri}
                clientHomepageUri={previewClient.homepage_uri}
                clientTermsUri={previewClient.terms_uri}
                clientPrivacyUri={previewClient.privacy_uri}
                scopes={(previewClient.allowed_scopes || previewClient.scopes || ['openid', 'profile', 'email']).map(s => ({
                  name: s,
                  description: getScopeLabel(s),
                }))}
                customCss={previewClient.custom_css}
                preview
              />
            </div>
          </div>
        </div>
      )}

      {/* Create / Edit Client Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto py-8" onClick={(e) => { if (e.target === e.currentTarget) { setShowForm(false); resetForm() } }}>
          <div className="absolute inset-0 bg-black/50" onClick={() => { setShowForm(false); resetForm() }} />
          <div className="relative z-10 w-full max-w-3xl rounded-2xl border border-surface-2 bg-surface-1 p-6 shadow-glow-violet my-auto">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-lg font-semibold text-text-primary">
                {editClientId ? 'Edit OAuth Client' : 'New OAuth Client'}
              </h3>
              {!editClientId && (
                <div className="flex items-center gap-1">
                  {TEMPLATES.map(t => (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => applyTemplate(t)}
                      data-testid={`template-${t.id}`}
                      className={cn(
                        'flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-all',
                        selectedTemplate === t.id
                          ? 'border-brand-violet bg-brand-violet/10 text-brand-violet'
                          : 'border-surface-2 text-text-muted hover:border-surface-3 hover:text-text-secondary'
                      )}
                    >
                      <t.icon size={12} />
                      {t.label}
                      {selectedTemplate === t.id && <Check size={10} />}
                    </button>
                  ))}
                </div>
              )}
            </div>

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

            {/* Two-column layout */}
            <div className="grid grid-cols-2 gap-5 mb-5">
              {/* Left column: Application identity */}
              <div className="space-y-3">
                <p className="text-xs font-medium text-text-muted uppercase tracking-wider">Identity</p>

                <div>
                  <label className="mb-1 block text-[11px] font-medium text-text-secondary">Application name <span className="text-semantic-error">*</span></label>
                  <TextInput value={name} onChange={v => { setName(v); setFormErrors({...formErrors, name: ''}) }} placeholder="My Application" data-testid="client-name-input" autoFocus />
                  {formErrors.name && <p className="mt-1 text-[11px] text-semantic-error">{formErrors.name}</p>}
                </div>

                <div>
                  <label className="mb-1 block text-[11px] font-medium text-text-secondary">Description</label>
                  <textarea value={description} onChange={e => setDescription(e.target.value)} placeholder="What does this client do?" rows={2} className="w-full rounded-xl border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 resize-y" />
                </div>

                <div>
                  <label className="mb-1.5 block text-[11px] font-medium text-text-secondary">Grant types <span className="text-semantic-error">*</span></label>
                  <div className="space-y-1">
                    {ALL_GRANT_TYPES.map(g => (
                      <label key={g.id} className={cn(
                        'flex items-center gap-2 rounded-lg px-2.5 py-1.5 cursor-pointer transition-colors',
                        grantTypes.includes(g.id) ? 'bg-brand-violet/10' : 'hover:bg-surface-2'
                      )}>
                        <input
                          type="checkbox"
                          checked={grantTypes.includes(g.id)}
                          onChange={() => toggleGrantType(g.id)}
                          data-testid={`grant-${g.id}`}
                          className="h-3.5 w-3.5 rounded border-surface-3 text-brand-violet focus:ring-brand-violet/20"
                        />
                        <span className="text-xs text-text-primary">{g.label}</span>
                      </label>
                    ))}
                  </div>
                  {formErrors.grant_types && <p className="mt-1 text-[11px] text-semantic-error">{formErrors.grant_types}</p>}
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
                          isConfidential ? 'border-brand-violet bg-brand-violet/10 text-brand-violet' : 'border-surface-2 text-text-muted hover:bg-surface-1'
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
                          !isConfidential ? 'border-brand-violet bg-brand-violet/10 text-brand-violet' : 'border-surface-2 text-text-muted hover:bg-surface-1'
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
                      className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-[11px] text-text-primary focus:border-brand-violet focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <option value="client_secret_basic">client_secret_basic</option>
                      <option value="client_secret_post">client_secret_post</option>
                      {!isConfidential && <option value="none">none (public)</option>}
                    </select>
                  </div>

                  {showRedirectUris && (
                    <div>
                      <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Redirect URIs <span className="text-semantic-error">*</span></label>
                      <div className="space-y-1.5">
                        {redirectUris.map((uri, i) => (
                          <div key={i} className="flex items-center gap-1.5">
                            <input value={uri} onChange={e => updateRedirectUri(i, e.target.value)} placeholder={`https://app.example.com/cb${redirectUris.length > 1 ? ` ${i+1}` : ''}`} data-testid={`client-uri-input-${i}`} className="flex-1 rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] font-mono text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                            {redirectUris.length > 1 && <button type="button" onClick={() => removeRedirectUri(i)} className="shrink-0 text-text-muted hover:text-semantic-error"><Trash2 size={12} /></button>}
                          </div>
                        ))}
                      </div>
                      <button type="button" onClick={addRedirectUri} className="mt-1.5 text-[11px] text-brand-violet hover:text-brand-blue font-medium">+ Add URI</button>
                      {formErrors.redirect_uris && <p className="mt-1 text-[11px] text-semantic-error">{formErrors.redirect_uris}</p>}
                    </div>
                  )}

                  <div className="space-y-2 pt-1 border-t border-surface-2">
                    <label className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={isConfidential ? requirePkce : true}
                        onChange={e => setRequirePkce(e.target.checked)}
                        disabled={!isConfidential}
                        className="h-3.5 w-3.5 rounded border-surface-3 text-brand-violet focus:ring-brand-violet/20 disabled:opacity-50"
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
                        className="h-3.5 w-3.5 rounded border-surface-3 text-brand-violet focus:ring-brand-violet/20"
                      />
                      <span className="text-[11px] text-text-primary">Require consent screen</span>
                    </label>
                  </div>
                </div>
              </div>
            </div>

            {/* Advanced (collapsible) */}
            <button type="button" onClick={() => setShowAdvanced(!showAdvanced)} className="flex w-full items-center gap-1.5 text-xs font-medium text-text-muted hover:text-text-secondary transition-colors mb-5">
              {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              Advanced: branding, scopes, token lifetimes
            </button>

            {showAdvanced && (
              <div className="space-y-4 rounded-xl border border-surface-2 bg-nested-panel p-4 mb-5">
                <div>
                  <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Allowed scopes (space-separated)</label>
                  <input value={allowedScopes} onChange={e => setAllowedScopes(e.target.value)} placeholder="openid profile email" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Homepage URI</label>
                    <input value={homepageUri} onChange={e => setHomepageUri(e.target.value)} placeholder="https://app.example.com" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Logo URI</label>
                    <input value={logoUri} onChange={e => setLogoUri(e.target.value)} placeholder="https://app.example.com/logo.png" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Terms URI</label>
                    <input value={termsUri} onChange={e => setTermsUri(e.target.value)} placeholder="https://app.example.com/tos" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Privacy URI</label>
                    <input value={privacyUri} onChange={e => setPrivacyUri(e.target.value)} placeholder="https://app.example.com/privacy" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                  </div>
                </div>

                <div className="pt-3 border-t border-surface-2">
                  <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Custom CSS</label>
                  <textarea
                    value={customCss}
                    onChange={e => setCustomCss(e.target.value)}
                    placeholder={`.authglow-consent {\n  --bg-color: #ffffff;\n  --text-color: #1a1a2e;\n}\n.authglow-consent .btn-approve {\n  background: #6366f1;\n  border-radius: 8px;\n}`}
                    rows={5}
                    className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none resize-y"
                  />
                  <p className="mt-1 text-[10px] text-text-muted">Override consent screen styles. Uses CSS custom properties and scoped selectors.</p>
                </div>

                <div className="grid grid-cols-2 gap-3 pt-3 border-t border-surface-2">
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Access token lifetime (s)</label>
                    <input type="number" min={300} max={86400} value={accessTokenLifetime} onChange={e => setAccessTokenLifetime(Number(e.target.value))} className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary focus:border-brand-violet focus:outline-none" />
                    <p className="mt-1 text-[10px] text-text-muted">5 min – 24 hours</p>
                  </div>
                  <div>
                    <label className="mb-1.5 block text-[11px] font-medium text-text-muted">Refresh token lifetime (s)</label>
                    <input type="number" min={3600} max={7776000} value={refreshTokenLifetime} onChange={e => setRefreshTokenLifetime(Number(e.target.value))} className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary focus:border-brand-violet focus:outline-none" />
                    <p className="mt-1 text-[10px] text-text-muted">1 hour – 90 days</p>
                  </div>
                </div>
              </div>
            )}

            <div className="flex gap-3">
              <button type="button" onClick={() => { setShowForm(false); resetForm() }} className="flex-1 rounded-xl border border-surface-2 px-4 py-2.5 text-sm text-text-secondary hover:bg-surface-2 transition-colors">Cancel</button>
              <button type="button" onClick={handleSubmit} disabled={saving} data-testid="create-client-submit" className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100">
                {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                {editClientId ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
