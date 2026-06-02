import { useState, useEffect } from 'react'
import { Trash2, RefreshCw, Plus, Loader2, Save, Globe, Cog, Smartphone, Shield, ChevronDown, ChevronRight } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { CopyButton } from '@/components/shared/CopyButton'

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
}

interface ClientType {
  id: string
  label: string
  desc: string
  icon: typeof Globe
  grant_types: string[]
  confidential: boolean
}

const CLIENT_TYPES: ClientType[] = [
  { id: 'web', label: 'Web Application', desc: 'Backend server that users log into via browser', icon: Globe, grant_types: ['authorization_code'], confidential: true },
  { id: 'service', label: 'Service / API', desc: 'Machine-to-machine, no user involved', icon: Cog, grant_types: ['client_credentials'], confidential: true },
  { id: 'mobile', label: 'Mobile / SPA', desc: 'No backend, PKCE secured authentication', icon: Smartphone, grant_types: ['authorization_code'], confidential: false },
]

function friendlyError(raw: string): string {
  if (raw.includes('client_name') && raw.includes('Field required')) return 'Application name is required.'
  if (raw.includes('redirect_uris') && raw.includes('List should have at least')) return 'Add at least one redirect URI.'
  if (raw.includes('grant_types') && raw.includes('List should have at least')) return 'Select a client type.'
  return raw
}

export function AdminOAuthClientsPage() {
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [clientType, setClientType] = useState<ClientType | null>(null)
  const [name, setName] = useState('')
  const [redirectUris, setRedirectUris] = useState<string[]>([''])
  const [scopes, setScopes] = useState('openid profile email')
  const [refreshToken, setRefreshToken] = useState(true)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [formErrors, setFormErrors] = useState<Record<string, string>>({})
  const [success, setSuccess] = useState('')
  const [secretModal, setSecretModal] = useState<string | null>(null)
  const [newClientId, setNewClientId] = useState('')

  const { data, refetch } = useApiQuery<OAuthClient[]>(['admin-oauth-clients'], '/api/oauth-clients')
  const clients: OAuthClient[] = Array.isArray(data) ? data : ((data as any)?.items as OAuthClient[]) ?? []

  useEffect(() => { if (success) { const t = setTimeout(() => setSuccess(''), 3000); return () => clearTimeout(t) } }, [success])

  const resetForm = () => {
    setClientType(null); setName(''); setRedirectUris(['']); setScopes('openid profile email')
    setRefreshToken(true); setShowAdvanced(false); setFormErrors({}); setError('')
  }

  const selectType = (ct: ClientType) => {
    setClientType(ct)
    setRedirectUris([''])
    setRefreshToken(ct.grant_types.includes('authorization_code'))
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
    const uris = redirectUris.map(u => u.trim()).filter(Boolean)
    if (uris.length === 0) errs.redirect_uris = 'Add at least one redirect URI.'
    setFormErrors(errs)
    return Object.keys(errs).length === 0
  }

  const handleCreate = async () => {
    if (!clientType || !validateForm()) return
    setSaving(true); setError('')
    try {
      const uris = redirectUris.map(u => u.trim()).filter(Boolean)
      const scopesList = scopes.split(',').map(s => s.trim()).filter(Boolean)
      const grantTypes = refreshToken && !clientType.grant_types.includes('refresh_token')
        ? [...clientType.grant_types, 'refresh_token'] : clientType.grant_types

      const { client_id, client_secret } = await api.post<{ client_id: string; client_secret: string }>('/api/oauth-clients', {
        client_name: name,
        redirect_uris: uris,
        grant_types: grantTypes,
        is_confidential: clientType.confidential,
        scopes: scopesList,
      })

      setNewClientId(client_id)
      setSecretModal(client_secret)
      setShowCreate(false)
      resetForm()
      await refetch()
    } catch (err: unknown) {
      setError(friendlyError(err instanceof Error ? err.message : 'Failed to create client'))
    } finally { setSaving(false) }
  }

  const addRedirectUri = () => setRedirectUris([...redirectUris, ''])
  const removeRedirectUri = (i: number) => setRedirectUris(redirectUris.filter((_, idx) => idx !== i))
  const updateRedirectUri = (i: number, v: string) => {
    const next = [...redirectUris]; next[i] = v
    setRedirectUris(next); setFormErrors({...formErrors, redirect_uris: ''})
  }

  const clientDisplayName = (c: OAuthClient) => c.client_name || c.name || c.client_id
  const clientGrantTypes = (c: OAuthClient) => c.grant_types || []

  return (
    <div className="space-y-6">
      <PageHeader
        title="OAuth Clients"
        description="Applications that authenticate users through AuthGlow."
        actions={
          <button onClick={() => { resetForm(); setShowCreate(true) }} className="flex items-center gap-1.5 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]">
            <Plus size={16} /> Create Client
          </button>
        }
      />

      {error && <div className="rounded-xl bg-semantic-error/10 px-4 py-3 text-sm text-semantic-error" role="alert">{error}</div>}
      {success && <div className="rounded-xl bg-semantic-success/10 px-4 py-3 text-sm text-semantic-success">{success}</div>}

      {!clients || clients.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-surface-2 bg-surface-1 py-16 text-center">
          <div className="rounded-2xl bg-surface-2 p-4"><Shield className="h-8 w-8 text-text-muted" /></div>
          <h3 className="mt-4 text-lg font-semibold text-text-primary">No OAuth clients yet</h3>
          <p className="mt-2 max-w-sm text-sm text-text-muted">Create your first client to let applications authenticate users.</p>
          <button onClick={() => { resetForm(); setShowCreate(true) }} className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]">
            <Plus size={16} /> Create Client
          </button>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Client ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Redirect URIs</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase w-20">Status</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {clients.map((c, idx) => (
                <tr key={c.client_id || idx} className="hover:bg-surface-2/50">
                  <td className="px-6 py-3 text-sm font-medium text-text-primary">{clientDisplayName(c)}</td>
                  <td className="px-6 py-3">
                    <div className="flex items-center gap-2">
                      <code className="text-xs font-mono text-text-secondary">{c.client_id}</code>
                      <CopyButton text={c.client_id} />
                    </div>
                  </td>
                  <td className="px-6 py-3">
                    <div className="flex flex-wrap gap-1 max-w-[200px]">
                      {(c.redirect_uris || []).slice(0, 2).map(u => (
                        <span key={u} className="truncate rounded-lg bg-surface-2 px-2 py-0.5 text-[10px] font-mono text-text-secondary" title={u}>
                          {u.length > 25 ? u.slice(0, 25) + '...' : u}
                        </span>
                      ))}
                      {(c.redirect_uris || []).length > 2 && <span className="text-[10px] text-text-muted">+{c.redirect_uris.length - 2} more</span>}
                    </div>
                  </td>
                  <td className="px-6 py-3"><div className="flex flex-wrap gap-1">{clientGrantTypes(c).map(g => <span key={g} className="rounded-lg bg-surface-2 px-2 py-0.5 text-[10px] text-text-secondary">{g}</span>)}</div></td>
                  <td className="px-6 py-3"><span className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${c.is_confidential ? 'bg-brand-violet/10 text-brand-violet' : 'bg-surface-2 text-text-muted'}`}>{c.is_confidential ? 'Confidential' : 'Public'}</span></td>
                  <td className="px-6 py-3">
                    <button onClick={() => handleToggle(c.client_id, c.is_active)} className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium ${c.is_active ? 'bg-semantic-success/10 text-semantic-success' : 'bg-semantic-error/10 text-semantic-error'}`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${c.is_active ? 'bg-semantic-success' : 'bg-semantic-error'}`} />
                      {c.is_active ? 'On' : 'Off'}
                    </button>
                  </td>
                  <td className="px-6 py-3">
                    <div className="flex gap-2">
                      <button onClick={() => handleRotate(c.client_id)} className="text-text-muted hover:text-text-secondary" title="Rotate secret"><RefreshCw size={14} /></button>
                      <button onClick={() => setDeleteId(c.client_id || idx.toString())} className="text-text-muted hover:text-semantic-error" title="Delete"><Trash2 size={14} /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog open={!!deleteId} title="Delete OAuth Client" message="All tokens for this client will be revoked. This action cannot be undone." confirmLabel="Delete" variant="danger" onConfirm={handleDelete} onCancel={() => setDeleteId(null)} />

      {/* Secret modal (post-create or rotate) */}
      {secretModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => { setSecretModal(null); setNewClientId('') }} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet">
            <h3 className="text-lg font-semibold text-text-primary">{newClientId ? 'Client Created' : 'New Secret'}</h3>
            {newClientId && <p className="text-xs text-text-muted">Client ID: <code className="text-text-secondary">{newClientId}</code></p>}
            <p className="text-xs text-semantic-warning">Copy this secret now. You will not be able to see it again.</p>
            <div className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-2 px-4 py-3">
              <code className="flex-1 break-all text-sm text-text-primary">{secretModal}</code>
              <CopyButton text={secretModal} label="Copy" />
            </div>
            <button onClick={() => { setSecretModal(null); setNewClientId('') }} className="w-full rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2">Close</button>
          </div>
        </div>
      )}

      {/* Create Client Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => { setShowCreate(false); resetForm() }} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-5 shadow-glow-violet">
            <h3 className="text-lg font-semibold text-text-primary">New OAuth Client</h3>

            {/* Step 1: Choose type */}
            {!clientType ? (
              <div className="space-y-3">
                <p className="text-sm text-text-secondary">What are you building?</p>
                {CLIENT_TYPES.map(ct => (
                  <button
                    key={ct.id}
                    onClick={() => selectType(ct)}
                    className="flex w-full items-center gap-4 rounded-xl border border-surface-2 bg-bg-secondary p-4 text-left transition-all hover:border-brand-violet/40 hover:bg-surface-1"
                  >
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-violet/10">
                      <ct.icon size={20} className="text-brand-violet" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-text-primary">{ct.label}</p>
                      <p className="text-xs text-text-muted">{ct.desc}</p>
                    </div>
                  </button>
                ))}
                <button onClick={() => { setShowCreate(false); resetForm() }} className="w-full rounded-xl border border-surface-2 px-4 py-2.5 text-sm text-text-secondary hover:bg-surface-2 transition-colors">Cancel</button>
              </div>
            ) : (
              /* Step 2: Compact form */
              <div className="space-y-4">
                {/* Selected type indicator */}
                <div className="flex items-center gap-3 rounded-xl bg-brand-violet/5 border border-brand-violet/10 px-4 py-2.5">
                  <clientType.icon size={16} className="text-brand-violet" />
                  <div className="flex-1">
                    <span className="text-sm font-medium text-text-primary">{clientType.label}</span>
                    <span className="ml-2 text-xs text-text-muted">{clientType.desc}</span>
                  </div>
                  <button onClick={() => setClientType(null)} className="text-xs text-text-muted hover:text-text-secondary">Change</button>
                </div>

                <div>
                  <label className="mb-1.5 block text-xs font-medium text-text-secondary">Name <span className="text-semantic-error">*</span></label>
                  <input value={name} onChange={e => { setName(e.target.value); setFormErrors({...formErrors, name: ''}) }} placeholder="My Application" className="w-full rounded-xl border border-surface-2 bg-bg-secondary px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20" autoFocus />
                  {formErrors.name && <p className="mt-1 text-xs text-semantic-error">{formErrors.name}</p>}
                </div>

                <div>
                  <label className="mb-1.5 block text-xs font-medium text-text-secondary">Redirect URIs <span className="text-semantic-error">*</span></label>
                  <div className="space-y-2">
                    {redirectUris.map((uri, i) => (
                      <div key={i} className="flex items-center gap-2">
                        <input value={uri} onChange={e => updateRedirectUri(i, e.target.value)} placeholder={`https://app.example.com/callback${redirectUris.length > 1 ? ` ${i+1}` : ''}`} className="flex-1 rounded-xl border border-surface-2 bg-bg-secondary px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 font-mono" />
                        {redirectUris.length > 1 && <button onClick={() => removeRedirectUri(i)} className="shrink-0 text-text-muted hover:text-semantic-error"><Trash2 size={14} /></button>}
                      </div>
                    ))}
                  </div>
                  <button onClick={addRedirectUri} className="mt-2 text-xs text-brand-violet hover:text-brand-blue font-medium">+ Add another URI</button>
                  {formErrors.redirect_uris && <p className="mt-1 text-xs text-semantic-error">{formErrors.redirect_uris}</p>}
                </div>

                {/* Advanced toggle */}
                <button onClick={() => setShowAdvanced(!showAdvanced)} className="flex w-full items-center gap-1.5 text-xs font-medium text-text-muted hover:text-text-secondary transition-colors">
                  {showAdvanced ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  Advanced settings
                </button>

                {showAdvanced && (
                  <div className="space-y-3 rounded-xl border border-surface-2 bg-bg-secondary p-4">
                    <div>
                      <label className="block text-xs font-medium text-text-secondary mb-1">Scopes</label>
                      <input value={scopes} onChange={e => setScopes(e.target.value)} placeholder="openid, profile, email" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                      <p className="mt-1 text-[11px] text-text-muted">Comma-separated permissions the client can request.</p>
                    </div>
                    {clientType.grant_types.includes('authorization_code') && (
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm text-text-primary">Refresh Token</p>
                          <p className="text-xs text-text-muted">Issue long-lived refresh tokens</p>
                        </div>
                        <button onClick={() => setRefreshToken(!refreshToken)} className={`relative h-5 w-9 rounded-full transition-colors ${refreshToken ? 'bg-brand-violet' : 'bg-surface-3'}`}>
                          <span className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform ${refreshToken ? 'translate-x-4' : ''}`} />
                        </button>
                      </div>
                    )}
                  </div>
                )}

                <div className="flex gap-3 pt-1">
                  <button onClick={() => { setShowCreate(false); resetForm() }} className="flex-1 rounded-xl border border-surface-2 px-4 py-2.5 text-sm text-text-secondary hover:bg-surface-2 transition-colors">Cancel</button>
                  <button onClick={handleCreate} disabled={saving} className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100">
                    {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                    Create
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Post-create secret modal uses same state as rotate */}
    </div>
  )
}
