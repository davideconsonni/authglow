import { useState, useEffect } from 'react'
import { Trash2, RefreshCw, Plus, Loader2, Copy, Check, Save, Shield } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'

interface OAuthClient {
  id: string
  name: string
  client_id: string
  is_confidential: boolean
  redirect_uris: string[]
  grant_types: string[]
  is_active: boolean
}

interface CreateForm {
  name: string
  redirect_uris: string
  grant_types: string[]
  is_confidential: boolean
  scopes: string
}

const GRANT_TYPE_OPTIONS = [
  { value: 'authorization_code', label: 'Authorization Code' },
  { value: 'client_credentials', label: 'Client Credentials' },
  { value: 'refresh_token', label: 'Refresh Token' },
  { value: 'password', label: 'Password' },
]

const initialForm: CreateForm = {
  name: '',
  redirect_uris: '',
  grant_types: ['authorization_code'],
  is_confidential: true,
  scopes: '',
}

export function AdminOAuthClientsPage() {
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState<CreateForm>(initialForm)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [secretModal, setSecretModal] = useState<{ id: string; secret: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const { data, refetch } = useApiQuery<OAuthClient[]>(['admin-oauth-clients'], '/api/oauth-clients')
  const clients: OAuthClient[] = Array.isArray(data) ? data : ((data as any)?.items as OAuthClient[]) ?? []

  useEffect(() => {
    if (success) {
      const t = setTimeout(() => setSuccess(''), 3000)
      return () => clearTimeout(t)
    }
  }, [success])

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      setError('')
      await api.delete(`/api/oauth-clients/${deleteId}`)
      setDeleteId(null)
      setSuccess('Client deleted successfully.')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete client')
    }
  }

  const handleToggle = async (id: string, active: boolean) => {
    try {
      setError('')
      if (active) {
        await api.post(`/api/oauth-clients/${id}/deactivate`)
      } else {
        await api.post(`/api/oauth-clients/${id}/activate`)
      }
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to toggle client')
    }
  }

  const handleRotate = async (id: string) => {
    try {
      setError('')
      const res = await api.post<{ secret: string }>(`/api/oauth-clients/${id}/rotate-secret`)
      setSecretModal({ id, secret: res.secret })
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to rotate secret')
    }
  }

  const handleCopy = async () => {
    if (!secretModal) return
    await navigator.clipboard.writeText(secretModal.secret)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleCreate = async () => {
    if (!form.name) return
    setSaving(true)
    setError('')
    try {
      const redirect_uris = form.redirect_uris
        .split('\n')
        .map((u) => u.trim())
        .filter(Boolean)

      const scopes = form.scopes
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)

      await api.post('/api/oauth-clients', {
        name: form.name,
        redirect_uris,
        grant_types: form.grant_types,
        is_confidential: form.is_confidential,
        scopes,
      })
      setShowCreate(false)
      setForm(initialForm)
      setSuccess('Client created successfully.')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create client')
    } finally {
      setSaving(false)
    }
  }

  const toggleGrant = (gt: string) => {
    setForm((f) => ({
      ...f,
      grant_types: f.grant_types.includes(gt)
        ? f.grant_types.filter((g) => g !== gt)
        : [...f.grant_types, gt],
    }))
  }

  return (
    <div>
      <PageHeader
        title="OAuth Clients"
        description="Manage OAuth2 client applications."
        actions={
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Plus size={16} />
            Create Client
          </button>
        }
      />

      {error && (
        <div className="mb-4 rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 rounded-xl bg-semantic-success/10 px-4 py-2 text-xs text-semantic-success">
          {success}
        </div>
      )}

      {!clients || clients.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-surface-2 bg-surface-1 py-16 text-center">
          <div className="rounded-2xl bg-surface-2 p-4">
            <Shield className="h-8 w-8 text-text-muted" />
          </div>
          <h3 className="mt-4 text-lg font-semibold text-text-primary">No OAuth clients</h3>
          <p className="mt-2 max-w-sm text-sm text-text-muted">
            Create your first OAuth2 client application to get started.
          </p>
          <button
            onClick={() => setShowCreate(true)}
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Plus size={16} />
            Create Client
          </button>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Client ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Active</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {clients.map((c) => (
                <tr key={c.id} className="hover:bg-surface-2/50">
                  <td className="px-6 py-3 text-sm font-medium text-text-primary">{c.name}</td>
                  <td className="px-6 py-3">
                    <code className="text-xs text-text-muted">{c.client_id}</code>
                  </td>
                  <td className="px-6 py-3">
                    <span
                      className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${
                        c.is_confidential
                          ? 'bg-brand-violet/10 text-brand-violet'
                          : 'bg-surface-2 text-text-muted'
                      }`}
                    >
                      {c.is_confidential ? 'Confidential' : 'Public'}
                    </span>
                  </td>
                  <td className="px-6 py-3">
                    <button
                      onClick={() => handleToggle(c.id, c.is_active)}
                      className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium transition-colors ${
                        c.is_active
                          ? 'bg-semantic-success/10 text-semantic-success hover:bg-semantic-success/20'
                          : 'bg-semantic-error/10 text-semantic-error hover:bg-semantic-error/20'
                      }`}
                    >
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          c.is_active ? 'bg-semantic-success' : 'bg-semantic-error'
                        }`}
                      />
                      {c.is_active ? 'Active' : 'Inactive'}
                    </button>
                  </td>
                  <td className="px-6 py-3">
                    <div className="flex gap-2">
                      <button
                        onClick={() => handleRotate(c.id)}
                        className="text-text-muted hover:text-text-secondary transition-colors"
                        title="Rotate secret"
                      >
                        <RefreshCw size={14} />
                      </button>
                      <button
                        onClick={() => setDeleteId(c.id)}
                        className="text-text-muted hover:text-semantic-error transition-colors"
                        title="Delete client"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={!!deleteId}
        title="Delete OAuth Client"
        message="This will revoke all tokens issued to this client. This action cannot be undone."
        confirmLabel="Delete"
        variant="danger"
        onConfirm={handleDelete}
        onCancel={() => setDeleteId(null)}
      />

      {secretModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => { setSecretModal(null); setCopied(false) }} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet">
            <h3 className="text-lg font-semibold text-text-primary">New Client Secret</h3>
            <p className="text-xs text-text-muted">
              Copy this secret now. You will not be able to see it again.
            </p>
            <div className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-2 px-4 py-3">
              <code className="flex-1 break-all text-sm text-text-primary">{secretModal.secret}</code>
              <button
                onClick={handleCopy}
                className="rounded-lg p-1.5 text-text-muted hover:bg-surface-3 hover:text-text-secondary transition-colors"
                title="Copy to clipboard"
              >
                {copied ? <Check size={16} className="text-semantic-success" /> : <Copy size={16} />}
              </button>
            </div>
            <button
              onClick={() => { setSecretModal(null); setCopied(false) }}
              className="w-full rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2 transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      )}

      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => { setShowCreate(false); setForm(initialForm) }} />
          <div className="relative z-10 w-full max-w-lg rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-text-primary">Create OAuth Client</h3>

            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Name</label>
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="My Application"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Redirect URIs (one per line)</label>
              <textarea
                value={form.redirect_uris}
                onChange={(e) => setForm({ ...form, redirect_uris: e.target.value })}
                placeholder="https://app.example.com/callback"
                rows={3}
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none resize-none"
              />
            </div>

            <div>
              <p className="mb-2 text-xs font-medium text-text-muted">Grant Types</p>
              <div className="grid grid-cols-2 gap-2 rounded-xl border border-surface-2 bg-surface-1 p-3">
                {GRANT_TYPE_OPTIONS.map((gt) => (
                  <label
                    key={gt.value}
                    className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-surface-2/50 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={form.grant_types.includes(gt.value)}
                      onChange={() => toggleGrant(gt.value)}
                      className="accent-brand-violet"
                    />
                    <span className="text-xs text-text-secondary">{gt.label}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-between rounded-xl border border-surface-2 bg-surface-1 px-4 py-3">
              <div>
                <p className="text-sm font-medium text-text-primary">Confidential Client</p>
                <p className="text-xs text-text-muted">Client can securely store a secret</p>
              </div>
              <button
                onClick={() => setForm({ ...form, is_confidential: !form.is_confidential })}
                className={`relative h-6 w-11 rounded-full transition-colors ${
                  form.is_confidential ? 'bg-brand-violet' : 'bg-surface-3'
                }`}
              >
                <span
                  className={`absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white transition-transform ${
                    form.is_confidential ? 'translate-x-5' : ''
                  }`}
                />
              </button>
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Scopes (comma-separated)</label>
              <input
                value={form.scopes}
                onChange={(e) => setForm({ ...form, scopes: e.target.value })}
                placeholder="openid, profile, email"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>

            <div className="flex gap-3 pt-2">
              <button
                onClick={() => { setShowCreate(false); setForm(initialForm) }}
                className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={saving || !form.name}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
              >
                {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Create Client
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
