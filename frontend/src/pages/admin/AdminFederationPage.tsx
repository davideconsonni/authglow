import { useState } from 'react'
import { Plus, Loader2, Save, Trash2, Edit, Power, PowerOff } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { PageHeader } from '@/components/layout/PageHeader'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

interface FederationProvider {
  id: string
  label: string
  description?: string | null
  issuer: string
  client_id: string
  scopes: string[]
  icon_uri?: string | null
  logo_uri?: string | null
  enabled: boolean
  auth_levels?: string[] | null
  claims_mapping: Record<string, string>
  created_at: string
  updated_at: string
}

const emptyForm: FederationProvider = {
  id: '',
  label: '',
  description: '',
  issuer: '',
  client_id: '',
  scopes: ['openid', 'profile', 'email'],
  enabled: true,
  claims_mapping: { sub: 'external_id', email: 'email', name: 'name', picture: 'picture' },
  created_at: '',
  updated_at: '',
}

function TextInput(props: { value: string; onChange: (v: string) => void; placeholder?: string; label: string; autoFocus?: boolean; type?: string }) {
  return (
    <div>
      <label className="mb-1 block text-[11px] font-medium text-text-muted">{props.label}</label>
      <input
        type={props.type || 'text'}
        value={props.value}
        onChange={(e) => props.onChange(e.target.value)}
        placeholder={props.placeholder}
        autoFocus={props.autoFocus}
        className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
      />
    </div>
  )
}

export function AdminFederationPage() {
  useDocumentTitle('Federation')
  const [showForm, setShowForm] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [form, setForm] = useState<FederationProvider>({ ...emptyForm })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [rawScopes, setRawScopes] = useState('openid profile email')
  const [rawAuthLevels, setRawAuthLevels] = useState('')
  const [clientSecret, setClientSecret] = useState('')

  const { data: providers, refetch } = useApiQuery<FederationProvider[]>(
    ['federation', 'admin'],
    '/api/federation/admin/providers',
  )

  const resetForm = () => {
    setForm({ ...emptyForm })
    setRawScopes('openid profile email')
    setRawAuthLevels('')
    setClientSecret('')
    setEditId(null)
    setError(null)
  }

  const openCreate = () => {
    resetForm()
    setShowForm(true)
  }

  const openEdit = (p: FederationProvider) => {
    setForm({ ...p })
    setRawScopes((p.scopes || []).join(' '))
    setRawAuthLevels((p.auth_levels || []).join(', '))
    setClientSecret('')
    setEditId(p.id)
    setShowForm(true)
  }

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    const scopes = rawScopes.trim().split(/\s+/).filter(Boolean)
    const authLevels = rawAuthLevels.split(/[, ]+/).map(s => s.trim()).filter(Boolean)
    try {
      if (editId) {
        const updatePayload: Record<string, unknown> = {
          label: form.label,
          description: form.description || '',
          issuer: form.issuer,
          client_id: form.client_id,
          scopes,
          icon_uri: form.icon_uri || '',
          logo_uri: form.logo_uri || '',
          enabled: form.enabled,
          auth_levels: authLevels,
          claims_mapping: form.claims_mapping,
        }
        if (clientSecret) updatePayload.client_secret = clientSecret
        await api.put(`/api/federation/admin/providers/${editId}`, updatePayload)
        setSuccess('Provider updated.')
      } else {
        await api.post('/api/federation/providers', {
          label: form.label,
          description: form.description || null,
          issuer: form.issuer,
          client_id: form.client_id,
          client_secret: clientSecret || form.issuer,
          scopes,
          icon_uri: form.icon_uri || null,
          logo_uri: form.logo_uri || null,
          enabled: form.enabled,
          auth_levels: authLevels.length > 0 ? authLevels : null,
          claims_mapping: form.claims_mapping,
        })
        setSuccess('Provider created.')
      }
      setShowForm(false)
      resetForm()
      await refetch()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  const handleToggle = async (p: FederationProvider) => {
    try {
      await api.patch(`/api/federation/admin/providers/${p.id}/toggle`, {})
      setSuccess(`Provider ${p.enabled ? 'disabled' : 'enabled'}.`)
      await refetch()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle')
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.delete(`/api/federation/admin/providers/${deleteId}`)
      setDeleteId(null)
      setSuccess('Provider deleted.')
      await refetch()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete')
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Federation"
        description="Manage external identity providers (CIE, SPID, Google, etc.)"
        actions={
          <button onClick={openCreate} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02]">
            <Plus size={16} /> Add Provider
          </button>
        }
      />

      {error && <div className="rounded-xl border border-semantic-error/30 bg-semantic-error/10 px-4 py-3 text-sm text-semantic-error" role="alert">{error}</div>}
      {success && <div className="rounded-xl border border-semantic-success/30 bg-semantic-success/10 px-4 py-3 text-sm text-semantic-success">{success}</div>}

      {/* Provider list */}
      <div className="overflow-hidden rounded-2xl border border-surface-2 bg-surface-1">
        <table className="w-full">
          <thead>
            <tr className="border-b border-surface-2 text-left text-xs font-medium text-text-muted">
              <th className="px-6 py-3">Label</th>
              <th className="px-6 py-3">Issuer</th>
              <th className="px-6 py-3">Scopes</th>
              <th className="px-6 py-3">Status</th>
              <th className="px-6 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {(providers || []).map((p) => (
              <tr key={p.id} className={`border-b border-surface-2 hover:bg-surface-2/50 ${!p.enabled ? 'opacity-50' : ''}`}>
                <td className="px-6 py-3">
                  <div className="flex items-center gap-2">
                    {p.icon_uri && <img src={p.icon_uri} alt="" className="h-5 w-5 rounded" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }} />}
                    <div>
                      <p className="text-sm font-medium text-text-primary">{p.label}</p>
                      {p.description && <p className="text-xs text-text-muted">{p.description}</p>}
                    </div>
                  </div>
                </td>
                <td className="px-6 py-3 text-xs font-mono text-text-secondary max-w-[200px] truncate">{p.issuer}</td>
                <td className="px-6 py-3">
                  <div className="flex flex-wrap gap-1">
                    {p.scopes.map((s) => <span key={s} className="rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary">{s}</span>)}
                  </div>
                </td>
                <td className="px-6 py-3">
                  <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${p.enabled ? 'bg-semantic-success/10 text-semantic-success' : 'bg-surface-2 text-text-muted'}`}>
                    {p.enabled ? 'Active' : 'Disabled'}
                  </span>
                </td>
                <td className="px-6 py-3">
                  <div className="flex gap-2">
                    <button onClick={() => handleToggle(p)} className="text-text-muted hover:text-text-secondary" title={p.enabled ? 'Disable' : 'Enable'}>
                      {p.enabled ? <PowerOff size={14} /> : <Power size={14} />}
                    </button>
                    <button onClick={() => openEdit(p)} className="text-text-muted hover:text-text-secondary" title="Edit">
                      <Edit size={14} />
                    </button>
                    <button onClick={() => setDeleteId(p.id)} className="text-text-muted hover:text-semantic-error" title="Delete">
                      <Trash2 size={14} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {(!providers || providers.length === 0) && (
              <tr><td colSpan={5} className="px-6 py-12 text-center text-sm text-text-muted">No providers configured. Add your first one.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Create/Edit Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto py-8">
          <div className="absolute inset-0 bg-black/50" onClick={() => { setShowForm(false); resetForm() }} />
          <div className="relative z-10 w-full max-w-xl rounded-2xl border border-surface-2 bg-surface-1 p-6 shadow-glow-violet my-auto">
            <h3 className="mb-4 text-lg font-semibold text-text-primary">{editId ? 'Edit Provider' : 'New Provider'}</h3>

            <div className="space-y-3 mb-5">
              <TextInput label="Label *" value={form.label} onChange={(v) => setForm({ ...form, label: v })} placeholder="CIE" autoFocus />
              <TextInput label="Description" value={form.description || ''} onChange={(v) => setForm({ ...form, description: v })} placeholder="Carta d'Identità Elettronica" />
              <TextInput label="Issuer URL *" value={form.issuer} onChange={(v) => setForm({ ...form, issuer: v })} placeholder="https://accounts.google.com" />
              <TextInput label="Client ID *" value={form.client_id} onChange={(v) => setForm({ ...form, client_id: v })} placeholder="your-client-id" />
              <TextInput label="Client Secret *" type="password" value={clientSecret} onChange={(v) => setClientSecret(v)} placeholder="●●●●●●●●" />
              <div>
                <label className="mb-1 block text-[11px] font-medium text-text-muted">Scopes (space-separated)</label>
                <input
                  value={rawScopes}
                  onChange={(e) => setRawScopes(e.target.value)}
                  placeholder="openid profile email"
                  className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <TextInput label="Icon URI" value={form.icon_uri || ''} onChange={(v) => setForm({ ...form, icon_uri: v })} placeholder="https://example.com/icon.png" />
                <TextInput label="Logo URI" value={form.logo_uri || ''} onChange={(v) => setForm({ ...form, logo_uri: v })} placeholder="https://example.com/logo.png" />
              </div>
              <div>
                <label className="mb-1 block text-[11px] font-medium text-text-muted">Auth Levels (CIE: L1, L2, L3)</label>
                <input
                  value={rawAuthLevels}
                  onChange={(e) => setRawAuthLevels(e.target.value)}
                  placeholder="L1, L2, L3"
                  className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
                />
              </div>
            </div>

            <div className="flex gap-3">
              <button onClick={() => { setShowForm(false); resetForm() }} className="flex-1 rounded-xl border border-surface-2 px-4 py-2.5 text-sm text-text-secondary hover:bg-surface-2 transition-colors">Cancel</button>
              <button onClick={handleSave} disabled={saving} className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50">
                {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {deleteId && (
        <ConfirmDialog
          open={true}
          title="Delete Provider"
          message="This will permanently remove this federation provider configuration. Existing federated users will not be affected."
          onConfirm={() => { void handleDelete() }}
          onCancel={() => setDeleteId(null)}
          variant="danger"
        />
      )}
    </div>
  )
}