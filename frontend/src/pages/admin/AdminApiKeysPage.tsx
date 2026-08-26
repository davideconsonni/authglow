import { useState } from 'react'
import { Search, Loader2, Trash2, Key, Plus, Save, Ban, Copy, Check, RotateCcw, Pencil, X } from 'lucide-react'
import { api } from '../../lib/api'
import { useApiQuery } from '../../hooks/useApi'
import { ConfirmDialog } from '../../components/shared/ConfirmDialog'
import { Banner } from '../../components/shared/Banner'
import { ApiKeyClaimsTab } from '../../components/admin/ApiKeyClaimsTab'
import { PageHeader } from '../../components/layout/PageHeader'
import { formatDateTime } from '../../lib/utils'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { notify } from '../../stores/toastStore'

interface ApiKeyData {
  key_id: string
  user_id: string
  user_email: string
  name: string
  description: string | null
  key_prefix: string
  scopes: string[]
  created_at: string
  is_active: boolean
  expires_at: string | null
  allowed_ips: string[]
  tier?: string | null
}

interface CreateForm {
  user_email: string
  name: string
  description: string
  scopes: string
  expires_in_days: string
  allowed_ips: string
  tier: string
}

interface EditForm {
  name: string
  description: string
  scopes: string
  allowed_ips: string
  tier: string
  expires_in_days: string
}

interface CreatedKey {
  key_id: string
  api_key: string
  name: string
  key_prefix?: string
  requested_scopes: string[]
  granted_scopes: string[]
  filtered_scopes: string[]
}

const initialForm: CreateForm = {
  user_email: '',
  name: '',
  description: '',
  scopes: '',
  expires_in_days: '',
  allowed_ips: '',
  tier: '',
}

const initialEdit: EditForm = {
  name: '',
  description: '',
  scopes: '',
  allowed_ips: '',
  tier: '',
  expires_in_days: '',
}

export function AdminApiKeysPage() {
  useDocumentTitle('Admin API Keys')
  const [search, setSearch] = useState('')
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [restoreId, setRestoreId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [cleaning, setCleaning] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState<CreateForm>(initialForm)
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [createdKey, setCreatedKey] = useState<CreatedKey | null>(null)
  const [copied, setCopied] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editForm, setEditForm] = useState<EditForm>(initialEdit)
  const [editNeverExpires, setEditNeverExpires] = useState(false)
  const [savingEdit, setSavingEdit] = useState(false)
  // Token Claims policy editor modal — opened from the per-row
  // KeyRound button. Tracks the key so the modal can call the
  // /api/admin/api-keys/{id}/claim-policy endpoint.
  const [claimsKey, setClaimsKey] = useState<{ id: string; name: string } | null>(null)

  const queryParam = search ? `?q=${encodeURIComponent(search)}` : ''
  const { data, refetch, isLoading } = useApiQuery<ApiKeyData[] | { items?: ApiKeyData[]; keys?: ApiKeyData[] }>(
    ['admin-keys', search],
    `/api/admin/keys${queryParam}`,
  )
  const keys: ApiKeyData[] = Array.isArray(data) ? data : (data?.items || data?.keys || [])

  const handleRevoke = async () => {
    if (!revokeId) return
    try {
      await api.post(`/api/keys/${revokeId}/revoke`)
      setRevokeId(null)
      notify.success('Key revoked. You can restore it later if needed.')
      await refetch()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to revoke key'
      notify.error(msg)
    }
  }

  const handleRestore = async () => {
    if (!restoreId) return
    try {
      await api.patch(`/api/keys/${restoreId}`, { is_active: true })
      setRestoreId(null)
      notify.success('Key restored successfully.')
      await refetch()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to restore key'
      notify.error(msg)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.delete(`/api/keys/${deleteId}`)
      setDeleteId(null)
      notify.success('Key deleted successfully.')
      await refetch()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to delete key'
      if (msg.includes('403') || msg.includes('authorized')) {
        notify.error('Delete failed: you may need admin scope.')
      } else {
        notify.error(msg)
      }
    }
  }

  const handleCleanup = async () => {
    setCleaning(true)
    try {
      await api.post('/api/admin/keys/cleanup')
      notify.success('Expired keys cleaned up.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to cleanup keys')
    } finally {
      setCleaning(false)
    }
  }

  const handleCreate = async () => {
    if (!form.name || !form.user_email) return
    setSaving(true)
    setFormError(null)
    try {
      const scopes = form.scopes
        ? form.scopes.split(',').map((s) => s.trim()).filter(Boolean)
        : []
      const allowed_ips = form.allowed_ips
        ? form.allowed_ips.split(',').map((s) => s.trim()).filter(Boolean)
        : []
      const body: Record<string, unknown> = {
        name: form.name,
        description: form.description.trim() || null,
        scopes,
        user_email: form.user_email,
        allowed_ips,
        tier: form.tier.trim() || null,
      }
      const days = parseInt(form.expires_in_days, 10)
      if (!isNaN(days) && days > 0) {
        body.expires_in_days = days
      }
      const result = await api.post<CreatedKey>('/api/keys', body)
      setShowCreate(false)
      setForm(initialForm)
      setCreatedKey({
        key_id: result.key_id,
        api_key: result.api_key,
        name: result.name || form.name,
        key_prefix: result.key_prefix,
        requested_scopes: result.requested_scopes || [],
        granted_scopes: result.granted_scopes || [],
        filtered_scopes: result.filtered_scopes || [],
      })
      setCopied(false)
      await refetch()
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : 'Failed to create key')
    } finally {
      setSaving(false)
    }
  }

  const openEdit = (k: ApiKeyData) => {
    setEditingId(k.key_id)
    setEditForm({
      name: k.name,
      description: k.description || '',
      scopes: (k.scopes || []).join(', '),
      allowed_ips: (k.allowed_ips || []).join(', '),
      tier: k.tier || '',
      expires_in_days: '',
    })
    setEditNeverExpires(false)
  }

  const closeEdit = () => {
    setEditingId(null)
    setEditForm(initialEdit)
    setEditNeverExpires(false)
  }

  const handleSaveEdit = async () => {
    if (!editingId) return
    setSavingEdit(true)
    try {
      await api.patch(`/api/keys/${editingId}`, {
        name: editForm.name,
        description: editForm.description.trim() || null,
        scopes: editForm.scopes.split(',').map((s) => s.trim()).filter(Boolean),
        allowed_ips: editForm.allowed_ips
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        tier: editForm.tier.trim() || null,
        ...(editNeverExpires
          ? { never_expires: true }
          : editForm.expires_in_days
            ? { expires_in_days: parseInt(editForm.expires_in_days, 10) }
            : {}),
      })
      closeEdit()
      notify.success('Key updated.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to update key')
    } finally {
      setSavingEdit(false)
    }
  }

  const handleCopyKey = () => {
    if (!createdKey) return
    navigator.clipboard.writeText(createdKey.api_key)
    setCopied(true)
    setTimeout(() => setCopied(false), 3000)
  }

  const closeCreatedKey = () => {
    setCreatedKey(null)
    setCopied(false)
  }

  return (
    <div>
      <PageHeader
        title="API Keys"
        description="Manage all API keys across users."
        actions={
          <div className="flex gap-2">
            <button
              onClick={handleCleanup}
              disabled={cleaning}
              className="flex items-center gap-2 rounded-xl border border-semantic-error/30 px-4 py-2 text-xs font-medium text-semantic-error hover:bg-semantic-error/10 transition-colors disabled:opacity-50"
            >
              {cleaning && <Loader2 size={14} className="animate-spin" />}
              Cleanup Expired
            </button>
            <button
              onClick={() => setShowCreate(true)}
              className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              <Plus size={16} />
              Create Key
            </button>
          </div>
        }
      />

      <div className="mb-4">
        <div className="relative max-w-sm">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by user email..."
            className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 pl-10 pr-4 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
          />
        </div>
      </div>

      {isLoading ? (
        <div className="py-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" />
        </div>
      ) : !keys || keys.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-surface-2 bg-surface-1 py-16 text-center">
          <div className="rounded-2xl bg-surface-2 p-4">
            <Key className="h-8 w-8 text-text-muted" />
          </div>
          <h3 className="mt-4 text-lg font-semibold text-text-primary">No API keys</h3>
          <p className="mt-2 max-w-sm text-sm text-text-muted">
            {search
              ? 'No keys match your filter. Try different keywords.'
              : 'Create your first API key to get started.'}
          </p>
          {!search && (
            <button
              onClick={() => setShowCreate(true)}
              className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              <Plus size={16} />
              Create Key
            </button>
          )}
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
              <thead className="border-b border-surface-2">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">User</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Prefix</th>
                  <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Scopes</th>
                  <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">IP Restriction</th>
                  <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                  <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Expires</th>
                  <th className="px-6 py-3" />
                </tr>
              </thead>
            <tbody className="divide-y divide-surface-2">
              {keys.map((k, i) => (
                <tr key={k.key_id || `key-${i}`} className={`hover:bg-surface-2/50 ${!k.is_active ? 'opacity-50' : ''}`}>
                  <td className="px-6 py-3 text-sm text-text-primary">{k.user_email}</td>
                  <td className="px-6 py-3 text-sm text-text-secondary">
                    <div>{k.name}</div>
                    {k.description && (
                      <p
                        className="mt-0.5 max-w-md truncate text-xs text-text-muted"
                        title={k.description}
                        data-testid="key-description-display"
                      >
                        {k.description}
                      </p>
                    )}
                  </td>
                  <td className="px-6 py-3">
                    <code className="text-xs font-mono text-text-secondary">{k.key_prefix}</code>
                  </td>
                  <td className="hidden md:table-cell px-6 py-3">
                    <div className="flex flex-wrap gap-1">
                      {k.scopes?.map((s, si) => (
                        <span
                          key={`${s}-${si}`}
                          className="rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary"
                        >
                          {s}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="hidden md:table-cell px-6 py-3" data-testid="key-ips-display">
                    {k.allowed_ips && k.allowed_ips.length > 0 ? (
                      <span
                        className="rounded-lg bg-brand-violet/10 px-2 py-0.5 text-xs text-brand-violet"
                        title={k.allowed_ips.join(', ')}
                      >
                        {k.allowed_ips[0]}{k.allowed_ips.length > 1 ? ` +${k.allowed_ips.length - 1}` : ''}
                      </span>
                    ) : (
                      <span className="text-xs text-text-muted">—</span>
                    )}
                  </td>
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">{formatDateTime(k.created_at)}</td>
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">
                    {k.expires_at ? formatDateTime(k.expires_at) : 'Never'}
                  </td>
                  <td className="px-6 py-3">
                    <div className="flex gap-2">
                      <button
                        onClick={() => openEdit(k)}
                        data-testid="key-edit-btn"
                        className="text-text-muted hover:text-brand-violet transition-colors"
                        title="Edit key"
                      >
                        <Pencil size={14} />
                      </button>
                      <button
                        onClick={() => setClaimsKey({ id: k.key_id, name: k.name })}
                        data-testid="open-claims-btn"
                        className="text-text-muted hover:text-brand-violet transition-colors"
                        title="Token Claims (customize JWT claims)"
                      >
                        <Key size={14} />
                      </button>
                      {k.is_active ? (
                        <button
                          onClick={() => setRevokeId(k.key_id)}
                          className="text-text-muted hover:text-semantic-warning transition-colors"
                          title="Deactivate key (reversible)"
                        >
                          <Ban size={14} />
                        </button>
                      ) : (
                        <button
                          onClick={() => setRestoreId(k.key_id)}
                          className="text-text-muted hover:text-semantic-success transition-colors"
                          title="Reactivate key"
                        >
                          <RotateCcw size={14} />
                        </button>
                      )}
                      <button
                        onClick={() => setDeleteId(k.key_id)}
                        className="text-text-muted hover:text-semantic-error transition-colors"
                        title="Delete key permanently (irreversible)"
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
        open={!!revokeId}
        title="Deactivate API Key"
        message="The key will stop working immediately but you can reactivate it later. Use Delete if you want to remove it permanently."
        confirmLabel="Deactivate"
        variant="danger"
        onConfirm={handleRevoke}
        onCancel={() => setRevokeId(null)}
      />

      <ConfirmDialog
        open={!!restoreId}
        title="Reactivate API Key"
        message="This will make the key active again. All services using this key will regain access."
        confirmLabel="Reactivate"
        variant="danger"
        onConfirm={handleRestore}
        onCancel={() => setRestoreId(null)}
      />

      <ConfirmDialog
        open={!!deleteId}
        title="Delete API Key"
        message="This permanently removes the key. It cannot be recovered. Use Deactivate if you might need to restore it later."
        confirmLabel="Delete"
        variant="danger"
        onConfirm={handleDelete}
        onCancel={() => setDeleteId(null)}
      />

      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => { setShowCreate(false); setForm(initialForm); setFormError(null) }} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet">
            <h3 className="text-lg font-semibold text-text-primary">Create API Key</h3>

            {formError && (
              <Banner
                variant="error"
                size="sm"
                onDismiss={() => setFormError(null)}
                data-testid="apikey-form-error"
              >
                {formError}
              </Banner>
            )}

            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">User email</label>
              <input
                value={form.user_email}
                onChange={(e) => setForm({ ...form, user_email: e.target.value })}
                placeholder="user@example.com"
                type="email"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Key name</label>
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Production API key"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Scopes (comma-separated)</label>
              <input
                value={form.scopes}
                onChange={(e) => setForm({ ...form, scopes: e.target.value })}
                placeholder="read, write"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Description (optional)</label>
              <textarea
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                placeholder="e.g. Production server backup automation, rotated 2026-Q3"
                rows={2}
                data-testid="key-description-input"
                className="w-full resize-y rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Expiration (days, optional)</label>
              <input
                value={form.expires_in_days}
                onChange={(e) => setForm({ ...form, expires_in_days: e.target.value })}
                placeholder="365"
                type="number"
                min="1"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Restrict to IPs or CIDR ranges (comma-separated, optional)</label>
              <input
                value={form.allowed_ips}
                onChange={(e) => setForm({ ...form, allowed_ips: e.target.value })}
                placeholder="203.0.113.5, 198.51.100.0/24"
                data-testid="key-allowed-ips-input"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>

            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Tier (optional)</label>
              <input
                value={form.tier}
                onChange={(e) => setForm({ ...form, tier: e.target.value })}
                placeholder="production, staging, dev"
                data-testid="key-tier-input"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>

            <div className="flex gap-3 pt-2">
              <button
                onClick={() => { setShowCreate(false); setForm(initialForm); setFormError(null) }}
                className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={saving || !form.name || !form.user_email}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
              >
                {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Create Key
              </button>
            </div>
          </div>
        </div>
      )}

      {createdKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={closeCreatedKey} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet">
            <div className="text-center space-y-2">
              <div className="rounded-2xl bg-semantic-success/10 p-3 inline-block">
                <Key size={24} className="text-semantic-success" />
              </div>
              <h3 className="text-lg font-semibold text-text-primary">API Key Created</h3>
              <p className="text-xs text-semantic-warning">
                Copy this key now. You won't be able to see it again.
              </p>
            </div>

            <div className="rounded-xl border border-surface-2 bg-surface-2 p-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs text-text-muted">{createdKey.name}</span>
                <span className="text-[10px] font-mono text-text-muted">{createdKey.key_id}</span>
              </div>
              <div className="flex items-center gap-2">
                <code className="flex-1 break-all text-sm font-mono text-text-primary">
                  {createdKey.api_key}
                </code>
                <button
                  onClick={handleCopyKey}
                  className="rounded-xl p-2 text-text-muted hover:bg-surface-3 hover:text-text-secondary transition-colors shrink-0"
                  title="Copy key"
                >
                  {copied ? <Check size={16} className="text-semantic-success" /> : <Copy size={16} />}
                </button>
              </div>
            </div>

            {createdKey.filtered_scopes && createdKey.filtered_scopes.length > 0 && (
              <div
                role="alert"
                data-testid="scope-filter-warning"
                className="rounded-xl border border-semantic-warning/30 bg-semantic-warning/10 p-3 text-left"
              >
                <p className="text-xs font-medium text-semantic-warning">Some scopes were filtered</p>
                <p className="mt-1 text-xs text-text-secondary">
                  Requested: <code className="font-mono">{createdKey.requested_scopes.join(', ') || '(none)'}</code>
                </p>
                <p className="text-xs text-text-secondary">
                  Granted: <code className="font-mono">{createdKey.granted_scopes.join(', ') || '(none)'}</code>
                </p>
                <p className="text-xs text-text-secondary">
                  Filtered: <code className="font-mono">{createdKey.filtered_scopes.join(', ')}</code>
                </p>
                <p className="mt-1 text-[11px] text-text-muted">
                  These scopes were not granted because they are not available on the calling admin&apos;s account.
                </p>
              </div>
            )}

            <button
              onClick={closeCreatedKey}
              className="w-full rounded-xl bg-gradient-cta px-4 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02]"
            >
              Done
            </button>
          </div>
        </div>
      )}

      {editingId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={closeEdit} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet" data-testid="key-edit-modal">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-text-primary">Edit API Key</h3>
              <button onClick={closeEdit} className="text-text-muted hover:text-text-primary" aria-label="Close">
                <X size={16} />
              </button>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Name</label>
              <input
                value={editForm.name}
                onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                data-testid="key-edit-name-input"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Description</label>
              <textarea
                value={editForm.description}
                onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                placeholder="e.g. Production server backup automation, rotated 2026-Q3"
                rows={2}
                data-testid="key-edit-description-input"
                className="w-full resize-y rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Scopes (comma-separated)</label>
              <input
                value={editForm.scopes}
                onChange={(e) => setEditForm({ ...editForm, scopes: e.target.value })}
                data-testid="key-edit-scopes-input"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Allowed IPs (comma-separated, IP or CIDR)</label>
              <input
                value={editForm.allowed_ips}
                onChange={(e) => setEditForm({ ...editForm, allowed_ips: e.target.value })}
                placeholder="203.0.113.5, 198.51.100.0/24"
                data-testid="key-edit-allowed-ips-input"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Tier (optional)</label>
              <input
                value={editForm.tier}
                onChange={(e) => setEditForm({ ...editForm, tier: e.target.value })}
                placeholder="production, staging, dev"
                data-testid="key-edit-tier-input"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Expiration</label>
              <input
                type="number"
                min={1}
                max={365}
                value={editForm.expires_in_days}
                onChange={(e) => setEditForm({ ...editForm, expires_in_days: e.target.value })}
                disabled={editNeverExpires}
                placeholder="Expires in days (empty = unchanged)"
                data-testid="key-edit-expires-input"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none disabled:opacity-50"
              />
              <label className="mt-1.5 flex cursor-pointer items-center gap-2 text-xs text-text-secondary">
                <input
                  type="checkbox"
                  checked={editNeverExpires}
                  onChange={(e) => setEditNeverExpires(e.target.checked)}
                  data-testid="key-edit-never-expires-toggle"
                  className="accent-brand-violet"
                />
                Never expires
                {(() => {
                  const editingKey = keys?.find((k) => k.key_id === editingId)
                  return editingKey?.expires_at ? (
                    <span className="text-text-muted">(currently: {formatDateTime(editingKey.expires_at)})</span>
                  ) : null
                })()}
              </label>
            </div>
            <div className="flex gap-3 pt-2">
              <button onClick={closeEdit} className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2 transition-colors">Cancel</button>
              <button
                onClick={handleSaveEdit}
                disabled={savingEdit}
                data-testid="key-edit-submit"
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
              >
                {savingEdit ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Token Claims policy editor - opened from the per-row
          KeyRound button. Renders above the create/edit form
          (z-50 modal) so the admin can move between editing
          the key metadata and its claim policy. */}
      {claimsKey && (
        <ApiKeyClaimsTab
          keyId={claimsKey.id}
          keyName={claimsKey.name}
          onClose={() => setClaimsKey(null)}
        />
      )}
    </div>
  )
}
