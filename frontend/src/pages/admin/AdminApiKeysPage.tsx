import { useState, useEffect } from 'react'
import { Search, Loader2, Trash2, Key, Plus, Save, Ban, Copy, Check, RotateCcw } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

interface ApiKeyData {
  key_id: string
  user_id: string
  user_email: string
  name: string
  key_prefix: string
  scopes: string[]
  created_at: string
  is_active: boolean
  expires_at: string | null
}

interface CreateForm {
  user_email: string
  name: string
  scopes: string
  expires_in_days: string
}

interface CreatedKey {
  key_id: string
  api_key: string
  name: string
}

const initialForm: CreateForm = {
  user_email: '',
  name: '',
  scopes: '',
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
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [createdKey, setCreatedKey] = useState<CreatedKey | null>(null)
  const [copied, setCopied] = useState(false)

  const queryParam = search ? `?q=${encodeURIComponent(search)}` : ''
  const { data, refetch, isLoading } = useApiQuery<ApiKeyData[] | { items?: ApiKeyData[]; keys?: ApiKeyData[] }>(
    ['admin-keys', search],
    `/api/admin/keys${queryParam}`,
  )
  const keys: ApiKeyData[] = Array.isArray(data) ? data : (data?.items || data?.keys || [])

  useEffect(() => {
    if (success) {
      const t = setTimeout(() => setSuccess(''), 3000)
      return () => clearTimeout(t)
    }
  }, [success])

  const handleRevoke = async () => {
    if (!revokeId) return
    setError('')
    try {
      await api.post(`/api/keys/${revokeId}/revoke`)
      setRevokeId(null)
      setSuccess('Key revoked. You can restore it later if needed.')
      await refetch()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to revoke key'
      setError(msg)
    }
  }

  const handleRestore = async () => {
    if (!restoreId) return
    setError('')
    try {
      await api.patch(`/api/keys/${restoreId}`, { is_active: true })
      setRestoreId(null)
      setSuccess('Key restored successfully.')
      await refetch()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to restore key'
      setError(msg)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    setError('')
    try {
      await api.delete(`/api/keys/${deleteId}`)
      setDeleteId(null)
      setSuccess('Key deleted successfully.')
      await refetch()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to delete key'
      if (msg.includes('403') || msg.includes('authorized')) {
        setError('Delete failed: you may need admin scope.')
      } else {
        setError(msg)
      }
    }
  }

  const handleCleanup = async () => {
    setCleaning(true)
    setError('')
    try {
      await api.post('/api/admin/keys/cleanup')
      setSuccess('Expired keys cleaned up.')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to cleanup keys')
    } finally {
      setCleaning(false)
    }
  }

  const handleCreate = async () => {
    if (!form.name || !form.user_email) return
    setSaving(true)
    setError('')
    try {
      const scopes = form.scopes
        ? form.scopes.split(',').map((s) => s.trim()).filter(Boolean)
        : []
      const body: Record<string, unknown> = {
        name: form.name,
        scopes,
        user_email: form.user_email,
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
      })
      setCopied(false)
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create key')
    } finally {
      setSaving(false)
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
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Expires</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {keys.map((k, i) => (
                <tr key={k.key_id || `key-${i}`} className={`hover:bg-surface-2/50 ${!k.is_active ? 'opacity-50' : ''}`}>
                  <td className="px-6 py-3 text-sm text-text-primary">{k.user_email}</td>
                  <td className="px-6 py-3 text-sm text-text-secondary">{k.name}</td>
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
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">{formatDateTime(k.created_at)}</td>
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">
                    {k.expires_at ? formatDateTime(k.expires_at) : 'Never'}
                  </td>
                  <td className="px-6 py-3">
                    <div className="flex gap-2">
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
          <div className="absolute inset-0 bg-black/50" onClick={() => { setShowCreate(false); setForm(initialForm) }} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet">
            <h3 className="text-lg font-semibold text-text-primary">Create API Key</h3>

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

            <div className="flex gap-3 pt-2">
              <button
                onClick={() => { setShowCreate(false); setForm(initialForm) }}
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

            <button
              onClick={closeCreatedKey}
              className="w-full rounded-xl bg-gradient-cta px-4 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02]"
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
