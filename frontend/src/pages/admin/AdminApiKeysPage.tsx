import { useState, useEffect } from 'react'
import { Search, Loader2, Trash2, Key, Plus, Save, Ban } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'

interface ApiKeyData {
  id: string
  user_email: string
  name: string
  key_prefix: string
  scopes: string[]
  created_at: string
  is_revoked: boolean
  expires_at: string | null
}

interface CreateForm {
  user_email: string
  name: string
  scopes: string
  expires_in_days: string
}

const initialForm: CreateForm = {
  user_email: '',
  name: '',
  scopes: '',
  expires_in_days: '',
}

export function AdminApiKeysPage() {
  const [search, setSearch] = useState('')
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [cleaning, setCleaning] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState<CreateForm>(initialForm)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const queryParam = search ? `?q=${encodeURIComponent(search)}` : ''
  const { data, refetch, isLoading } = useApiQuery<any>(
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
    try {
      setError('')
      await api.post(`/api/keys/${revokeId}/revoke`)
      setRevokeId(null)
      setSuccess('Key revoked successfully.')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to revoke key')
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      setError('')
      await api.delete(`/api/keys/${deleteId}`)
      setDeleteId(null)
      setSuccess('Key deleted successfully.')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete key')
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
      await api.post('/api/keys', body)
      setShowCreate(false)
      setForm(initialForm)
      setSuccess('Key created successfully.')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create key')
    } finally {
      setSaving(false)
    }
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
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Scopes</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Expires</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {keys.map((k) => (
                <tr key={k.id} className={`hover:bg-surface-2/50 ${k.is_revoked ? 'opacity-50' : ''}`}>
                  <td className="px-6 py-3 text-sm text-text-primary">{k.user_email}</td>
                  <td className="px-6 py-3 text-sm text-text-secondary">{k.name}</td>
                  <td className="px-6 py-3">
                    <code className="text-xs text-text-muted">{k.key_prefix}...</code>
                  </td>
                  <td className="px-6 py-3">
                    <div className="flex flex-wrap gap-1">
                      {k.scopes?.map((s) => (
                        <span
                          key={s}
                          className="rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary"
                        >
                          {s}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-3 text-sm text-text-muted">{formatDateTime(k.created_at)}</td>
                  <td className="px-6 py-3 text-sm text-text-muted">
                    {k.expires_at ? formatDateTime(k.expires_at) : 'Never'}
                  </td>
                  <td className="px-6 py-3">
                    <div className="flex gap-2">
                      {!k.is_revoked && (
                        <button
                          onClick={() => setRevokeId(k.id)}
                          className="text-text-muted hover:text-semantic-error transition-colors"
                          title="Revoke key"
                        >
                          <Ban size={14} />
                        </button>
                      )}
                      <button
                        onClick={() => setDeleteId(k.id)}
                        className="text-text-muted hover:text-semantic-error transition-colors"
                        title="Delete key"
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
        title="Revoke API Key"
        message="This will immediately invalidate the key. Any service using this key will lose access."
        confirmLabel="Revoke"
        variant="danger"
        onConfirm={handleRevoke}
        onCancel={() => setRevokeId(null)}
      />

      <ConfirmDialog
        open={!!deleteId}
        title="Delete API Key"
        message="This will permanently delete the key. This action cannot be undone."
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
    </div>
  )
}
