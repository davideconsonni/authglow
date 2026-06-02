import { useState } from 'react'
import { Plus, Trash2, Copy, Check, Key, Loader2, Ban, RotateCcw } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'

interface ApiKeyData {
  key_id: string
  name: string
  scopes: string[]
  key_prefix: string
  is_active: boolean
  expires_at: string | null
  last_used_at: string | null
  created_at: string
}

export function ApiKeysPage() {
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState('')
  const [newScopes, setNewScopes] = useState('read')
  const [newExpires, setNewExpires] = useState('')
  const [newKey, setNewKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [restoreId, setRestoreId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [creating, setCreating] = useState(false)

  const { data: keys, refetch } = useApiQuery<ApiKeyData[]>(['my-keys'], '/api/keys')

  const handleCreate = async () => {
    setError('')
    setCreating(true)
    try {
      const data = await api.post<{ key_id: string; api_key: string; key_prefix: string }>('/api/keys', {
        name: newName || 'My Key',
        scopes: newScopes.split(',').map((s: string) => s.trim()).filter(Boolean),
        expires_in_days: newExpires ? parseInt(newExpires) : null,
      })
      setNewKey(data.api_key)
      setNewName('')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create key')
    } finally {
      setCreating(false)
    }
  }

  const handleCopy = () => {
    if (!newKey) return
    navigator.clipboard.writeText(newKey)
    setCopied(true)
    setTimeout(() => setCopied(false), 3000)
  }

  const handleRevoke = async () => {
    if (!revokeId) return
    try {
      await api.post(`/api/keys/${revokeId}/revoke`)
      setRevokeId(null)
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to deactivate key')
    }
  }

  const handleRestore = async () => {
    if (!restoreId) return
    try {
      await api.patch(`/api/keys/${restoreId}`, { is_active: true })
      setRestoreId(null)
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to restore key')
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.delete(`/api/keys/${deleteId}`)
      setDeleteId(null)
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete key')
    }
  }

  const closeCreate = () => {
    setShowCreate(false)
    setNewKey(null)
    setNewName('')
    setNewScopes('read')
    setNewExpires('')
    setError('')
  }

  return (
    <div>
      <PageHeader
        title="API Keys"
        description="Manage API keys for programmatic access."
        actions={
          <button
            onClick={() => setShowCreate(true)}
            data-testid="create-api-key-btn"
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Plus size={16} />
            Create Key
          </button>
        }
      />

      {error && <div className="mb-4 rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">{error}</div>}

      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={closeCreate} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet">
            {newKey ? (
              <div className="space-y-4 text-center" data-testid="key-created-display">
                <h3 className="text-lg font-semibold text-text-primary">API Key Created</h3>
                <p className="text-xs text-semantic-warning">Copy this key now. It will not be shown again.</p>
                <div className="flex items-center gap-2 rounded-xl bg-surface-2 p-3">
                  <code className="flex-1 break-all text-xs text-text-secondary">{newKey}</code>
                  <button onClick={handleCopy} className="text-text-muted hover:text-text-secondary">
                    {copied ? <Check size={16} className="text-semantic-success" /> : <Copy size={16} />}
                  </button>
                </div>
                <button onClick={closeCreate} data-testid="key-created-done" className="rounded-xl bg-gradient-cta px-6 py-2 text-sm font-semibold text-white">
                  Done
                </button>
              </div>
            ) : (
              <div className="space-y-4" data-testid="create-key-modal">
                <h3 className="text-lg font-semibold text-text-primary">Create API Key</h3>
                <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Key name" data-testid="key-name-input" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                <input value={newScopes} onChange={(e) => setNewScopes(e.target.value)} placeholder="Scopes (comma-separated)" data-testid="key-scopes-input" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                <input type="number" value={newExpires} onChange={(e) => setNewExpires(e.target.value)} placeholder="Expires in days (optional)" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                <div className="flex gap-3">
                  <button onClick={closeCreate} className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2 transition-colors">Cancel</button>
                  <button onClick={handleCreate} disabled={creating} data-testid="key-create-submit" className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white disabled:opacity-50">
                    {creating ? <Loader2 size={16} className="animate-spin" /> : null}
                    Create
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {keys && keys.length > 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-surface-2">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Prefix</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Scopes</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Expires</th>
                  <th className="px-6 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-2">
                {keys.map((k, i) => (
                  <tr key={k.key_id || i} className={`hover:bg-surface-2/50 ${!k.is_active ? 'opacity-50' : ''}`} data-testid="api-key-row">
                    <td className="px-6 py-3 text-sm font-medium text-text-primary">{k.name}</td>
                    <td className="px-6 py-3">
                      <code className="text-xs font-mono text-text-secondary">{k.key_prefix || '-'}</code>
                    </td>
                    <td className="px-6 py-3">
                      <div className="flex flex-wrap gap-1">
                        {k.scopes.map((s) => (
                          <span key={s} className="rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary">{s}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-3">
                      <span className={`rounded-lg px-2 py-0.5 text-xs font-medium ${k.is_active ? 'bg-semantic-success/10 text-semantic-success' : 'bg-semantic-warning/10 text-semantic-warning'}`}>
                        {k.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-sm text-text-muted">
                      {k.expires_at ? formatDateTime(k.expires_at) : 'Never'}
                    </td>
                    <td className="px-6 py-3">
                      <div className="flex gap-2">
                        {k.is_active ? (
                          <button onClick={() => setRevokeId(k.key_id)} data-testid="revoke-key-btn" className="text-text-muted hover:text-semantic-warning transition-colors" aria-label="Deactivate key" title="Deactivate">
                            <Ban size={14} />
                          </button>
                        ) : (
                          <button onClick={() => setRestoreId(k.key_id)} className="text-text-muted hover:text-semantic-success transition-colors" aria-label="Restore key" title="Restore">
                            <RotateCcw size={14} />
                          </button>
                        )}
                        <button onClick={() => setDeleteId(k.key_id)} className="text-text-muted hover:text-semantic-error transition-colors" aria-label="Delete key">
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-12 text-center">
          <Key className="mx-auto h-8 w-8 text-text-muted" />
          <h3 className="mt-3 text-sm font-semibold text-text-primary">No API keys</h3>
          <p className="mt-1 text-xs text-text-muted">Create your first API key for programmatic access.</p>
        </div>
      )}

      <ConfirmDialog open={!!revokeId} title="Deactivate API Key" message="The key will stop working immediately but you can reactivate it later." confirmLabel="Deactivate" variant="danger" onConfirm={handleRevoke} onCancel={() => setRevokeId(null)} />
      <ConfirmDialog open={!!restoreId} title="Reactivate API Key" message="This will make the key active again." confirmLabel="Reactivate" variant="danger" onConfirm={handleRestore} onCancel={() => setRestoreId(null)} />
      <ConfirmDialog open={!!deleteId} title="Delete API Key" message="This permanently removes the key. Use Deactivate if you might need it later." confirmLabel="Delete" variant="danger" onConfirm={handleDelete} onCancel={() => setDeleteId(null)} />
    </div>
  )
}
