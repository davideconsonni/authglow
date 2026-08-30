import { useState } from 'react'
import { Plus, Trash2, Copy, Check, Key, Loader2, Ban, RotateCcw, AlertTriangle, Pencil, X } from 'lucide-react'
import { api } from '../lib/api'
import { useApiQuery } from '../hooks/useApi'
import { ConfirmDialog } from '../components/shared/ConfirmDialog'
import { PageHeader } from '../components/layout/PageHeader'
import { ScopePicker } from '../components/shared/ScopePicker'
import { formatDateTime } from '../lib/utils'
import { parseScopeInput } from '../lib/scopes'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { notify } from '../stores/toastStore'

interface ApiKeyData {
  key_id: string
  name: string
  description: string | null
  scopes: string[]
  key_prefix: string
  is_active: boolean
  expires_at: string | null
  never_expires?: boolean
  last_used_at: string | null
  created_at: string
  allowed_ips: string[]
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

interface EditForm {
  name: string
  description: string
  scopes: string
  allowed_ips: string
  expires_in_days: string
}

export function ApiKeysPage() {
  useDocumentTitle('API Keys')
  const [showCreate, setShowCreate] = useState(false)
  const [newName, setNewName] = useState('')
  const [newDescription, setNewDescription] = useState('')
  const [newScopes, setNewScopes] = useState('read')
  const [newExpires, setNewExpires] = useState('')
  const [newAllowedIps, setNewAllowedIps] = useState('')
  const [newKey, setNewKey] = useState<string | null>(null)
  const [createdKeyInfo, setCreatedKeyInfo] = useState<CreatedKey | null>(null)
  const [copied, setCopied] = useState(false)
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [restoreId, setRestoreId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editForm, setEditForm] = useState<EditForm>({ name: '', description: '', scopes: '', allowed_ips: '', expires_in_days: '' })
  const [editNeverExpires, setEditNeverExpires] = useState(false)
  const [savingEdit, setSavingEdit] = useState(false)

  const { data: keys, refetch } = useApiQuery<ApiKeyData[]>(['my-keys'], '/api/keys')

  const atRiskKeys = (keys ?? []).filter((k) => {
    if (!k.is_active) return false
    const noExpiry = !k.expires_at
    const unused90d = k.last_used_at && (Date.now() - new Date(k.last_used_at).getTime()) > 90 * 24 * 60 * 60 * 1000
    return noExpiry || unused90d
  })

  const handleCreate = async () => {
    setCreating(true)
    try {
      const { tokens: scopes, invalid } = parseScopeInput(newScopes)
      if (invalid.length > 0) {
        notify.error(`Invalid scope token(s): ${invalid.join(', ')} — scopes are space-separated (RFC 6749).`)
        return
      }
      const data = await api.post<CreatedKey>('/api/keys', {
        name: newName || 'My Key',
        description: newDescription.trim() || null,
        scopes,
        expires_in_days: newExpires ? parseInt(newExpires) : null,
        allowed_ips: newAllowedIps
          .split(',')
          .map((s: string) => s.trim())
          .filter(Boolean),
      })
      setNewKey(data.api_key)
      setCreatedKeyInfo(data)
      setNewName('')
      setNewDescription('')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to create key')
    } finally {
      setCreating(false)
    }
  }

  const openEdit = (k: ApiKeyData) => {
    setEditingId(k.key_id)
    setEditForm({
      name: k.name,
      description: k.description || '',
      scopes: k.scopes.join(' '),
      allowed_ips: (k.allowed_ips || []).join(', '),
      expires_in_days: '',
    })
    setEditNeverExpires(!!k.never_expires || k.expires_at === null)
  }

  const closeEdit = () => {
    setEditingId(null)
    setEditForm({ name: '', description: '', scopes: '', allowed_ips: '', expires_in_days: '' })
    setEditNeverExpires(false)
  }

  const handleSaveEdit = async () => {
    if (!editingId) return
    const { tokens: scopes, invalid } = parseScopeInput(editForm.scopes)
    if (invalid.length > 0) {
      notify.error(`Invalid scope token(s): ${invalid.join(', ')} — scopes are space-separated (RFC 6749).`)
      return
    }
    setSavingEdit(true)
    try {
      await api.patch(`/api/keys/${editingId}`, {
        name: editForm.name,
        description: editForm.description.trim() || null,
        scopes,
        allowed_ips: editForm.allowed_ips
          .split(',')
          .map((s: string) => s.trim())
          .filter(Boolean),
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
      notify.success('Key deactivated.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to deactivate key')
    }
  }

  const handleRestore = async () => {
    if (!restoreId) return
    try {
      await api.patch(`/api/keys/${restoreId}`, { is_active: true })
      setRestoreId(null)
      notify.success('Key restored.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to restore key')
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.delete(`/api/keys/${deleteId}`)
      setDeleteId(null)
      notify.success('Key deleted.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to delete key')
    }
  }

  const closeCreate = () => {
    setShowCreate(false)
    setNewKey(null)
    setCreatedKeyInfo(null)
    setNewName('')
    setNewDescription('')
    setNewScopes('read')
    setNewExpires('')
    setNewAllowedIps('')
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
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Plus size={16} />
            Create Key
          </button>
        }
      />

      {atRiskKeys.length > 0 && (
        <div className="mb-4 flex items-start gap-3 rounded-xl border border-semantic-warning/20 bg-semantic-warning/5 px-4 py-3">
          <AlertTriangle size={16} className="shrink-0 text-semantic-warning mt-0.5" />
          <div>
            <p className="text-sm font-medium text-text-primary">
              {atRiskKeys.length} key{atRiskKeys.length !== 1 ? 's' : ''} may need attention
            </p>
            <p className="text-xs text-text-muted mt-0.5">
              {atRiskKeys.filter(k => !k.expires_at).length > 0 && 'Keys without expiration are a security risk. '}
              {atRiskKeys.filter(k => k.last_used_at && (Date.now() - new Date(k.last_used_at).getTime()) > 90 * 24 * 60 * 60 * 1000).length > 0 && 'Some keys have not been used in over 90 days.'}
            </p>
          </div>
        </div>
      )}

      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={closeCreate} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-accent">
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
                {createdKeyInfo && createdKeyInfo.filtered_scopes.length > 0 && (
                  <div
                    role="alert"
                    data-testid="scope-filter-warning"
                    className="rounded-xl border border-semantic-warning/30 bg-semantic-warning/10 p-3 text-left"
                  >
                    <p className="text-xs font-medium text-semantic-warning">Some scopes were filtered</p>
                    <p className="mt-1 text-xs text-text-secondary">
                      Requested: <code className="font-mono">{createdKeyInfo.requested_scopes.join(', ') || '(none)'}</code>
                    </p>
                    <p className="text-xs text-text-secondary">
                      Granted: <code className="font-mono">{createdKeyInfo.granted_scopes.join(', ') || '(none)'}</code>
                    </p>
                    <p className="text-xs text-text-secondary">
                      Filtered: <code className="font-mono">{createdKeyInfo.filtered_scopes.join(', ')}</code>
                    </p>
                    <p className="mt-1 text-[11px] text-text-muted">
                      These scopes were not granted because they are not available on your account.
                    </p>
                  </div>
                )}
                <button onClick={closeCreate} data-testid="key-created-done" className="rounded-xl bg-gradient-cta px-6 py-2 text-sm font-semibold text-white">
                  Done
                </button>
              </div>
            ) : (
              <div className="space-y-4" data-testid="create-key-modal">
                <h3 className="text-lg font-semibold text-text-primary">Create API Key</h3>
                <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Key name" data-testid="key-name-input" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                <textarea
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="Description (optional) — e.g. Production server backup automation, rotated 2026-Q3"
                  rows={2}
                  data-testid="key-description-input"
                  className="w-full resize-y rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20"
                />
                <div>
                  <label className="mb-1 block text-xs font-medium text-text-muted">Scopes</label>
                  <ScopePicker
                    value={newScopes}
                    onChange={setNewScopes}
                    placeholder="Add custom scope"
                    testId="key-scopes"
                  />
                </div>
                <input type="number" value={newExpires} onChange={(e) => setNewExpires(e.target.value)} placeholder="Expires in days (optional)" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
                <input
                  value={newAllowedIps}
                  onChange={(e) => setNewAllowedIps(e.target.value)}
                  placeholder="Restrict to IPs or CIDR ranges (comma-separated, optional)"
                  data-testid="key-allowed-ips-input"
                  className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
                />
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
        <>
          {/* Desktop table */}
          <div className="hidden md:block rounded-2xl border border-surface-2 bg-surface-1">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-surface-2">
                  <tr>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Name</th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Prefix</th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Scopes</th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">IP Restriction</th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Last Used</th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Status</th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Expires</th>
                    <th className="px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-2">
                  {keys.map((k, i) => (
                    <tr key={k.key_id || i} className={`hover:bg-surface-2/50 ${!k.is_active ? 'opacity-50' : ''}`} data-testid="api-key-row">
                      <td className="px-4 py-2.5 text-sm font-medium text-text-primary">
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
                      <td className="px-4 py-2.5">
                        <code className="text-xs font-mono text-text-secondary">{k.key_prefix || '-'}</code>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex flex-wrap gap-1">
                          {k.scopes.map((s) => (
                            <span key={s} className="rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary">{s}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-2.5" data-testid="key-ips-display">
                        {k.allowed_ips && k.allowed_ips.length > 0 ? (
                          <span
                            className="rounded-lg bg-brand-wash px-2 py-0.5 text-xs text-brand-accent"
                            title={k.allowed_ips.join(', ')}
                          >
                            {k.allowed_ips[0]}{k.allowed_ips.length > 1 ? ` +${k.allowed_ips.length - 1}` : ''}
                          </span>
                        ) : (
                          <span className="text-xs text-text-muted">—</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-sm text-text-muted">
                        {k.last_used_at ? formatDateTime(k.last_used_at) : 'Never'}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={`rounded-lg px-2 py-0.5 text-xs font-medium ${k.is_active ? 'bg-semantic-success/10 text-semantic-success' : 'bg-semantic-warning/10 text-semantic-warning'}`}>
                          {k.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-sm text-text-muted">
                        {k.expires_at ? formatDateTime(k.expires_at) : 'Never'}
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex gap-2">
                          <button
                            onClick={() => openEdit(k)}
                            data-testid="key-edit-btn"
                            className="text-text-muted hover:text-brand-accent transition-colors"
                            aria-label="Edit key"
                            title="Edit"
                          >
                            <Pencil size={14} />
                          </button>
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

          {/* Mobile cards */}
          <div className="md:hidden space-y-3">
            {keys.map((k, i) => (
              <div key={k.key_id || i} className={`rounded-2xl border border-surface-2 bg-surface-1 p-4 space-y-3 ${!k.is_active ? 'opacity-50' : ''}`} data-testid="api-key-row">
                <div className="flex items-start justify-between">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-text-primary truncate">{k.name}</p>
                      <span className={`shrink-0 rounded-lg px-2 py-0.5 text-[10px] font-medium ${k.is_active ? 'bg-semantic-success/10 text-semantic-success' : 'bg-semantic-warning/10 text-semantic-warning'}`}>
                        {k.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </div>
                    {k.description && (
                      <p className="mt-0.5 truncate text-xs text-text-muted" title={k.description} data-testid="key-description-display">
                        {k.description}
                      </p>
                    )}
                    <code className="mt-1 inline-block text-[10px] font-mono text-text-muted">{k.key_prefix || '-'}</code>
                  </div>
                  <div className="shrink-0 flex gap-1">
                    <button
                      onClick={() => openEdit(k)}
                      data-testid="key-edit-btn"
                      className="rounded-lg p-1.5 text-text-muted hover:text-brand-accent hover:bg-brand-wash-faint transition-colors"
                      aria-label="Edit key"
                    >
                      <Pencil size={14} />
                    </button>
                    {k.is_active ? (
                      <button onClick={() => setRevokeId(k.key_id)} data-testid="revoke-key-btn" className="rounded-lg p-1.5 text-text-muted hover:text-semantic-warning hover:bg-semantic-warning/10 transition-colors" aria-label="Deactivate key">
                        <Ban size={14} />
                      </button>
                    ) : (
                      <button onClick={() => setRestoreId(k.key_id)} className="rounded-lg p-1.5 text-text-muted hover:text-semantic-success hover:bg-semantic-success/10 transition-colors" aria-label="Restore key">
                        <RotateCcw size={14} />
                      </button>
                    )}
                    <button onClick={() => setDeleteId(k.key_id)} className="rounded-lg p-1.5 text-text-muted hover:text-semantic-error hover:bg-semantic-error/10 transition-colors" aria-label="Delete key">
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {k.scopes.map((s) => (
                    <span key={s} className="rounded-lg bg-surface-2 px-2 py-0.5 text-[10px] text-text-secondary">{s}</span>
                  ))}
                </div>
                <div className="flex items-center gap-4 text-[11px] text-text-muted">
                  {k.allowed_ips && k.allowed_ips.length > 0 && (
                    <span className="text-brand-accent" title={k.allowed_ips.join(', ')}>
                      {k.allowed_ips[0]}{k.allowed_ips.length > 1 ? ` +${k.allowed_ips.length - 1}` : ''}
                    </span>
                  )}
                  <span>Last: {k.last_used_at ? formatDateTime(k.last_used_at) : 'Never'}</span>
                  <span>Exp: {k.expires_at ? formatDateTime(k.expires_at) : 'Never'}</span>
                </div>
              </div>
            ))}
          </div>
        </>
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

      {editingId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={closeEdit} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-accent" data-testid="key-edit-modal">
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
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
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
                className="w-full resize-y rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Scopes</label>
              <ScopePicker
                value={editForm.scopes}
                onChange={(value) => setEditForm({ ...editForm, scopes: value })}
                placeholder="Add custom scope"
                testId="key-edit-scopes"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Allowed IPs (comma-separated, IP or CIDR)</label>
              <input
                value={editForm.allowed_ips}
                onChange={(e) => setEditForm({ ...editForm, allowed_ips: e.target.value })}
                placeholder="203.0.113.5, 198.51.100.0/24"
                data-testid="key-edit-allowed-ips-input"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
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
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none disabled:opacity-50"
              />
              <label className="mt-1.5 flex cursor-pointer items-center gap-2 text-xs text-text-secondary">
                <input
                  type="checkbox"
                  checked={editNeverExpires}
                  onChange={(e) => setEditNeverExpires(e.target.checked)}
                  data-testid="key-edit-never-expires-toggle"
                  className="accent-brand-accent"
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
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
              >
                {savingEdit ? <Loader2 size={16} className="animate-spin" /> : null}
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
