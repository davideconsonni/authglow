import { useState } from 'react'
import { RefreshCw, Ban, Loader2, Key } from 'lucide-react'
import { api } from '../../lib/api'
import { useApiQuery } from '../../hooks/useApi'
import { ConfirmDialog } from '../../components/shared/ConfirmDialog'
import { PageHeader } from '../../components/layout/PageHeader'
import { formatDateTime } from '../../lib/utils'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { notify } from '../../stores/toastStore'

interface JwkKey {
  kid: string
  status: 'active' | 'verifying' | 'revoked'
  algorithm: string
  key_size: number
  created_at: string
}

export function AdminJwkKeysPage() {
  useDocumentTitle('JWK Keys')
  const [revokeKid, setRevokeKid] = useState<string | null>(null)
  const [rotating, setRotating] = useState(false)

  const { data, refetch, isLoading } = useApiQuery<JwkKey[] | { items?: JwkKey[]; keys?: JwkKey[] }>(
    ['admin-jwk-keys'],
    '/api/admin/jwk-keys',
  )
  const keys: JwkKey[] = Array.isArray(data) ? data : (data?.items || data?.keys || [])

  const handleRotate = async () => {
    setRotating(true)
    try {
      await api.post('/api/admin/jwk-keys/rotate')
      notify.success('Keys rotated.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to rotate keys')
    } finally {
      setRotating(false)
    }
  }

  const handleRevoke = async () => {
    if (!revokeKid) return
    try {
      await api.post(`/api/admin/jwk-keys/${revokeKid}/revoke`)
      setRevokeKid(null)
      notify.success('Key revoked.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to revoke key')
    }
  }

  return (
    <div>
      <PageHeader
        title="JWK Keys"
        description="Manage signing keys for JWT tokens."
        actions={
          <button
            onClick={handleRotate}
            disabled={rotating}
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50"
          >
            {rotating && <Loader2 size={16} className="animate-spin" />}
            <RefreshCw size={16} />
            Rotate
          </button>
        }
      />

      {isLoading ? (
        <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div>
      ) : !keys || keys.length === 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-12 text-center">
          <Key className="mx-auto h-8 w-8 text-text-muted" />
          <h3 className="mt-3 text-sm font-semibold text-text-primary">No JWK keys</h3>
          <p className="mt-1 text-xs text-text-muted">JWK signing keys will appear here.</p>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Key ID</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Status</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Algorithm</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Key Size</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                <th className="px-6 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {keys.map((k) => (
                <tr key={k.kid} className={`hover:bg-surface-2/50 ${k.status === 'revoked' ? 'opacity-50' : ''}`}>
                  <td className="px-6 py-3"><code className="text-xs text-text-secondary">{k.kid}</code></td>
                  <td className="px-6 py-3">
                    <span className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${
                      k.status === 'active' ? 'bg-semantic-success/10 text-semantic-success' :
                      k.status === 'verifying' ? 'bg-semantic-warning/10 text-semantic-warning' :
                      'bg-surface-2 text-text-muted'
                    }`}>
                      {k.status}
                    </span>
                  </td>
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-secondary">{k.algorithm}</td>
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">{k.key_size} bit</td>
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">{formatDateTime(k.created_at)}</td>
                  <td className="px-6 py-3">
                    {k.status !== 'revoked' && k.status !== 'active' && (
                      <button
                        onClick={() => setRevokeKid(k.kid)}
                        className="text-text-muted hover:text-semantic-error transition-colors"
                        title="Revoke key"
                      >
                        <Ban size={14} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={!!revokeKid}
        title="Revoke JWK Key"
        message="This will revoke the signing key. Tokens signed with this key will no longer validate unless another verifying key exists."
        confirmLabel="Revoke"
        variant="danger"
        onConfirm={handleRevoke}
        onCancel={() => setRevokeKid(null)}
      />
    </div>
  )
}
