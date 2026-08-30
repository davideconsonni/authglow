import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { RefreshCw, Ban, Loader2, Key, ExternalLink } from 'lucide-react'
import { api } from '../../lib/api'
import { API_URL } from '../../lib/constants'
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
  retired_at?: string | null
  revoked_at?: string | null
}

interface JwksStatus {
  active_kid: string
  keys: JwkKey[]
}

export function AdminJwkKeysPage() {
  useDocumentTitle('JWK Keys')
  const queryClient = useQueryClient()
  const [revokeKid, setRevokeKid] = useState<string | null>(null)
  const [rotating, setRotating] = useState(false)

  const { data, isLoading } = useApiQuery<JwkKey[] | { items?: JwkKey[]; keys?: JwkKey[] }>(
    ['admin-jwk-keys'],
    '/api/admin/jwk-keys',
  )
  const keys: JwkKey[] = Array.isArray(data) ? data : (data?.items || data?.keys || [])

  // Public JWKS status (same data clients see via /.well-known/jwks.json).
  const { data: jwksStatus } = useApiQuery<JwksStatus>(
    ['jwks-status'],
    '/oauth2/jwks/status',
  )
  const totalKeys = jwksStatus?.keys.length ?? 0
  // /.well-known/jwks.json publishes active + verifying keys only —
  // revoked ones disappear from the public set.
  const publishedKeys = jwksStatus?.keys.filter(k => k.status !== 'revoked').length ?? 0

  // Both views must refresh together after a mutation — the status
  // endpoint has its own query key and a 5-minute global staleTime,
  // so refetching only the admin list would leave the card frozen.
  const refreshAll = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ['admin-jwk-keys'] }),
      queryClient.invalidateQueries({ queryKey: ['jwks-status'] }),
    ])

  const handleRotate = async () => {
    setRotating(true)
    try {
      await api.post('/api/admin/jwk-keys/rotate')
      notify.success('Keys rotated.')
      await refreshAll()
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
      await refreshAll()
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
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] disabled:opacity-50"
          >
            {rotating && <Loader2 size={16} className="animate-spin" />}
            <RefreshCw size={16} />
            Rotate
          </button>
        }
      />

      {/* ----- Status lifecycle legend ----- */}
      <div
        data-testid="jwks-status-legend"
        className="mb-4 flex flex-wrap gap-x-5 gap-y-1 text-[11px] text-text-muted"
      >
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full bg-semantic-success" />
          <strong className="font-semibold text-text-secondary">Active</strong> signs new
          tokens
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full bg-semantic-warning" />
          <strong className="font-semibold text-text-secondary">Verifying</strong> only
          validates tokens issued before a rotation
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full bg-surface-3" />
          <strong className="font-semibold text-text-secondary">Revoked</strong> removed
          from the client-facing JWKS
        </span>
      </div>

      {jwksStatus && (
        <div
          data-testid="jwks-public-card"
          className="mb-6 flex flex-wrap items-center gap-x-6 gap-y-3 rounded-2xl border border-surface-2 bg-surface-1 px-5 py-4"
        >
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">
              Public JWKS
            </p>
            <p className="mt-1 text-sm text-text-secondary">
              Active key:{' '}
              <code data-testid="jwks-active-kid" className="text-xs font-semibold text-text-primary">
                {jwksStatus.active_kid}
              </code>
            </p>
          </div>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">
              Visible to clients
            </p>
            <p data-testid="jwks-published-count" className="mt-1 text-sm text-text-secondary">
              {publishedKeys} of {totalKeys} keys published
              {totalKeys - publishedKeys > 0 && (
                <span className="ml-1 text-text-muted">(revoked keys are excluded)</span>
              )}
            </p>
          </div>
          <a
            data-testid="jwks-public-link"
            href={`${API_URL}/.well-known/jwks.json`}
            target="_blank"
            rel="noreferrer"
            className="ml-auto flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-xs font-medium text-brand-accent transition-colors hover:bg-brand-wash-faint hover:text-brand-cool"
          >
            View /.well-known/jwks.json <ExternalLink size={12} />
          </a>
        </div>
      )}

      {isLoading ? (
        <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-accent" /></div>
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
                <th className="hidden lg:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Retired / Revoked</th>
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
                  <td className="hidden lg:table-cell px-6 py-3 text-sm text-text-muted">
                    {k.revoked_at
                      ? formatDateTime(k.revoked_at)
                      : k.retired_at
                        ? formatDateTime(k.retired_at)
                        : '—'}
                  </td>
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
