import { useState } from 'react'
import { Ban, Loader2, CheckCircle } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'

interface ConsentData {
  id: string
  user_email: string
  client_name: string
  scopes: string[]
  created_at: string
  is_revoked: boolean
}

export function AdminConsentsPage() {
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [error, setError] = useState('')

  const { data, refetch, isLoading } = useApiQuery<any>(
    ['admin-consents'],
    '/api/admin/oauth-consents',
  )
  const consents: ConsentData[] = Array.isArray(data) ? data : (data?.items || data?.consents || [])

  const handleRevoke = async () => {
    if (!revokeId) return
    try {
      await api.post(`/api/admin/oauth-consents/${revokeId}/revoke`)
      setRevokeId(null)
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to revoke consent')
    }
  }

  return (
    <div>
      <PageHeader title="OAuth Consents" description="Manage user consent grants for OAuth2 clients." />

      {error && <div className="mb-4 rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">{error}</div>}

      {isLoading ? (
        <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div>
      ) : !consents || consents.length === 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-12 text-center">
          <CheckCircle className="mx-auto h-8 w-8 text-text-muted" />
          <h3 className="mt-3 text-sm font-semibold text-text-primary">No consents</h3>
          <p className="mt-1 text-xs text-text-muted">OAuth consent grants will appear here.</p>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">User</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Client</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Scopes</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                <th className="px-6 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {consents.map((c) => (
                <tr key={c.id} className={`hover:bg-surface-2/50 ${c.is_revoked ? 'opacity-50' : ''}`}>
                  <td className="px-6 py-3 text-sm text-text-primary">{c.user_email}</td>
                  <td className="px-6 py-3 text-sm text-text-secondary">{c.client_name}</td>
                  <td className="px-6 py-3">
                    <div className="flex flex-wrap gap-1">
                      {c.scopes?.map((s) => (
                        <span key={s} className="rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary">{s}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-3 text-sm text-text-muted">{formatDateTime(c.created_at)}</td>
                  <td className="px-6 py-3">
                    {!c.is_revoked && (
                      <button
                        onClick={() => setRevokeId(c.id)}
                        className="text-text-muted hover:text-semantic-error transition-colors"
                        title="Revoke consent"
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
        open={!!revokeId}
        title="Revoke Consent"
        message="This will revoke the user's consent. They will need to re-authorize the client on next login."
        confirmLabel="Revoke"
        variant="danger"
        onConfirm={handleRevoke}
        onCancel={() => setRevokeId(null)}
      />
    </div>
  )
}
