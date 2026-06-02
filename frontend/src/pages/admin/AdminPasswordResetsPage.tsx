import { useState } from 'react'
import { Loader2, Ban, KeyRound } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'

interface PasswordReset {
  id: string
  user_email: string
  status: string
  created_at: string
  expires_at: string
}

interface ResetStats {
  total: number
  pending: number
  completed: number
}

export function AdminPasswordResetsPage() {
  const [revokeUserId, setRevokeUserId] = useState<string | null>(null)
  const [cleaning, setCleaning] = useState(false)
  const [error, setError] = useState('')

  const { data: resets, refetch, isLoading } = useApiQuery<PasswordReset[]>(
    ['admin-password-resets'],
    '/api/admin/password-resets',
  )

  const { data: stats } = useApiQuery<ResetStats>(
    ['admin-password-resets-stats'],
    '/api/admin/password-resets/stats',
  )

  const handleRevokeUser = async () => {
    if (!revokeUserId) return
    try {
      await api.post(`/api/admin/users/${revokeUserId}/revoke-resets`)
      setRevokeUserId(null)
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to revoke resets')
    }
  }

  const handleCleanup = async () => {
    setCleaning(true)
    try {
      await api.post('/api/admin/password-resets/cleanup')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to cleanup')
    } finally {
      setCleaning(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="Password Resets"
        description="Manage password reset tokens."
        actions={
          <button
            onClick={handleCleanup}
            disabled={cleaning}
            className="flex items-center gap-2 rounded-xl border border-semantic-error/30 px-4 py-2 text-xs font-medium text-semantic-error hover:bg-semantic-error/10 transition-colors disabled:opacity-50"
          >
            {cleaning && <Loader2 size={14} className="animate-spin" />}
            Cleanup
          </button>
        }
      />

      {error && <div className="mb-4 rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">{error}</div>}

      {stats && (
        <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
          {[
            { label: 'Total', value: stats.total },
            { label: 'Pending', value: stats.pending },
            { label: 'Completed', value: stats.completed },
          ].map((s) => (
            <div key={s.label} className="rounded-2xl border border-surface-2 bg-surface-1 p-4">
              <p className="text-xs text-text-muted">{s.label}</p>
              <p className="mt-1 text-xl font-bold text-text-primary">{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {isLoading ? (
        <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div>
      ) : !resets || resets.length === 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-12 text-center">
          <KeyRound className="mx-auto h-8 w-8 text-text-muted" />
          <h3 className="mt-3 text-sm font-semibold text-text-primary">No password resets</h3>
          <p className="mt-1 text-xs text-text-muted">Password reset requests will appear here.</p>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">User</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Expires</th>
                <th className="px-6 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {resets.map((r) => (
                <tr key={r.id} className="hover:bg-surface-2/50">
                  <td className="px-6 py-3 text-sm text-text-primary">{r.user_email}</td>
                  <td className="px-6 py-3">
                    <span className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${
                      r.status === 'pending' ? 'bg-semantic-warning/10 text-semantic-warning' :
                      r.status === 'completed' ? 'bg-semantic-success/10 text-semantic-success' :
                      'bg-surface-2 text-text-muted'
                    }`}>
                      {r.status}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-sm text-text-muted">{formatDateTime(r.created_at)}</td>
                  <td className="px-6 py-3 text-sm text-text-muted">{formatDateTime(r.expires_at)}</td>
                  <td className="px-6 py-3">
                    {r.status === 'pending' && (
                      <button
                        onClick={() => setRevokeUserId(r.id)}
                        className="text-text-muted hover:text-semantic-error transition-colors"
                        title="Revoke reset"
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
        open={!!revokeUserId}
        title="Revoke Password Reset"
        message="This will invalidate the reset token for this request."
        confirmLabel="Revoke"
        variant="danger"
        onConfirm={handleRevokeUser}
        onCancel={() => setRevokeUserId(null)}
      />
    </div>
  )
}
