import { useState } from 'react'
import { Trash2, Loader2, Monitor } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

interface SessionData {
  id: string
  user_email: string
  client: string
  ip_address: string
  scopes: string[]
  created_at: string
}

export function AdminSessionsPage() {
  useDocumentTitle('Admin Sessions')
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [cleaning, setCleaning] = useState(false)
  const [error, setError] = useState('')

  const { data, refetch, isLoading } = useApiQuery<any>(
    ['admin-sessions'],
    '/api/admin/sessions',
  )
  const sessions: SessionData[] = Array.isArray(data) ? data : (data?.items || data?.sessions || data?.tokens || [])

  const handleRevoke = async () => {
    if (!revokeId) return
    try {
      await api.post(`/api/admin/tokens/refresh/${revokeId}/revoke`)
      setRevokeId(null)
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to revoke session')
    }
  }

  const handleCleanup = async () => {
    setCleaning(true)
    try {
      await api.post('/api/admin/sessions/cleanup')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to cleanup sessions')
    } finally {
      setCleaning(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="Sessions"
        description="Manage all active user sessions."
        actions={
          <button
            onClick={handleCleanup}
            disabled={cleaning}
            className="flex items-center gap-2 rounded-xl border border-semantic-error/30 px-4 py-2 text-xs font-medium text-semantic-error hover:bg-semantic-error/10 transition-colors disabled:opacity-50"
          >
            {cleaning && <Loader2 size={14} className="animate-spin" />}
            Cleanup All
          </button>
        }
      />

      {error && <div className="mb-4 rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">{error}</div>}

      {isLoading ? (
        <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div>
      ) : !sessions || sessions.length === 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-12 text-center">
          <Monitor className="mx-auto h-8 w-8 text-text-muted" />
          <h3 className="mt-3 text-sm font-semibold text-text-primary">No active sessions</h3>
          <p className="mt-1 text-xs text-text-muted">All user sessions will appear here.</p>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">User</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Client</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">IP</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                <th className="px-6 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {sessions.map((s) => (
                <tr key={s.id} className="hover:bg-surface-2/50">
                  <td className="px-6 py-3 text-sm text-text-primary">{s.user_email}</td>
                  <td className="px-6 py-3 text-sm text-text-secondary">{s.client}</td>
                  <td className="hidden md:table-cell px-6 py-3">
                    <code className="text-xs text-text-muted">{s.ip_address}</code>
                  </td>
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">{formatDateTime(s.created_at)}</td>
                  <td className="px-6 py-3">
                    <button
                      onClick={() => setRevokeId(s.id)}
                      className="text-text-muted hover:text-semantic-error transition-colors"
                      title="Revoke session"
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={!!revokeId}
        title="Revoke Session"
        message="This will immediately terminate the session and invalidate all associated tokens."
        confirmLabel="Revoke"
        variant="danger"
        onConfirm={handleRevoke}
        onCancel={() => setRevokeId(null)}
      />
    </div>
  )
}
