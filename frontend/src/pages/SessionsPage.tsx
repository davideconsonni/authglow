import { useState } from 'react'
import { Monitor, Globe, Loader2 } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'

interface Session {
  id: string
  client: string
  ip_address: string
  created_at: string
  last_active: string
}

export function SessionsPage() {
  const [revokingAll, setRevokingAll] = useState(false)
  const [error, setError] = useState('')

  const { data: rawData, refetch, isLoading } = useApiQuery<any>(
    ['my-sessions'],
    '/api/tokens/refresh/list',
  )

  const sessions: Session[] = Array.isArray(rawData) ? rawData : (rawData?.sessions || rawData?.items || rawData?.tokens || [])

  const handleRevokeAll = async () => {
    setRevokingAll(true)
    setError('')
    try {
      const res = await api.post<{ message?: string; count?: number }>('/api/tokens/refresh/revoke-all')
      const count = res?.count || 0
      setError('')
      alert(count > 0 ? `Revoked ${count} session(s).` : 'All sessions revoked.')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to revoke sessions')
    } finally {
      setRevokingAll(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="Sessions"
        description="Manage your active OAuth2 refresh tokens."
        actions={
          <button
            onClick={handleRevokeAll}
            disabled={revokingAll}
            className="rounded-xl border border-semantic-error/30 px-4 py-2 text-xs font-medium text-semantic-error hover:bg-semantic-error/10 transition-colors disabled:opacity-50"
          >
            {revokingAll ? <Loader2 size={14} className="inline animate-spin mr-1" /> : null}
            Revoke all
          </button>
        }
      />

      {error && <div className="mb-4 rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">{error}</div>}

      {isLoading ? (
        <div className="py-8 text-center text-text-muted">Loading sessions...</div>
      ) : !sessions || sessions.length === 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-12 text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-surface-2">
            <Monitor size={24} className="text-text-muted" />
          </div>
          <h3 className="mt-4 text-sm font-semibold text-text-primary">No active sessions</h3>
          <p className="mt-2 max-w-sm mx-auto text-xs text-text-muted">
            You don&apos;t have any active sessions. This can happen if all your sessions have
            expired or been revoked.
          </p>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-surface-2">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Client</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">IP Address</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Last Active</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-2">
                {sessions.map((s) => (
                  <tr key={s.id} className="hover:bg-surface-2/50 transition-colors">
                    <td className="px-6 py-3 text-sm text-text-primary">{s.client}</td>
                    <td className="px-6 py-3">
                      <span className="inline-flex items-center gap-1 rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary">
                        <Globe size={10} />
                        {s.ip_address}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-sm text-text-secondary">{formatDateTime(s.created_at)}</td>
                    <td className="px-6 py-3 text-sm text-text-secondary">{formatDateTime(s.last_active)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
