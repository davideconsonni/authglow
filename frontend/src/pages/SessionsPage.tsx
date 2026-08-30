import { useState } from 'react'
import { Monitor, Globe, Loader2, Trash2 } from 'lucide-react'
import { api } from '../lib/api'
import { useApiQuery } from '../hooks/useApi'
import { ConfirmDialog } from '../components/shared/ConfirmDialog'
import { PageHeader } from '../components/layout/PageHeader'
import { JwtDecoder } from '../components/playground/JwtDecoder'
import { formatDateTime } from '../lib/utils'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { notify } from '../stores/toastStore'

interface Session {
  id: string
  client: string
  ip_address: string
  created_at: string
  last_active: string
}

export function SessionsPage() {
  useDocumentTitle('Sessions')
  const [revokingAll, setRevokingAll] = useState(false)
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [showToken, setShowToken] = useState(false)

  const { data: rawData, refetch, isLoading } = useApiQuery<Session[] | { items?: Session[]; sessions?: Session[]; tokens?: Session[] }>(
    ['my-sessions'],
    '/api/tokens/refresh/list',
  )

  // Fase 6: decoded claims of the access token this browser is using now.
  // The httpOnly cookie never reaches JS — the backend echoes the token.
  const { data: myToken } = useApiQuery<{ access_token?: string }>(
    ['my-token'],
    '/api/auth/my-token',
  )

  const sessions: Session[] = Array.isArray(rawData) ? rawData : (rawData?.sessions || rawData?.items || rawData?.tokens || [])

  const thisDeviceId = sessions.length > 0
    ? sessions.reduce((a, b) => (new Date(a.last_active) > new Date(b.last_active) ? a : b)).id
    : null

  const handleRevokeAll = async () => {
    setRevokingAll(true)
    try {
      const res = await api.post<{ message?: string; count?: number }>('/api/tokens/refresh/revoke-all')
      const count = res?.count || 0
      notify.success(count > 0 ? `Revoked ${count} session${count !== 1 ? 's' : ''}.` : 'All sessions revoked.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to revoke sessions')
    } finally {
      setRevokingAll(false)
    }
  }

  const handleRevokeSession = async () => {
    if (!revokeId) return
    try {
      await api.delete(`/api/tokens/refresh/${revokeId}`)
      setRevokeId(null)
      notify.success('Session revoked.')
      await refetch()
    } catch (err: unknown) {
      setRevokeId(null)
      notify.error(err instanceof Error ? err.message : 'Failed to revoke session')
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
        <>
          {/* Desktop table */}
          <div className="hidden md:block rounded-2xl border border-surface-2 bg-surface-1">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-surface-2">
                  <tr>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase w-32">Device</th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Client</th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">IP Address</th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                    <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Last Active</th>
                    <th className="px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-2">
                  {sessions.map((s) => (
                    <tr key={s.id} className="hover:bg-surface-2/50 transition-colors">
                      <td className="px-4 py-2.5">
                        {s.id === thisDeviceId && (
                          <span className="inline-flex rounded-lg bg-brand-wash px-2 py-0.5 text-xs font-medium text-brand-accent">This device</span>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-sm text-text-primary">{s.client}</td>
                      <td className="px-4 py-2.5">
                        <span className="inline-flex items-center gap-1 rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary">
                          <Globe size={10} />
                          {s.ip_address}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-sm text-text-secondary">{formatDateTime(s.created_at)}</td>
                      <td className="px-4 py-2.5 text-sm text-text-secondary">{formatDateTime(s.last_active)}</td>
                      <td className="px-4 py-2.5">
                        <button
                          onClick={() => setRevokeId(s.id)}
                          className="text-text-muted hover:text-semantic-error transition-colors"
                          aria-label="Revoke session"
                        >
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Mobile cards */}
          <div className="md:hidden space-y-3">
            {sessions.map((s) => (
              <div key={s.id} className="rounded-2xl border border-surface-2 bg-surface-1 p-4 space-y-3">
                <div className="flex items-start justify-between">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-text-primary truncate">{s.client}</p>
                      {s.id === thisDeviceId && (
                        <span className="shrink-0 inline-flex rounded-lg bg-brand-wash px-2 py-0.5 text-[10px] font-medium text-brand-accent">This device</span>
                      )}
                    </div>
                    <div className="mt-1 flex items-center gap-1.5 text-xs text-text-muted">
                      <Globe size={10} />
                      <span>{s.ip_address}</span>
                    </div>
                  </div>
                  <button
                    onClick={() => setRevokeId(s.id)}
                    className="shrink-0 rounded-lg p-1.5 text-text-muted hover:text-semantic-error hover:bg-semantic-error/10 transition-colors"
                    aria-label="Revoke session"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
                <div className="flex items-center gap-4 text-xs text-text-muted">
                  <span>Created {formatDateTime(s.created_at)}</span>
                  <span>Active {formatDateTime(s.last_active)}</span>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* ----- My current access token (Fase 6) ----- */}
      <div className="mt-6 rounded-2xl border border-surface-2 bg-surface-1 p-5">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-semibold text-text-primary">My current access token</h3>
            <p className="mt-0.5 text-xs text-text-muted">
              Decoded claims of the token this browser is using right now. The httpOnly cookie
              never reaches JavaScript — the backend echoes it on request.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setShowToken(s => !s)}
            aria-expanded={showToken}
            data-testid="my-token-toggle"
            className="shrink-0 rounded-xl border border-surface-2 px-3 py-1.5 text-xs font-semibold text-text-secondary transition-colors hover:border-brand-accent/40 hover:text-brand-accent"
          >
            {showToken ? 'Hide' : 'Show claims'}
          </button>
        </div>
        {showToken && (
          <div className="mt-4" data-testid="my-token-panel">
            {myToken?.access_token ? (
              <JwtDecoder response={JSON.stringify(myToken)} />
            ) : (
              <p className="rounded-xl border border-surface-2 bg-surface-2/50 p-4 text-xs text-text-muted">
                No active access token.
              </p>
            )}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={!!revokeId}
        title="Revoke Session"
        message="This will immediately log out this session. The user will need to re-authenticate."
        confirmLabel="Revoke"
        variant="danger"
        onConfirm={handleRevokeSession}
        onCancel={() => setRevokeId(null)}
      />
    </div>
  )
}
