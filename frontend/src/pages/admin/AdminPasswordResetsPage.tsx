import { useState } from 'react'
import { Ban, Loader2, Trash2, KeyRound } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { CopyButton } from '@/components/shared/CopyButton'
import { formatDateTime } from '@/lib/utils'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

interface ResetToken {
  token_id: string
  email: string
  reset_code: string
  token_lookup: string
  token_hash: string
  is_used: boolean
  created_at: string
  expires_at: string
}

interface ResetStats {
  total: number
  pending: number
  completed: number
  expired: number
}

export function AdminPasswordResetsPage() {
  useDocumentTitle('Password Resets')
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [revokeEmail, setRevokeEmail] = useState('')
  const [cleaning, setCleaning] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const { data, refetch, isLoading } = useApiQuery<ResetToken[] | { items?: ResetToken[]; tokens?: ResetToken[]; password_resets?: ResetToken[] }>(['admin-password-resets'], '/api/admin/password-resets')
  const tokens: ResetToken[] = Array.isArray(data) ? data : (data?.items || data?.tokens || data?.password_resets || [])

  const { data: stats } = useApiQuery<ResetStats>(['admin-reset-stats'], '/api/admin/password-resets/stats')

  const handleRevokeForUser = async () => {
    if (!revokeEmail.trim()) return
    setError('')
    try {
      const res = await api.post<{ message?: string }>(`/api/admin/users/${revokeEmail}/revoke-resets`)
      setSuccess(res?.message || `Reset tokens revoked for ${revokeEmail}`)
      setRevokeEmail('')
      await refetch()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'User not found or failed to revoke')
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try { setError(''); await api.delete(`/api/admin/password-resets/${deleteId}`); setDeleteId(null); setSuccess('Token deleted.'); await refetch() }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed') }
  }

  const handleCleanup = async () => {
    setCleaning(true); setError('')
    try { await api.post('/api/admin/password-resets/cleanup'); setSuccess('Expired tokens cleaned up.'); await refetch() }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed') }
    finally { setCleaning(false) }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Password Resets"
        description="Track and manage password reset requests. When users forget their password, a reset token is generated and appears here. You can revoke tokens, clean up expired ones, or see who's requesting resets."
        actions={
          <button onClick={handleCleanup} disabled={cleaning} className="whitespace-nowrap flex items-center gap-2 rounded-xl border border-semantic-error/30 px-4 py-2 text-xs font-medium text-semantic-error hover:bg-semantic-error/10 disabled:opacity-50">
            {cleaning ? <Loader2 size={14} className="animate-spin" /> : <Trash2 size={14} />}
            Cleanup Expired
          </button>
        }
      />

      {error && <div className="rounded-xl bg-semantic-error/10 px-4 py-3 text-sm text-semantic-error" role="alert">{error}</div>}
      {success && <div className="rounded-xl bg-semantic-success/10 px-4 py-3 text-sm text-semantic-success">{success}</div>}

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Total" value={stats.total} />
          <StatCard label="Pending" value={stats.pending} color="text-semantic-warning" />
          <StatCard label="Completed" value={stats.completed} color="text-semantic-success" />
          <StatCard label="Expired" value={stats.expired} color="text-text-muted" />
        </div>
      )}

      {/* Revoke by user */}
      <div className="rounded-2xl border border-surface-2 bg-surface-1 p-5">
        <h3 className="text-sm font-semibold text-text-primary mb-3">Revoke All Tokens for a User</h3>
        <p className="text-xs text-text-muted mb-3">If a user reports a compromised reset link, revoke all their active tokens immediately.</p>
        <div className="flex gap-3">
          <input
            value={revokeEmail}
            onChange={e => setRevokeEmail(e.target.value)}
            placeholder="user@example.com"
            className="flex-1 rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
          />
          <button onClick={handleRevokeForUser} disabled={!revokeEmail.trim()} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-5 py-2.5 text-sm font-semibold text-white shadow-glow-violet disabled:opacity-50">
            <Ban size={14} /> Revoke
          </button>
        </div>
      </div>

      {/* Tokens table */}
      {isLoading ? (
        <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div>
      ) : tokens.length === 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 py-12 text-center">
          <KeyRound className="mx-auto h-8 w-8 text-text-muted" />
          <h3 className="mt-3 text-sm font-semibold text-text-primary">No password reset requests</h3>
          <p className="mt-1 text-xs text-text-muted">Reset tokens will appear here when users request password resets.</p>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">User</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Token</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Status</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Expires</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {tokens.map(t => (
                <tr key={t.token_id} className="hover:bg-surface-2/50">
                  <td className="px-6 py-3 text-sm text-text-primary">{t.email}</td>
                  <td className="px-6 py-3">
                    <div className="flex items-center gap-2">
                      <code className="text-xs font-mono text-text-secondary">{(t.reset_code || t.token_lookup).slice(0, 12)}...</code>
                      <CopyButton text={t.reset_code || t.token_lookup} />
                    </div>
                  </td>
                  <td className="px-6 py-3">
                    <span className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${
                      t.is_used ? 'bg-semantic-success/10 text-semantic-success' : new Date(t.expires_at) < new Date() ? 'bg-surface-3 text-text-muted' : 'bg-semantic-warning/10 text-semantic-warning'
                    }`}>
                      {t.is_used ? 'Used' : new Date(t.expires_at) < new Date() ? 'Expired' : 'Active'}
                    </span>
                  </td>
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">{formatDateTime(t.created_at)}</td>
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">{formatDateTime(t.expires_at)}</td>
                  <td className="px-6 py-3">
                    <button onClick={() => setDeleteId(t.token_id)} className="text-text-muted hover:text-semantic-error" title="Delete token"><Trash2 size={14} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog open={!!deleteId} title="Delete Reset Token" message="This will remove the reset token. The user will need to request a new one." confirmLabel="Delete" variant="danger" onConfirm={handleDelete} onCancel={() => setDeleteId(null)} />
    </div>
  )
}

function StatCard({ label, value, color = 'text-text-primary' }: { label: string; value: number; color?: string }) {
  return (
    <div className="rounded-xl border border-surface-2 bg-surface-1 px-4 py-3">
      <p className="text-sm text-text-muted">{label}</p>
      <p className={`text-xl font-bold ${color}`}>{value}</p>
    </div>
  )
}
