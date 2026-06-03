import { useState } from 'react'
import { Ban, Loader2, Search, CheckCircle } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

interface ConsentData {
  consent_id: string
  user_email: string
  client_name: string
  scopes: string[]
  granted_at: string
  revoked: boolean
  revoked_at: string | null
}

export function AdminConsentsPage() {
  useDocumentTitle('Consents')
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const queryParam = search ? `?email=${encodeURIComponent(search)}` : ''
  const { data, refetch, isLoading } = useApiQuery<any>(
    ['admin-consents', search],
    `/api/admin/oauth-consents${queryParam}`,
  )
  const consents: ConsentData[] = Array.isArray(data) ? data : (data?.items || data?.consents || [])

  const handleRevoke = async () => {
    if (!revokeId) return
    try { setError(''); await api.post(`/api/admin/oauth-consents/${revokeId}/revoke`); setRevokeId(null); setSuccess('Consent revoked.'); await refetch() }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed') }
  }

  return (
    <div>
      <PageHeader
        title="OAuth Consents"
        description="When a user authorizes a third-party application via OAuth2, a consent record is created here. You can revoke consents to force users to re-authorize."
      />

      {error && <div className="mb-4 rounded-xl bg-semantic-error/10 px-4 py-3 text-sm text-semantic-error" role="alert">{error}</div>}
      {success && <div className="mb-4 rounded-xl bg-semantic-success/10 px-4 py-3 text-sm text-semantic-success">{success}</div>}

      <div className="mb-4">
        <div className="relative max-w-sm">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter by user email..."
            className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 pl-10 pr-4 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
          />
        </div>
      </div>

      {isLoading ? (
        <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div>
      ) : consents.length === 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-12 text-center">
          <CheckCircle className="mx-auto h-8 w-8 text-text-muted" />
          <h3 className="mt-3 text-sm font-semibold text-text-primary">No consents</h3>
          <p className="mt-1 text-xs text-text-muted">
            {search ? 'No consents match your filter.' : 'User consent grants will appear here when they authorize OAuth2 applications.'}
          </p>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">User</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Client</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Scopes</th>
                <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {consents.map((c) => (
                <tr key={c.consent_id} className={`hover:bg-surface-2/50 ${c.revoked ? 'opacity-50' : ''}`}>
                  <td className="px-6 py-3 text-sm text-text-primary">{c.user_email}</td>
                  <td className="px-6 py-3 text-sm text-text-secondary">{c.client_name}</td>
                  <td className="hidden md:table-cell px-6 py-3">
                    <div className="flex flex-wrap gap-1">
                      {c.scopes?.map((s) => (
                        <span key={s} className="rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary">{s}</span>
                      ))}
                    </div>
                  </td>
                  <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">{formatDateTime(c.granted_at)}</td>
                  <td className="px-6 py-3">
                    {!c.revoked && (
                      <button onClick={() => setRevokeId(c.consent_id)} className="text-text-muted hover:text-semantic-error" title="Revoke consent">
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

      <ConfirmDialog open={!!revokeId} title="Revoke Consent" message="The user will need to re-authorize on next login." confirmLabel="Revoke" variant="danger" onConfirm={handleRevoke} onCancel={() => setRevokeId(null)} />
    </div>
  )
}
