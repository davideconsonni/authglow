import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Smartphone, Loader2, ShieldBan, Plus } from 'lucide-react'
import { api } from '../../lib/api'
import { useApiQuery } from '../../hooks/useApi'
import { ConfirmDialog } from '../../components/shared/ConfirmDialog'
import { PageHeader } from '../../components/layout/PageHeader'
import { formatDateTime } from '../../lib/utils'
import { ROUTES } from '../../lib/constants'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { notify } from '../../stores/toastStore'

interface DeviceAuth {
  device_code: string
  user_code: string
  client_id: string
  scope: string
  status: string
  user_id: string | null
  created_at: string
  expires_at: string
  authorized_at: string | null
}

const STATUS_STYLES: Record<string, string> = {
  pending: 'bg-amber-500/10 text-amber-500 border-amber-500/20',
  authorized: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
  denied: 'bg-red-500/10 text-red-500 border-red-500/20',
  expired: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
}

export function AdminDeviceAuthsPage() {
  useDocumentTitle('Device Authorizations')
  const [statusFilter, setStatusFilter] = useState('')
  const [revokeTarget, setRevokeTarget] = useState<DeviceAuth | null>(null)
  const [revoking, setRevoking] = useState(false)

  const queryKey = ['admin-device-auths', statusFilter]
  const { data: rawData, refetch, isLoading } = useApiQuery<{ device_authorizations: DeviceAuth[] }>(
    queryKey,
    `/api/admin/device-authorizations${statusFilter ? `?status=${statusFilter}` : ''}`,
  )

  const deviceAuths = rawData?.device_authorizations ?? []

  const handleRevoke = async () => {
    if (!revokeTarget) return
    setRevoking(true)
    try {
      await api.post(`/api/admin/device-authorizations/${revokeTarget.device_code}/revoke`)
      notify.success(`Device authorization ${revokeTarget.user_code} revoked.`)
      setRevokeTarget(null)
      await refetch()
    } catch {
      notify.error('Failed to revoke device authorization')
    } finally {
      setRevoking(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Device Authorizations" description="Manage OAuth 2.0 device authorization (RFC 8628) requests." />

      <div className="flex items-center gap-3">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-xl border border-surface-2 bg-surface-2 px-4 py-2 text-sm text-text-primary focus:border-brand-violet focus:outline-none"
        >
          <option value="">All statuses</option>
          <option value="pending">Pending</option>
          <option value="authorized">Authorized</option>
          <option value="denied">Denied</option>
          <option value="expired">Expired</option>
        </select>
        <span className="text-sm text-text-muted">{deviceAuths.length} request{deviceAuths.length !== 1 ? 's' : ''}</span>
        <Link
          to={ROUTES.ADMIN.DEVICE_AUTHORIZATIONS_NEW}
          className="ml-auto inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          <Plus className="h-4 w-4" />
          New Device Auth
        </Link>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="h-8 w-8 animate-spin text-brand-violet" />
        </div>
      ) : deviceAuths.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-text-muted">
          <Smartphone className="h-12 w-12 mb-3 opacity-40" />
          <p className="text-sm">No device authorization requests found.</p>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-2 text-text-muted">
                  <th className="px-4 py-3 text-left font-medium">User Code</th>
                  <th className="px-4 py-3 text-left font-medium">Client</th>
                  <th className="px-4 py-3 text-left font-medium">Scopes</th>
                  <th className="px-4 py-3 text-left font-medium">User</th>
                  <th className="px-4 py-3 text-left font-medium">Status</th>
                  <th className="px-4 py-3 text-left font-medium">Created</th>
                  <th className="px-4 py-3 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {deviceAuths.map((auth) => (
                  <tr key={auth.device_code} className="border-b border-surface-2 last:border-0 hover:bg-surface-2/50">
                    <td className="px-4 py-3 font-mono text-text-primary">{auth.user_code}</td>
                    <td className="px-4 py-3 text-text-secondary">{auth.client_id}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {auth.scope.split(' ').map((s) => (
                          <span key={s} className="inline-flex rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-muted">
                            {s}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-text-secondary max-w-[120px] truncate">
                      {auth.user_id || <span className="text-text-muted">—</span>}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex rounded-lg border px-2 py-0.5 text-xs font-medium ${STATUS_STYLES[auth.status] || STATUS_STYLES.pending}`}>
                        {auth.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-text-muted text-xs">{formatDateTime(auth.created_at)}</td>
                    <td className="px-4 py-3 text-right">
                      {(auth.status === 'pending' || auth.status === 'authorized') && (
                        <button
                          onClick={() => setRevokeTarget(auth)}
                          className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-medium text-red-400 hover:bg-red-500/10 transition-colors"
                        >
                          <ShieldBan className="h-3.5 w-3.5" />
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <ConfirmDialog
        open={!!revokeTarget}
        title="Revoke Device Authorization"
        message={`Revoke device authorization ${revokeTarget?.user_code} for client ${revokeTarget?.client_id}?`}
        confirmLabel="Revoke"
        onConfirm={handleRevoke}
        onCancel={() => setRevokeTarget(null)}
        loading={revoking}
        variant="danger"
      />
    </div>
  )
}
