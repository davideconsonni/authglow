import { useState } from 'react'
import { Smartphone, Loader2, ShieldBan } from 'lucide-react'
import { api } from '../lib/api'
import { useApiQuery } from '../hooks/useApi'
import { ConfirmDialog } from '../components/shared/ConfirmDialog'
import { PageHeader } from '../components/layout/PageHeader'
import { formatDateTime } from '../lib/utils'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { notify } from '../stores/toastStore'

interface UserDeviceAuth {
  device_code: string
  user_code: string
  client_id: string
  scope: string
  status: string
  created_at: string
  expires_at: string
}

const STATUS_STYLES: Record<string, string> = {
  pending: 'bg-amber-500/10 text-amber-500 border-amber-500/20',
  authorized: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20',
  denied: 'bg-red-500/10 text-red-500 border-red-500/20',
  expired: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
}

export function DeviceAuthorizationsPage() {
  useDocumentTitle('Device Authorizations')
  const [revokeTarget, setRevokeTarget] = useState<UserDeviceAuth | null>(null)
  const [revoking, setRevoking] = useState(false)

  const { data: rawData, refetch, isLoading } = useApiQuery<{ device_authorizations: UserDeviceAuth[] }>(
    ['my-device-auths'],
    '/api/oauth2/device/authorizations',
  )

  const deviceAuths = rawData?.device_authorizations ?? []

  const handleRevoke = async () => {
    if (!revokeTarget) return
    setRevoking(true)
    try {
      await api.post(`/api/oauth2/device/authorizations/${revokeTarget.user_code}/revoke`)
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
      <PageHeader
        title="Device Authorizations"
        description="Devices you've approved via OAuth 2.0 Device Authorization Grant."
      />

      {isLoading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="h-8 w-8 animate-spin text-brand-accent" />
        </div>
      ) : deviceAuths.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-text-muted">
          <Smartphone className="h-12 w-12 mb-3 opacity-40" />
          <p className="text-sm">No device authorizations.</p>
          <p className="text-xs mt-1">When you approve a device (CLI, IoT, TV), it will appear here.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {deviceAuths.map((auth) => (
            <div
              key={auth.user_code}
              className="flex items-center justify-between rounded-2xl border border-surface-2 bg-surface-1 p-4"
            >
              <div className="space-y-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-text-primary">{auth.user_code}</span>
                  <span className={`inline-flex rounded-lg border px-2 py-0.5 text-xs font-medium ${STATUS_STYLES[auth.status] || STATUS_STYLES.pending}`}>
                    {auth.status}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 text-xs text-text-muted">
                  <span>{auth.client_id}</span>
                  <span className="text-surface-2 select-none">|</span>
                  <span>{auth.scope}</span>
                  <span className="text-surface-2 select-none">|</span>
                  <span>{formatDateTime(auth.created_at)}</span>
                </div>
              </div>
              {(auth.status === 'pending' || auth.status === 'authorized') && (
                <button
                  onClick={() => setRevokeTarget(auth)}
                  className="shrink-0 inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-xs font-medium text-red-400 hover:bg-red-500/10 transition-colors"
                >
                  <ShieldBan className="h-3.5 w-3.5" />
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={!!revokeTarget}
        title="Revoke Device Authorization"
        message={`Revoke device authorization ${revokeTarget?.user_code} for ${revokeTarget?.client_id}?`}
        confirmLabel="Revoke"
        onConfirm={handleRevoke}
        onCancel={() => setRevokeTarget(null)}
        loading={revoking}
        variant="danger"
      />
    </div>
  )
}
