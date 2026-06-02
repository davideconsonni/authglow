import { useState } from 'react'
import { Monitor, Globe, Trash2, Loader2 } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { formatDateTime } from '@/lib/utils'

interface TrustedDevice {
  id: string
  name: string
  ip_address: string
  created_at: string
}

export function TrustedDevices() {
  const [removing, setRemoving] = useState<string | null>(null)
  const [error, setError] = useState('')

  const { data: devices, refetch } = useApiQuery<TrustedDevice[]>(
    ['mfa-trusted-devices'],
    '/api/mfa/trusted-devices',
  )

  const handleRemove = async (id: string) => {
    setRemoving(id)
    setError('')
    try {
      await api.delete(`/api/mfa/trusted-devices/${id}`)
      await refetch()
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setError(message || 'Failed to remove device.')
    } finally {
      setRemoving(null)
    }
  }

  if (!devices || devices.length === 0) {
    return (
      <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 text-center">
        <Monitor className="mx-auto h-8 w-8 text-text-muted" />
        <h3 className="mt-3 text-sm font-semibold text-text-primary">No trusted devices</h3>
        <p className="mt-1 text-xs text-text-muted">
          Trusted devices will appear here after you complete MFA verification.
        </p>
      </div>
    )
  }

  return (
    <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-text-primary">Trusted Devices</h3>
        <p className="text-xs text-text-muted">Devices that can skip MFA verification</p>
      </div>

      {error && (
        <p className="text-xs text-semantic-error" role="alert">{error}</p>
      )}

      <div className="space-y-2">
        {devices.map((device) => (
          <div
            key={device.id}
            className="flex items-center justify-between rounded-xl bg-surface-2 px-4 py-3"
          >
            <div className="flex items-center gap-3">
              <Monitor size={18} className="text-text-muted" />
              <div>
                <p className="text-sm font-medium text-text-primary">{device.name}</p>
                <div className="flex items-center gap-2 text-xs text-text-muted">
                  <Globe size={10} />
                  <span>{device.ip_address}</span>
                  <span>&middot;</span>
                  <span>{formatDateTime(device.created_at)}</span>
                </div>
              </div>
            </div>
            <button
              onClick={() => handleRemove(device.id)}
              disabled={removing === device.id}
              className="text-text-muted hover:text-semantic-error transition-colors disabled:opacity-50"
              aria-label={`Remove device ${device.name}`}
            >
              {removing === device.id ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                <Trash2 size={16} />
              )}
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
