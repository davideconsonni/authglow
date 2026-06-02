import { useState } from 'react'
import { Shield, Plus, Trash2, Laptop, Smartphone, Key, Loader2, Clock } from 'lucide-react'
import { startRegistration } from '@simplewebauthn/browser'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { formatDateTime } from '@/lib/utils'

interface Passkey {
  id: string
  name: string
  device_type: string
  transports: string[]
  created_at: string
  last_used_at: string | null
}

const DEVICE_ICONS: Record<string, typeof Laptop> = {
  platform: Smartphone,
  'cross-platform': Key,
  default: Laptop,
}

export function PasskeyManager() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState('')

  const { data: passkeys, refetch } = useApiQuery<Passkey[]>(
    ['passkeys'],
    '/api/passkey/list',
  )

  const handleAddPasskey = async () => {
    setLoading(true)
    setError('')
    setSuccessMsg('')
    try {
      const beginResp = await api.post<any>(
        '/api/passkey/register/begin',
        { name: navigator.userAgent || 'Browser' },
      )

      const regResult = await startRegistration({ optionsJSON: beginResp })

      await api.post('/api/passkey/register/complete', {
        credential_id: regResult.id,
        client_data_json: regResult.response.clientDataJSON,
        attestation_object: regResult.response.attestationObject,
        transports: regResult.response.transports || [],
      })

      setSuccessMsg('Passkey added successfully')
      await refetch()
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setError(message || 'Failed to register passkey')
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    setError('')
    try {
      await api.delete(`/api/passkey/${deleteId}`)
      setDeleteId(null)
      await refetch()
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setError(message || 'Failed to remove passkey')
    }
  }

  return (
    <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-text-primary">Passkeys</h3>
          <p className="text-xs text-text-muted">Passwordless authentication with biometrics or security keys</p>
        </div>
        <button
          onClick={handleAddPasskey}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-xs font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50"
        >
          {loading ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
          Add Passkey
        </button>
      </div>

      {successMsg && (
        <p className="text-xs text-semantic-success">{successMsg}</p>
      )}

      {error && (
        <p className="text-xs text-semantic-error" role="alert">{error}</p>
      )}

      {!passkeys || passkeys.length === 0 ? (
        <div className="flex flex-col items-center gap-3 py-8 text-center">
          <div className="rounded-2xl bg-brand-violet/10 p-3 shadow-glow-violet">
            <Shield size={24} className="text-brand-violet" />
          </div>
          <p className="text-sm text-text-secondary">No passkeys registered yet</p>
          <p className="text-xs text-text-muted max-w-xs">
            Add a passkey to sign in securely with your fingerprint, face, or device PIN.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {passkeys.map((pk) => {
            const Icon = DEVICE_ICONS[pk.device_type] || DEVICE_ICONS.default
            return (
              <div
                key={pk.id}
                className="flex items-center justify-between rounded-xl bg-surface-2 px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-violet/10">
                    <Icon size={16} className="text-brand-violet" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-text-primary">{pk.name}</p>
                    <div className="flex items-center gap-2 text-xs text-text-muted">
                      <span>{pk.transports?.join(', ') || pk.device_type}</span>
                      <span>&middot;</span>
                      <span>Created {formatDateTime(pk.created_at)}</span>
                      {pk.last_used_at && (
                        <>
                          <span>&middot;</span>
                          <Clock size={10} />
                          <span>Last used {formatDateTime(pk.last_used_at)}</span>
                        </>
                      )}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setDeleteId(pk.id)}
                  className="text-text-muted hover:text-semantic-error transition-colors"
                  aria-label={`Remove passkey ${pk.name}`}
                >
                  <Trash2 size={16} />
                </button>
              </div>
            )
          })}
        </div>
      )}

      <ConfirmDialog
        open={!!deleteId}
        title="Remove Passkey"
        message="Are you sure you want to remove this passkey? You will no longer be able to use it to sign in."
        confirmLabel="Remove"
        variant="danger"
        onConfirm={handleDelete}
        onCancel={() => setDeleteId(null)}
      />
    </div>
  )
}
