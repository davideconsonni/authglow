import { useState } from 'react'
import { Fingerprint, Loader2 } from 'lucide-react'
import { startAuthentication } from '@simplewebauthn/browser'
import { api } from '@/lib/api'
import { useAuthStore } from '@/stores/authStore'
import { getSavedEmail } from '@/components/auth/LoginForm'

export function PasskeyLoginButton() {
  const setAuthenticated = useAuthStore((s) => s.setAuthenticated)
  const fetchCurrentUser = useAuthStore((s) => s.fetchCurrentUser)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handlePasskeyLogin = async () => {
    setLoading(true)
    setError('')
    try {
      const email = getSavedEmail()
      if (!email) {
        setError('Sign in with email first to enable passkey login.')
        setLoading(false)
        return
      }
      const beginResp = await api.post<any>('/api/passkey/auth/begin', { email })
      const authResult = await startAuthentication({ optionsJSON: beginResp })
      const completeResp = await api.post<{ access_token: string; refresh_token?: string }>('/api/passkey/auth/complete', {
        credential_id: authResult.id,
        client_data_json: authResult.response.clientDataJSON,
        authenticator_data: authResult.response.authenticatorData,
        signature: authResult.response.signature,
        user_handle: authResult.response.userHandle || null,
      })
      if (completeResp.access_token) {
        setAuthenticated(true)
        await fetchCurrentUser()
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Passkey authentication failed'
      if (msg.includes('name')) {
        setError('No passkey found for this device.')
      } else {
        setError(msg)
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-2">
      {error && (
        <div className="rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">
          {error}
        </div>
      )}
      <button
        onClick={handlePasskeyLogin}
        disabled={loading}
        className="flex w-full items-center justify-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm font-medium text-text-secondary hover:bg-surface-2 hover:text-text-primary transition-colors disabled:opacity-50"
      >
        {loading ? (
          <Loader2 size={18} className="animate-spin" />
        ) : (
          <Fingerprint size={18} />
        )}
        Sign in with Passkey
      </button>
    </div>
  )
}
