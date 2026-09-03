import { useState } from 'react'
import { Fingerprint, Loader2 } from 'lucide-react'
import { startAuthentication, type PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser'
import { api } from '../../lib/api'
import { useAuthStore } from '../../stores/authStore'
import { getSavedEmail, saveEmail } from '../../lib/loginStorage'
import { Banner } from '../../components/shared/Banner'

export function PasskeyLoginButton() {
  const setAuthenticated = useAuthStore((s) => s.setAuthenticated)
  const fetchCurrentUser = useAuthStore((s) => s.fetchCurrentUser)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [email, setEmail] = useState(getSavedEmail())
  const [requiresEmail, setRequiresEmail] = useState(!getSavedEmail())

  const handlePasskeyLogin = async () => {
    setLoading(true)
    setError('')
    try {
      if (!email) {
        setError('Enter your email to find your registered passkey.')
        setLoading(false)
        return
      }
      saveEmail(email)
      setRequiresEmail(false)
      const beginResp = await api.post<PublicKeyCredentialRequestOptionsJSON>('/api/passkey/auth/begin', { email })
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
        <Banner variant="error" size="sm" role="alert">
          {error}
        </Banner>
      )}
      {requiresEmail && (
        <input
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          placeholder="you@example.com"
          autoComplete="email"
          aria-label="Email for passkey login"
          className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
        />
      )}
      <button
        onClick={handlePasskeyLogin}
        disabled={loading || !email}
        className="group relative flex w-full items-center justify-center gap-2 rounded-xl border border-border bg-surface-1 px-4 py-3 text-sm font-medium text-text-secondary hover:border-brand-accent/50 hover:text-brand-accent transition-all btn-cta"
      >
        {loading ? (
          <Loader2 size={18} className="animate-spin" />
        ) : (
          <Fingerprint size={18} />
        )}
        Sign in with Passkey
        <span className="absolute -top-2.5 right-3 rounded-full bg-gradient-cta px-2 py-0.5 text-[10px] font-bold text-white shadow-glow-accent">
          Recommended
        </span>
      </button>
    </div>
  )
}
