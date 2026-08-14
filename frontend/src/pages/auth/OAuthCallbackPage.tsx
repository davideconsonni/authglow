import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { api } from '../../lib/api'
import { ROUTES } from '../../lib/constants'
import { PLAYGROUND_TRANSACTION_KEY, parseAuthorizationCallback, readJwtClaim } from '../../lib/oauthCrypto'
import { useAuthStore } from '../../stores/authStore'

export function OAuthCallbackPage() {
  const navigate = useNavigate()
  const fetchCurrentUser = useAuthStore((store) => store.fetchCurrentUser)
  const [error, setError] = useState('')
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return
    started.current = true
    const complete = async () => {
      try {
        const raw = sessionStorage.getItem(PLAYGROUND_TRANSACTION_KEY)
        if (!raw) throw new Error('Sign-in transaction is missing or expired')
        const transaction = JSON.parse(raw) as {
          clientId: string
          redirectUri: string
          state: string
          nonce: string
          codeVerifier: string
          returnTo?: string
        }
        const code = parseAuthorizationCallback(window.location.href, transaction.redirectUri, transaction.state)
        const result = await api.postForm<Record<string, unknown>>('/oauth2/token', {
          grant_type: 'authorization_code',
          code,
          client_id: transaction.clientId,
          redirect_uri: transaction.redirectUri,
          code_verifier: transaction.codeVerifier,
        })
        if (result.ok !== true) {
          const idToken = typeof result.id_token === 'string' ? result.id_token : ''
          if (readJwtClaim<string>(idToken, 'nonce') !== transaction.nonce) {
            throw new Error('OIDC nonce validation failed')
          }
        }
        sessionStorage.removeItem(PLAYGROUND_TRANSACTION_KEY)
        await fetchCurrentUser()
        navigate(transaction.returnTo || ROUTES.DASHBOARD, { replace: true })
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Sign-in failed')
      }
    }
    complete()
  }, [fetchCurrentUser, navigate])

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
      <div className="w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-8 text-center">
        {error ? (
          <>
            <h1 className="text-xl font-semibold text-semantic-error">Sign-in failed</h1>
            <p className="mt-2 text-sm text-text-muted" role="alert">{error}</p>
            <button onClick={() => navigate(ROUTES.AUTH.LOGIN, { replace: true })} className="mt-6 rounded-xl bg-surface-2 px-5 py-2.5 text-sm font-semibold text-text-secondary">Return to sign in</button>
          </>
        ) : (
          <>
            <Loader2 className="mx-auto h-8 w-8 animate-spin text-brand-violet" />
            <p className="mt-4 text-sm text-text-muted">Completing secure sign-in...</p>
          </>
        )}
      </div>
    </div>
  )
}
