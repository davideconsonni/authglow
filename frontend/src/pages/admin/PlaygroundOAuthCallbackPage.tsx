import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2, ShieldCheck } from 'lucide-react'
import { api } from '../../lib/api'
import { PLAYGROUND_TRANSACTION_KEY, parseAuthorizationCallback, readJwtClaim } from '../../lib/oauthCrypto'
import { ROUTES } from '../../lib/constants'
import { usePlaygroundStore } from '../../stores/playgroundStore'

export function PlaygroundOAuthCallbackPage() {
  const navigate = useNavigate()
  const persistTokens = usePlaygroundStore((store) => store.persistTokens)
  const [error, setError] = useState('')
  const [complete, setComplete] = useState(false)
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return
    started.current = true

    const exchangeCallback = async () => {
      try {
        const rawTransaction = sessionStorage.getItem(PLAYGROUND_TRANSACTION_KEY)
        if (!rawTransaction) throw new Error('OAuth playground transaction is missing or expired')

        const transaction = JSON.parse(rawTransaction) as {
          clientId: string
          clientSecret?: string
          redirectUri: string
          scopes: string
          state: string
          nonce: string
          codeVerifier: string
        }
        const code = parseAuthorizationCallback(window.location.href, transaction.redirectUri, transaction.state)
        const result = await api.postForm<Record<string, unknown>>('/oauth2/token', {
          grant_type: 'authorization_code',
          code,
          redirect_uri: transaction.redirectUri,
          client_id: transaction.clientId,
          client_secret: transaction.clientSecret || '',
          code_verifier: transaction.codeVerifier,
        })

        const idToken = typeof result.id_token === 'string' ? result.id_token : ''
        if (transaction.scopes.split(/\s+/).includes('openid') && readJwtClaim<string>(idToken, 'nonce') !== transaction.nonce) {
          throw new Error('OIDC nonce validation failed')
        }

        persistTokens(
          typeof result.access_token === 'string' ? result.access_token : '',
          typeof result.refresh_token === 'string' ? result.refresh_token : '',
          idToken,
        )
        sessionStorage.removeItem(PLAYGROUND_TRANSACTION_KEY)
        setComplete(true)
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'OAuth callback failed')
      }
    }

    exchangeCallback()
  }, [persistTokens])

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
      <div className="w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-8 text-center">
        {!error && !complete && <Loader2 className="mx-auto h-8 w-8 animate-spin text-brand-accent" />}
        {complete && (
          <>
            <ShieldCheck className="mx-auto h-10 w-10 text-semantic-success" />
            <h1 className="mt-4 text-xl font-semibold text-text-primary">OAuth authorization complete</h1>
            <p className="mt-2 text-sm text-text-muted">The callback state, PKCE verifier, and OIDC nonce were validated.</p>
            <button onClick={() => navigate(ROUTES.ADMIN.PLAYGROUND)} className="mt-6 rounded-xl bg-gradient-cta px-5 py-2.5 text-sm font-semibold text-white">Return to playground</button>
          </>
        )}
        {error && (
          <>
            <h1 className="text-xl font-semibold text-semantic-error">OAuth callback failed</h1>
            <p className="mt-2 text-sm text-text-muted" role="alert">{error}</p>
            <button onClick={() => navigate(ROUTES.ADMIN.PLAYGROUND)} className="mt-6 rounded-xl bg-surface-2 px-5 py-2.5 text-sm font-semibold text-text-secondary">Return to playground</button>
          </>
        )}
      </div>
    </div>
  )
}
