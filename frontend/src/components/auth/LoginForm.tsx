import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Loader2, ShieldCheck } from 'lucide-react'
import { api } from '../../lib/api'
import { ROUTES } from '../../lib/constants'
import { generateOAuthNonce, generateOAuthState, generatePkceChallenge, generatePkceVerifier, PLAYGROUND_TRANSACTION_KEY } from '../../lib/oauthCrypto'
import { Banner } from '../../components/shared/Banner'
import { useDemoMeta } from '../../hooks/useDemoMeta'

export function LoginForm() {
  const [generalError, setGeneralError] = useState('')
  const [searchParams] = useSearchParams()
  const redirect = searchParams.get('redirect')
  const [starting, setStarting] = useState(false)
  const [demoCopied, setDemoCopied] = useState(false)
  const { meta } = useDemoMeta()

  const startLogin = async () => {
    setGeneralError('')
    setStarting(true)
    try {
      const config = await api.get<{ client_id: string; redirect_uri: string; scopes: string; authorization_endpoint: string }>(
        '/api/auth/oidc/config',
        { cache: 'no-store' },
      )
      const verifier = generatePkceVerifier()
      const state = generateOAuthState()
      const nonce = generateOAuthNonce()
      const challenge = await generatePkceChallenge(verifier)
      sessionStorage.setItem(PLAYGROUND_TRANSACTION_KEY, JSON.stringify({
        clientId: config.client_id,
        redirectUri: config.redirect_uri,
        state,
        nonce,
        codeVerifier: verifier,
        returnTo: redirect && redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : ROUTES.DASHBOARD,
      }))
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: config.client_id,
        redirect_uri: config.redirect_uri,
        scope: config.scopes,
        state,
        nonce,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      })
      window.location.assign(`${window.location.origin}${ROUTES.OAUTH_AUTHORIZE}?${params}`)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setGeneralError(message || 'Unable to start secure sign-in.')
    } finally {
      setStarting(false)
    }
  }

  return (
    <div className="space-y-5">
      {generalError && (
        <Banner variant="error" role="alert">
          {generalError}
        </Banner>
      )}
      {meta.demo_mode && (
        <Banner variant="demo" data-testid="demo-mode-banner">
          {meta.demo_banner_text || 'Demo environment — accounts and data are reset on every server restart.'}
        </Banner>
      )}
      {meta.demo_mode && meta.demo_user_email && meta.demo_user_password && (
        <div
          data-testid="demo-credentials"
          role="button"
          tabIndex={0}
          title="Click to copy credentials"
          aria-label="Click to copy demo credentials"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(`${meta.demo_user_email} / ${meta.demo_user_password}`)
            } catch {
              // ignore clipboard errors
            }
            try {
              sessionStorage.setItem('authglow_demo_email', meta.demo_user_email || '')
              sessionStorage.setItem('authglow_demo_password', meta.demo_user_password || '')
            } catch {
              // ignore storage errors
            }
            setDemoCopied(true)
            setTimeout(() => setDemoCopied(false), 2000)
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              ;(e.currentTarget as HTMLElement).click()
            }
          }}
          className="cursor-pointer rounded-xl border border-surface-2 bg-surface-1/50 p-4 text-sm transition-colors hover:border-brand-violet/30 hover:bg-surface-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-violet/30"
        >
          <p className="mb-2 font-medium text-text-primary">Demo credentials <span className="font-normal text-text-muted">— click to copy</span>{demoCopied && <span className="ml-2 text-xs font-medium text-semantic-success">Copied!</span>}</p>
          <p className="break-all font-mono text-xs text-text-secondary">
            <span className="text-text-muted">Email: </span>{meta.demo_user_email}
          </p>
          <p className="mt-1 break-all font-mono text-xs text-text-secondary">
            <span className="text-text-muted">Password: </span>{meta.demo_user_password}
          </p>
          <p className="mt-2 text-xs text-text-muted">
            Use these on the next screen to sign in to the sandbox.
          </p>
        </div>
      )}
      <p className="text-sm text-text-secondary">Continue with AuthGlow using the secure OAuth 2.0 Authorization Code flow with PKCE.</p>
      <button
        type="button"
        onClick={startLogin}
        disabled={starting}
        data-testid="login-submit"
        className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {starting ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
        {starting ? 'Starting secure sign-in...' : 'Sign in with AuthGlow'}
      </button>
    </div>
  )
}
