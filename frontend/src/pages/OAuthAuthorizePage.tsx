import { useState, useEffect, useRef, type FormEvent } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { Shield, Loader2, LogIn } from 'lucide-react'
import { api } from '../lib/api'
import { ROUTES } from '../lib/constants'
import { useAuth } from '../hooks/useAuth'
import { useDemoMeta } from '../hooks/useDemoMeta'
import { ConsentScreen } from '../components/oauth/ConsentScreen'
import { FederationLoginButtons } from '../components/auth/FederationLoginButtons'
import { PasskeyLoginButton } from '../components/auth/PasskeyLoginButton'
import { Banner } from '../components/shared/Banner'
import { ThemeSwitcher } from '../components/shared/ThemeSwitcher'
import { brandingStyle } from '../lib/clientBranding'

interface ClientInfo {
  client_name: string
  client_description?: string
  client_logo_uri?: string | null
  client_homepage_uri?: string | null
  client_terms_uri?: string | null
  client_privacy_uri?: string | null
  redirect_uri?: string | null
  branding?: Record<string, unknown> | null
}

interface AuthorizeResponse {
  redirect_url?: string
  consent_required?: boolean
  session_token?: string
  mfa_required?: string
  password_expired?: boolean
  email?: string
  client_name?: string
  client_description?: string | null
  client_logo_uri?: string | null
  client_homepage_uri?: string | null
  client_terms_uri?: string | null
  client_privacy_uri?: string | null
  redirect_uri?: string | null
  branding?: Record<string, unknown> | null
  scopes?: Array<{ name: string; description: string }>
}

type Phase = 'loading' | 'login' | 'consent'

// Login phase follows the ACTIVE theme (the IdP's house); client branding
// (--brand-*) only overrides individual properties when configured.
const NEUTRAL_CSS = `
.authglow-authorize {
  position: relative;
  --radius: var(--brand-radius, 14px);
  --font-family: var(--brand-font, 'Inter', 'Segoe UI', 'Roboto', sans-serif);
  --bg-page: var(--color-bg-primary);
  --bg-surface: var(--brand-surface, var(--color-surface-1));
  --text-primary: var(--color-text-primary);
  --text-secondary: var(--color-text-secondary);
  --text-muted: var(--color-text-muted);
  --border-color: var(--color-surface-2);
  --brand-color: var(--brand-primary, var(--color-brand-accent));
  --brand-hover: color-mix(in srgb, var(--brand-color) 84%, #000);
  --brand-fg: var(--brand-text, #FFFFFF);
  --brand-shadow: color-mix(in srgb, var(--brand-color) 25%, transparent);
  --error-color: var(--color-semantic-error);
  --error-bg: color-mix(in srgb, var(--color-semantic-error) 8%, transparent);
  --ring-color: color-mix(in srgb, var(--brand-color) 20%, transparent);
  --transition: 150ms ease;
  display: flex;
  min-height: 100vh;
  align-items: center;
  justify-content: center;
  background: var(--bg-page);
  padding: 2rem;
  font-family: var(--font-family);
  color: var(--text-primary);
}
.authglow-authorize * { box-sizing: border-box; }
.authglow-authorize .login-card {
  width: 100%;
  max-width: 28rem;
}
.authglow-authorize .login-logo-area {
  text-align: center;
  margin-bottom: 1.5rem;
}
.authglow-authorize .login-logo-img {
  height: 64px;
  width: 64px;
  border-radius: 12px;
  object-fit: contain;
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  display: inline-block;
}
.authglow-authorize .login-logo-icon {
  display: inline-flex;
  height: 56px;
  width: 56px;
  align-items: center;
  justify-content: center;
  border-radius: var(--radius);
  background: color-mix(in srgb, var(--brand-color) 8%, transparent);
  border: 1px solid color-mix(in srgb, var(--brand-color) 16%, transparent);
  color: var(--brand-color);
}
.authglow-authorize .login-title {
  font-size: 1.25rem;
  font-weight: 700;
  color: var(--text-primary);
  text-align: center;
}
.authglow-authorize .login-subtitle {
  margin-top: 0.5rem;
  font-size: 0.875rem;
  color: var(--text-muted);
  text-align: center;
}
.authglow-authorize .login-app-name {
  color: var(--brand-color);
  font-weight: 600;
}
.authglow-authorize .login-app-desc {
  margin-top: 0.25rem;
  font-size: 0.75rem;
  color: var(--text-muted);
  text-align: center;
}
.authglow-authorize .login-error {
  margin-bottom: 1rem;
  padding: 0.75rem 1rem;
  border-radius: var(--radius);
  border: 1px solid color-mix(in srgb, var(--error-color) 30%, transparent);
  background: var(--error-bg);
  color: var(--error-color);
  font-size: 0.875rem;
}
.authglow-authorize .login-form-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  border-radius: var(--radius);
  padding: 1.5rem;
  margin-bottom: 1rem;
}
.authglow-authorize .login-field {
  margin-bottom: 1rem;
}
.authglow-authorize .login-field:last-child { margin-bottom: 0; }
.authglow-authorize .login-label {
  display: block;
  margin-bottom: 0.375rem;
  font-size: 0.75rem;
  font-weight: 500;
  color: var(--text-secondary);
}
.authglow-authorize .login-input {
  width: 100%;
  padding: 0.625rem 1rem;
  border-radius: var(--radius);
  border: 1px solid var(--border-color);
  background: var(--bg-page);
  color: var(--text-primary);
  font-size: 0.875rem;
  font-family: var(--font-family);
  transition: border-color var(--transition), box-shadow var(--transition);
}
.authglow-authorize .login-input::placeholder { color: var(--text-muted); }
.authglow-authorize .login-input:focus {
  outline: none;
  border-color: var(--brand-color);
  box-shadow: 0 0 0 2px var(--ring-color);
}
.authglow-authorize .login-btn {
  display: flex;
  width: 100%;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  border-radius: var(--radius);
  border: none;
  background: var(--brand-color);
  color: var(--brand-fg);
  font-size: 0.875rem;
  font-weight: 600;
  font-family: var(--font-family);
  cursor: pointer;
  transition: all var(--transition);
  box-shadow: 0 2px 8px var(--brand-shadow);
}
.authglow-authorize .login-btn:hover { background: var(--brand-hover); transform: scale(1.02); }
.authglow-authorize .login-btn:active { transform: scale(0.98); }
.authglow-authorize .login-btn:disabled { cursor: not-allowed; opacity: 0.5; transform: none; }
.authglow-authorize .login-error-block {
  background: var(--bg-surface);
  border: 1px solid var(--border-color);
  border-radius: var(--radius);
  padding: 1.5rem;
  text-align: center;
}
.authglow-authorize .login-error-block p { color: var(--error-color); font-size: 0.875rem; }
.authglow-authorize .login-spinner {
  display: flex;
  min-height: 100vh;
  align-items: center;
  justify-content: center;
}
.authglow-authorize .login-spin {
  animation: authglow-spin 1s linear infinite;
  width: 32px;
  height: 32px;
  color: var(--brand-color);
}
@keyframes authglow-spin { to { transform: rotate(360deg); } }
`

export function OAuthAuthorizePage() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { isAuthenticated } = useAuth()
  const [phase, setPhase] = useState<Phase>('loading')
  const [clientInfo, setClientInfo] = useState<ClientInfo | null>(null)
  const [consentData, setConsentData] = useState<AuthorizeResponse | null>(null)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const { meta } = useDemoMeta()

  // If demo credentials were copied on the previous LoginForm screen,
  // pre-fill only the email on the OAuth sign-in form (no auto-submit).
  // The password is intentionally NOT pre-filled: a stale demo password
  // sitting invisibly in the field caused wrong-credential failures (and
  // account lockouts) when signing in with a different account.
  useEffect(() => {
    if (!meta.demo_mode) return
    try {
      const storedEmail = sessionStorage.getItem('authglow_demo_email')
      if (storedEmail) setEmail((prev) => prev || storedEmail)
    } catch {
      // ignore storage errors
    }
  }, [meta.demo_mode])

  const clientId = searchParams.get('client_id') || ''
  const redirectUri = searchParams.get('redirect_uri') || ''
  const scope = searchParams.get('scope') || 'read'
  const state = searchParams.get('state') || ''
  const codeChallenge = searchParams.get('code_challenge') || ''
  const codeChallengeMethod = searchParams.get('code_challenge_method') || ''
  const nonce = searchParams.get('nonce') || ''
  const responseType = searchParams.get('response_type') || ''
  const mfaSessionToken = searchParams.get('mfa_session_token') || ''

  useEffect(() => {
    if (mfaSessionToken) {
      let cancelled = false
      const loadConsentAfterMfa = async () => {
        try {
          const data = await api.get<AuthorizeResponse & { consent_required?: boolean }>(
            `/api/oauth2/consent/check?session_token=${encodeURIComponent(mfaSessionToken)}`,
          )
          if (cancelled) return
          if (data.redirect_url) {
            window.location.href = data.redirect_url
          } else if (data.consent_required) {
            setConsentData({ ...data, session_token: data.session_token || mfaSessionToken })
            setPhase('consent')
          }
        } catch {
          if (!cancelled) setError('The OAuth authorization session has expired.')
          if (!cancelled) setPhase('login')
        }
      }
      loadConsentAfterMfa()
      return () => { cancelled = true }
    }
    if (!clientId || !redirectUri) {
      if (searchParams.get('fed') === '1') {
        setPhase('login')
        return
      }
      setError('Missing required parameters (client_id and redirect_uri).')
      setPhase('login')
      return
    }
    if (responseType && responseType !== 'code') {
      setError('Unsupported response_type. Only "code" is supported.')
      setPhase('login')
      return
    }

    let cancelled = false
    const fetchClientInfo = async () => {
      try {
        const info = await api.get<ClientInfo>(`/api/oauth2/authorize-info?client_id=${encodeURIComponent(clientId)}`)
        if (!cancelled) {
          setClientInfo(info)
          setPhase('login')
        }
      } catch {
        if (!cancelled) {
          setError('Invalid client_id or the application is not active.')
          setPhase('login')
        }
      }
    }
    fetchClientInfo()
    return () => { cancelled = true }
  }, [clientId, redirectUri, responseType, mfaSessionToken])

  useEffect(() => {
    if (phase !== 'login') return

    let cancelled = false
    const checkFederatedSession = async () => {
      try {
        const data = await api.postForm<AuthorizeResponse & { consent_required?: boolean }>(
          '/api/oauth2/federated-consent', {}
        )
        if (!cancelled && data.consent_required) {
          setConsentData(data)
          setPhase('consent')
        }
      } catch {
        // no pending federated session — normal login flow
      }
    }
    checkFederatedSession()
    return () => { cancelled = true }
  }, [phase, clientInfo])

  const passkeyProbed = useRef(false)

  useEffect(() => {
    if (!isAuthenticated || phase !== 'login' || !clientId || !redirectUri) return
    if (passkeyProbed.current) return
    passkeyProbed.current = true

    let cancelled = false
    const completeAfterPasskey = async () => {
      try {
        const formBody: Record<string, string> = {
          client_id: clientId,
          redirect_uri: redirectUri,
          scope,
          state,
        }
        if (codeChallenge) {
          formBody.code_challenge = codeChallenge
          formBody.code_challenge_method = codeChallengeMethod || 'S256'
        }
        if (nonce) formBody.nonce = nonce

        const data = await api.postForm<AuthorizeResponse>('/api/oauth2/authorize', formBody)

        if (cancelled) return
        if (data.redirect_url) {
          window.location.href = data.redirect_url
        } else if (data.consent_required) {
          setConsentData(data)
          setPhase('consent')
        }
      } catch (err: unknown) {
        if (!cancelled) {
          const msg = err instanceof Error ? err.message : ''
          setError(msg || 'Authorization failed. Please try again.')
        }
      }
    }
    completeAfterPasskey()
    return () => { cancelled = true }
  }, [isAuthenticated, phase, clientId, redirectUri])

  const handleLogin = async (e: FormEvent) => {
    e.preventDefault()
    if (!email || !password) return
    setLoading(true)
    setError('')

    try {
      const formBody: Record<string, string> = {
        email,
        password,
        client_id: clientId,
        redirect_uri: redirectUri,
        scope,
        state,
      }
      if (codeChallenge) {
        formBody.code_challenge = codeChallenge
        formBody.code_challenge_method = codeChallengeMethod || 'S256'
      }
      if (nonce) formBody.nonce = nonce

        const data = await api.postForm<AuthorizeResponse>('/api/oauth2/authorize', formBody)

        if (data.redirect_url) {
        window.location.href = data.redirect_url
        return
      }
      if (data.consent_required) {
        setConsentData(data)
        setPhase('consent')
        return
      }
      if (data.mfa_required) {
        window.location.href = `/auth/mfa-verify?session_token=${encodeURIComponent(data.session_token || '')}&oauth=1`
        return
      }
      if (data.password_expired) {
        // Forced credential rotation: route to the change-password screen.
        navigate(ROUTES.AUTH.PASSWORD_EXPIRED, { state: { email } })
        return
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : ''
      if (msg.toLowerCase().includes('invalid credentials')) {
        setError('Invalid email or password.')
      } else if (msg.toLowerCase().includes('locked')) {
        setError('Account is temporarily locked. Try again later.')
      } else {
        setError(msg || 'Authorization failed. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  const displayName = consentData?.client_name || clientInfo?.client_name || 'this application'
  const displayLogo = consentData?.client_logo_uri ?? clientInfo?.client_logo_uri
  const displayDescription = consentData?.client_description ?? clientInfo?.client_description
  const displayHomepage = consentData?.client_homepage_uri ?? clientInfo?.client_homepage_uri
  const displayTerms = consentData?.client_terms_uri ?? clientInfo?.client_terms_uri
  const displayPrivacy = consentData?.client_privacy_uri ?? clientInfo?.client_privacy_uri
  const displayRedirectUri = consentData?.redirect_uri ?? redirectUri
  const displayBranding = consentData?.branding ?? clientInfo?.branding

  if (phase === 'loading') {
    return (
      <>
        <style>{NEUTRAL_CSS}</style>
        <div className="authglow-authorize">
          <div className="login-spinner">
            <Loader2 className="login-spin" />
          </div>
        </div>
      </>
    )
  }

  if (phase === 'consent' && consentData) {
    return (
      <ConsentScreen
        sessionToken={consentData.session_token!}
        clientName={displayName}
        clientDescription={displayDescription}
        clientLogoUri={displayLogo}
        clientHomepageUri={displayHomepage}
        clientTermsUri={displayTerms}
        clientPrivacyUri={displayPrivacy}
        redirectUri={displayRedirectUri}
        branding={displayBranding}
        scopes={consentData.scopes || []}
      />
    )
  }

  return (
    <>
      <style>{NEUTRAL_CSS}</style>
      <div className="authglow-authorize" style={brandingStyle(displayBranding)}>
        <div className="absolute right-4 top-4 z-20">
          <ThemeSwitcher size="sm" />
        </div>
        <div className="login-card">

          <div className="login-logo-area">
            {displayLogo ? (
              <img
                src={displayLogo}
                alt={`${displayName} logo`}
                className="login-logo-img"
                onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
              />
            ) : (
              <div className="login-logo-icon">
                <Shield size={28} />
              </div>
            )}
          </div>

          <h1 className="login-title">Sign in to AuthGlow</h1>
          <p className="login-subtitle">
            <span className="login-app-name">{displayName}</span> wants to access your account.
          </p>
          {displayDescription && (
            <p className="login-app-desc">{displayDescription}</p>
          )}

          {error && !error.includes('client_id') && (
            <div role="alert" className="mb-4">
              <Banner variant="error">{error}</Banner>
            </div>
          )}

          {error && error.includes('client_id') ? (
            <div className="login-error-block">
              <p>{error}</p>
            </div>
          ) : (
            <>
              {meta.demo_mode && (
                <div data-testid="demo-mode-banner" className="mb-4">
                  <Banner variant="demo">
                    {meta.demo_banner_text || 'Demo environment — accounts and data are reset on every server restart.'}
                  </Banner>
                </div>
              )}
              {meta.demo_mode && meta.demo_user_email && meta.demo_user_password && (
                <div
                  data-testid="demo-credentials"
                  role="button"
                  tabIndex={0}
                  title="Click to fill credentials"
                  aria-label="Click to fill demo credentials into the sign-in form"
                  onClick={() => {
                    setEmail(meta.demo_user_email || '')
                    setPassword(meta.demo_user_password || '')
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      setEmail(meta.demo_user_email || '')
                      setPassword(meta.demo_user_password || '')
                    }
                  }}
                  className="mb-4 cursor-pointer rounded-xl border border-surface-2 bg-surface-1/50 px-4 py-3 text-sm transition-colors hover:border-brand-accent/30 hover:bg-surface-1 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent/30"
                >
                  <p className="mb-1 font-semibold text-text-primary">Demo credentials <span className="font-normal text-text-muted">— click to fill</span></p>
                  <p className="break-all font-mono text-xs text-text-secondary">
                    <span className="text-text-muted">Email: </span>{meta.demo_user_email}
                  </p>
                  <p className="mt-0.5 break-all font-mono text-xs text-text-secondary">
                    <span className="text-text-muted">Password: </span>{meta.demo_user_password}
                  </p>
                </div>
              )}
              <form onSubmit={handleLogin}>
                <div className="login-form-card">
                  <div className="login-field">
                    <label htmlFor="oauth-email" className="login-label">Email</label>
                    <input
                      id="oauth-email"
                      type="email"
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value)
                      }}
                      placeholder="admin@authglow.local"
                      autoFocus
                      autoComplete="email"
                      required
                      className="login-input"
                    />
                  </div>

                  <div className="login-field">
                    <label htmlFor="oauth-password" className="login-label">Password</label>
                    <input
                      id="oauth-password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter your password"
                      autoComplete="current-password"
                      required
                      className="login-input"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading || !email || !password}
                  className="login-btn"
                >
                  {loading ? <Loader2 size={16} className="login-spin" /> : <LogIn size={16} />}
                  Sign In & Continue
                </button>
              </form>
            </>
          )}

          <div className="mt-5 pt-4 border-t border-surface-2">
            <PasskeyLoginButton />
          </div>

          <FederationLoginButtons
            context="oauth2"
            oauth2Context={{
              client_id: clientId,
              oauth_redirect_uri: redirectUri,
              scope,
              app_state: state,
              code_challenge: codeChallenge,
              code_challenge_method: codeChallengeMethod,
              response_type: responseType,
              oidc_nonce: nonce,
            }}
          />
        </div>
      </div>
    </>
  )
}
