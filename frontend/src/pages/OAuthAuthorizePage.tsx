import { useState, useEffect, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Shield, Loader2, LogIn } from 'lucide-react'
import { api } from '@/lib/api'
import { ConsentScreen } from '@/components/oauth/ConsentScreen'

interface ClientInfo {
  client_name: string
  client_description?: string
  client_logo_uri?: string | null
  client_homepage_uri?: string | null
  client_terms_uri?: string | null
  client_privacy_uri?: string | null
  custom_css?: string | null
}

interface AuthorizeResponse {
  redirect_url?: string
  consent_required?: boolean
  session_token?: string
  mfa_required?: string
  client_name?: string
  client_description?: string | null
  client_logo_uri?: string | null
  client_homepage_uri?: string | null
  client_terms_uri?: string | null
  client_privacy_uri?: string | null
  custom_css?: string | null
  scopes?: Array<{ name: string; description: string }>
}

type Phase = 'loading' | 'login' | 'consent'

const NEUTRAL_CSS = `
.authglow-authorize {
  --bg-primary: #f8f9fa;
  --bg-surface: #ffffff;
  --text-primary: #1a1a2e;
  --text-secondary: #475569;
  --text-muted: #718096;
  --border-color: #e2e8f0;
  --brand-color: #475569;
  --brand-hover: #334155;
  --brand-text: #ffffff;
  --brand-shadow: rgba(71, 85, 105, 0.25);
  --error-color: #dc2626;
  --error-bg: #fef2f2;
  --ring-color: rgba(71, 85, 105, 0.2);
  --radius: 12px;
  --font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
  --transition: 150ms ease;
  display: flex;
  min-height: 100vh;
  align-items: center;
  justify-content: center;
  background: var(--bg-primary);
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
  background: rgba(71, 85, 105, 0.06);
  border: 1px solid rgba(71, 85, 105, 0.12);
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
  border: 1px solid rgba(220, 38, 38, 0.3);
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
  background: var(--bg-primary);
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
  color: var(--brand-text);
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
.authglow-authorize .fed-separator {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin: 1rem 0;
}
.authglow-authorize .fed-sep-line {
  flex: 1;
  height: 1px;
  background: var(--border-color);
}
.authglow-authorize .fed-sep-text {
  font-size: 0.75rem;
  color: var(--text-muted);
  white-space: nowrap;
}
.authglow-authorize .fed-buttons {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.authglow-authorize .fed-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  padding: 0.625rem 1rem;
  border-radius: var(--radius);
  border: 1px solid var(--border-color);
  background: var(--bg-surface);
  color: var(--text-primary);
  font-size: 0.875rem;
  font-weight: 500;
  text-decoration: none;
  cursor: pointer;
  transition: all var(--transition);
}
.authglow-authorize .fed-btn:hover {
  background: var(--bg-subtle);
  border-color: var(--brand-color);
}
.authglow-authorize .fed-btn-icon {
  width: 18px;
  height: 18px;
  border-radius: 4px;
  object-fit: contain;
}
`

export function OAuthAuthorizePage() {
  const [searchParams] = useSearchParams()
  const [phase, setPhase] = useState<Phase>('loading')
  const [clientInfo, setClientInfo] = useState<ClientInfo | null>(null)
  const [consentData, setConsentData] = useState<AuthorizeResponse | null>(null)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [fedProviders, setFedProviders] = useState<Array<{id: string; label: string; icon_uri?: string | null}>>([])

  const clientId = searchParams.get('client_id') || ''
  const redirectUri = searchParams.get('redirect_uri') || ''
  const scope = searchParams.get('scope') || 'read'
  const state = searchParams.get('state') || ''
  const codeChallenge = searchParams.get('code_challenge') || ''
  const codeChallengeMethod = searchParams.get('code_challenge_method') || ''
  const nonce = searchParams.get('nonce') || ''
  const responseType = searchParams.get('response_type') || ''

  useEffect(() => {
    if (!clientId || !redirectUri) {
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
  }, [clientId, redirectUri, responseType])

  useEffect(() => {
    let cancelled = false
    const fetchProviders = async () => {
      try {
        const providers = await api.get<Array<{id: string; label: string; icon_uri?: string | null}>>('/api/federation/providers')
        if (!cancelled) setFedProviders(providers)
      } catch { /* federation not available — silently skip */ }
    }
    fetchProviders()
    return () => { cancelled = true }
  }, [])

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

      const data = await api.postForm<AuthorizeResponse>('/oauth2/authorize', formBody)

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
        setError('MFA verification is required but not yet supported in this flow.')
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
  const displayCustomCss = consentData?.custom_css ?? clientInfo?.custom_css

  if (phase === 'loading') {
    return (
      <>
        <style>{NEUTRAL_CSS}{displayCustomCss || ''}</style>
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
        customCss={displayCustomCss}
        scopes={consentData.scopes || []}
      />
    )
  }

  return (
    <>
      <style>{NEUTRAL_CSS}{displayCustomCss || ''}</style>
      <div className="authglow-authorize">
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
            <div className="login-error" role="alert">{error}</div>
          )}

          {error && error.includes('client_id') ? (
            <div className="login-error-block">
              <p>{error}</p>
            </div>
          ) : (
            <form onSubmit={handleLogin}>
              <div className="login-form-card">
                <div className="login-field">
                  <label htmlFor="oauth-email" className="login-label">Email</label>
                  <input
                    id="oauth-email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
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

              {fedProviders.length > 0 && (
                <div className="fed-separator">
                  <span className="fed-sep-line" />
                  <span className="fed-sep-text">or continue with</span>
                  <span className="fed-sep-line" />
                </div>
              )}
            </form>
          )}

          {fedProviders.length > 0 && (
            <div className="fed-buttons">
              {fedProviders.map((p) => (
                <a
                  key={p.id}
                  href={`/api/federation/login/${p.id}?redirect_uri=${encodeURIComponent(window.location.origin + window.location.pathname + window.location.search)}`}
                  className="fed-btn"
                  data-testid={`fed-provider-${p.id}`}
                >
                  {p.icon_uri ? <img src={p.icon_uri} alt="" className="fed-btn-icon" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }} /> : <Shield size={16} />}
                  {p.label}
                </a>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  )
}