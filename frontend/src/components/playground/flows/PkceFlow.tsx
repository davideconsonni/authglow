import { useState } from 'react'
import { ArrowRight, ExternalLink, Loader2, RefreshCw } from 'lucide-react'
import { api } from '../../../lib/api'
import { usePlaygroundStore, generateState, generatePkceVerifier, generatePkceChallenge } from '../../../stores/playgroundStore'
import { generateOAuthNonce, parseAuthorizationCallback, readJwtClaim } from '../../../lib/oauthCrypto'
import { FlowStepper } from '../FlowStepper'
import { ResponsePanel } from '../ResponsePanel'

const STEPS = [
  { id: 'config', label: 'Configure' },
  { id: 'pkce', label: 'PKCE Params' },
  { id: 'authorize', label: 'Authorize' },
  { id: 'exchange', label: 'Exchange' },
  { id: 'tokens', label: 'Tokens' },
]

export function PkceFlow() {
  const store = usePlaygroundStore()

  const [currentStep, setCurrentStep] = useState('config')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const [localClientId, setLocalClientId] = useState(store.clientId)
  const [localRedirectUri, setLocalRedirectUri] = useState(store.redirectUri)
  const [localScopes, setLocalScopes] = useState(store.scopes)
  const [localState, setLocalState] = useState(store.state)
  const [localVerifier, setLocalVerifier] = useState(store.codeVerifier)
  const [localChallenge, setLocalChallenge] = useState(store.codeChallenge)
  const [localCode, setLocalCode] = useState('')
  const [callbackUrl, setCallbackUrl] = useState('')
  const [localNonce] = useState(store.nonce || generateOAuthNonce())

  const authUrl = (() => {
    if (!localClientId || !localRedirectUri || !localChallenge) return ''
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: localClientId,
      redirect_uri: localRedirectUri,
      scope: localScopes.replace(/,/g, ' ').replace(/\s+/g, ' ').trim(),
      state: localState,
      code_challenge: localChallenge,
      code_challenge_method: 'S256',
      nonce: localNonce,
    })
    return `${window.location.origin}/oauth2/authorize?${params.toString()}`
  })()

  const handleConfigNext = () => {
    store.setClientId(localClientId)
    store.setRedirectUri(localRedirectUri)
    store.setScopes(localScopes)
    store.setState(localState)
    store.setNonce(localNonce)
    setCompleted(['config'])
    setCurrentStep('pkce')
  }

  const handleGeneratePkce = async () => {
    const v = generatePkceVerifier()
    const c = await generatePkceChallenge(v)
    setLocalVerifier(v)
    setLocalChallenge(c)
    store.setCodeVerifier(v)
    store.setCodeChallenge(c)
    setCompleted(['config', 'pkce'])
    setCurrentStep('authorize')
  }

  const handleExchangeCode = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      const exchangeCode = callbackUrl.trim()
        ? parseAuthorizationCallback(callbackUrl.trim(), localRedirectUri, localState)
        : localCode
      if (!exchangeCode) throw new Error('Authorization code or callback URL is required')
      const formBody: Record<string, string> = {
        grant_type: 'authorization_code',
        code: exchangeCode,
        redirect_uri: localRedirectUri,
        code_verifier: localVerifier,
      }
      if (localClientId) formBody.client_id = localClientId

      const result = await api.postForm('/oauth2/token', formBody)
      const r = result as Record<string, unknown>
      const idToken = typeof r.id_token === 'string' ? r.id_token : ''
      if (localScopes.split(/\s+/).includes('openid') && readJwtClaim<string>(idToken, 'nonce') !== localNonce) {
        throw new Error('OIDC nonce validation failed')
      }
      store.persistTokens(
        (r.access_token as string) || '',
        (r.refresh_token as string) || '',
        idToken,
      )

      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
      setCompleted(['config', 'pkce', 'authorize', 'exchange'])
      setCurrentStep('tokens')
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) setHttpStatus((err as { status: number }).status)
      const msg = err instanceof Error ? err.message : 'Failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleReset = () => {
    setCurrentStep('config')
    setCompleted([])
    setResponse(null)
    setError('')
    setHttpStatus(null)
  }

  return (
    <div className="space-y-4">
      <FlowStepper steps={STEPS} currentStep={currentStep} completedSteps={completed} />

      {currentStep === 'config' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">PKCE (Proof Key for Code Exchange) — secure flow for SPAs and mobile apps without a client secret.</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Client ID *</label>
              <input value={localClientId} onChange={(e) => setLocalClientId(e.target.value)} placeholder="public_client_id" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Redirect URI *</label>
              <input value={localRedirectUri} onChange={(e) => setLocalRedirectUri(e.target.value)} placeholder="http://localhost:3000" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Scopes</label>
              <input value={localScopes} onChange={(e) => setLocalScopes(e.target.value)} placeholder="openid profile email" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
            <div className="flex items-end gap-2">
              <div className="flex-1">
                <label className="block mb-1 text-xs font-medium text-text-muted">State</label>
                <input value={localState} onChange={(e) => setLocalState(e.target.value)} className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary focus:border-brand-violet focus:outline-none" />
              </div>
              <button onClick={() => setLocalState(generateState())} className="rounded-xl bg-surface-2 px-3 py-2.5 text-text-muted hover:text-text-secondary" title="Regenerate"><RefreshCw size={14} /></button>
            </div>
          </div>
          <button onClick={handleConfigNext} disabled={!localClientId || !localRedirectUri} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50">
            Next <ArrowRight size={16} />
          </button>
        </div>
      )}

      {currentStep === 'pkce' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">Generate a cryptographically secure code verifier and its SHA-256 challenge.</p>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Code Verifier (auto-generated)</label>
            <input value={localVerifier} readOnly className="w-full rounded-xl border border-surface-2 bg-surface-2/50 py-2.5 px-3 font-mono text-xs text-text-secondary focus:outline-none" />
          </div>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Code Challenge (SHA-256)</label>
            <input value={localChallenge} readOnly className="w-full rounded-xl border border-surface-2 bg-surface-2/50 py-2.5 px-3 font-mono text-xs text-text-secondary focus:outline-none" />
          </div>
          <button onClick={handleGeneratePkce} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02]">
            Generate PKCE & Continue <ArrowRight size={16} />
          </button>
        </div>
      )}

      {currentStep === 'authorize' && (
        <div className="space-y-3">
          <div className="rounded-xl border border-surface-2 bg-surface-2/50 p-4 space-y-3">
            <code className="block break-all text-xs font-mono text-text-secondary">{authUrl}</code>
            <div className="flex gap-2">
              <a href={authUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1.5 rounded-lg bg-brand-violet/20 px-3 py-1.5 text-xs font-medium text-brand-violet hover:bg-brand-violet/30">
                <ExternalLink size={14} /> Open in Browser
              </a>
            </div>
          </div>
          <button onClick={() => { setCompleted(['config', 'pkce', 'authorize']); setCurrentStep('exchange') }} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02]">
            I have the code <ArrowRight size={16} />
          </button>
        </div>
      )}

      {currentStep === 'exchange' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">Paste the full callback URL to validate state automatically, or enter only the code for compatibility.</p>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Callback URL</label>
            <input value={callbackUrl} onChange={(e) => setCallbackUrl(e.target.value)} placeholder={`${localRedirectUri}?code=...&state=...`} data-testid="pkce-callback-url" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
          </div>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Authorization Code *</label>
            <input value={localCode} onChange={(e) => { setLocalCode(e.target.value); setCallbackUrl('') }} placeholder="Paste code from callback" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
          </div>
          <button onClick={handleExchangeCode} disabled={loading || (!localCode && !callbackUrl.trim())} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50">
            {loading ? <Loader2 size={16} className="animate-spin" /> : <ArrowRight size={16} />}
            Exchange Code
          </button>
        </div>
      )}

      {currentStep === 'tokens' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 p-3 rounded-xl bg-semantic-success/10 border border-semantic-success/20">
            <span className="text-xs text-semantic-success">Tokens obtained via PKCE. Use them in any other flow.</span>
          </div>
          <button onClick={handleReset} className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-3">
            <RefreshCw size={16} /> Start Over
          </button>
        </div>
      )}

      <ResponsePanel response={response} status={httpStatus} error={error} loading={loading} />
    </div>
  )
}
