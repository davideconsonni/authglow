import { useState } from 'react'
import { ArrowRight, ExternalLink, Loader2, RefreshCw } from 'lucide-react'
import { api } from '@/lib/api'
import { usePlaygroundStore, generateState } from '@/stores/playgroundStore'
import { FlowStepper } from '../FlowStepper'
import { ResponsePanel } from '../ResponsePanel'

const STEPS = [
  { id: 'config', label: 'Configure' },
  { id: 'authorize', label: 'Authorize' },
  { id: 'code', label: 'Exchange Code' },
  { id: 'tokens', label: 'Tokens' },
]

export function AuthorizationCodeFlow() {
  const store = usePlaygroundStore()

  const [currentStep, setCurrentStep] = useState('config')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const [localClientId, setLocalClientId] = useState(store.clientId)
  const [localClientSecret, setLocalClientSecret] = useState(store.clientSecret)
  const [localRedirectUri, setLocalRedirectUri] = useState(store.redirectUri)
  const [localScopes, setLocalScopes] = useState(store.scopes)
  const [localState, setLocalState] = useState(store.state)
  const [localCode, setLocalCode] = useState(store.authCode)

  const authUrl = (() => {
    if (!localClientId || !localRedirectUri) return ''
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: localClientId,
      redirect_uri: localRedirectUri,
      scope: localScopes,
      state: localState,
    })
    return `${window.location.origin}/oauth2/authorize?${params.toString()}`
  })()

  const handleConfigNext = () => {
    store.setClientId(localClientId)
    store.setClientSecret(localClientSecret)
    store.setRedirectUri(localRedirectUri)
    store.setScopes(localScopes)
    store.setState(localState)
    setCompleted(['config'])
    setCurrentStep('authorize')
  }

  const handleAuthorizeNext = () => {
    setCompleted(['config', 'authorize'])
    setCurrentStep('code')
  }

  const handleExchangeCode = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      const formBody: Record<string, string> = {
        grant_type: 'authorization_code',
        code: localCode,
        redirect_uri: localRedirectUri,
      }
      if (localClientId) formBody.client_id = localClientId
      if (localClientSecret) formBody.client_secret = localClientSecret

      const result = await api.postForm('/oauth2/token', formBody)
      const r = result as Record<string, unknown>

      store.persistTokens(
        (r.access_token as string) || '',
        (r.refresh_token as string) || '',
        (r.id_token as string) || '',
      )
      setLocalCode(store.authCode)

      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
      setCompleted(['config', 'authorize', 'code'])
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
          <p className="text-xs text-text-muted">
            Configure the OAuth2 client parameters for the Authorization Code flow.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Client ID *</label>
              <input value={localClientId} onChange={(e) => setLocalClientId(e.target.value)} placeholder="your_client_id" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Client Secret</label>
              <input value={localClientSecret} onChange={(e) => setLocalClientSecret(e.target.value)} type="password" autoComplete="off" placeholder="secret" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
          </div>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Redirect URI *</label>
            <input value={localRedirectUri} onChange={(e) => setLocalRedirectUri(e.target.value)} placeholder="http://localhost:3000/callback" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
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
              <button onClick={() => setLocalState(generateState())} className="rounded-xl bg-surface-2 px-3 py-2.5 text-text-muted hover:text-text-secondary" title="Regenerate state"><RefreshCw size={14} /></button>
            </div>
          </div>
          <button onClick={handleConfigNext} disabled={!localClientId || !localRedirectUri} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50">
            Next <ArrowRight size={16} />
          </button>
        </div>
      )}

      {currentStep === 'authorize' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">
            Open this URL in a browser to authenticate. After approval you'll be redirected to the callback with a <code className="text-brand-violet">?code=...</code> parameter.
          </p>
          <div className="rounded-xl border border-surface-2 bg-surface-2/50 p-4 space-y-3">
            <code className="block break-all text-xs font-mono text-text-secondary">
              {authUrl}
            </code>
            <div className="flex gap-2">
              <a
                href={authUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 rounded-lg bg-brand-violet/20 px-3 py-1.5 text-xs font-medium text-brand-violet hover:bg-brand-violet/30"
              >
                <ExternalLink size={14} /> Open in Browser
              </a>
            </div>
          </div>
          <button onClick={handleAuthorizeNext} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02]">
            I have the code <ArrowRight size={16} />
          </button>
        </div>
      )}

      {currentStep === 'code' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">
            Paste the authorization code received in the callback redirect.
          </p>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Authorization Code *</label>
            <input value={localCode} onChange={(e) => { setLocalCode(e.target.value); store.setAuthCode(e.target.value) }} placeholder="Paste the code from ?code=..." className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
          </div>
          <button
            onClick={handleExchangeCode}
            disabled={loading || !localCode}
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <ArrowRight size={16} />}
            Exchange Code for Tokens
          </button>
        </div>
      )}

      {currentStep === 'tokens' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 p-3 rounded-xl bg-semantic-success/10 border border-semantic-success/20">
            <span className="text-xs text-semantic-success">Tokens obtained and auto-saved. Use them in any other flow.</span>
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
