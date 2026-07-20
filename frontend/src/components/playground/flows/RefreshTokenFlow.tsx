import { useState } from 'react'
import { ArrowRight, Loader2, RefreshCw } from 'lucide-react'
import { api } from '../../../lib/api'
import { usePlaygroundStore } from '../../../stores/playgroundStore'
import { FlowStepper } from '../FlowStepper'
import { ResponsePanel } from '../ResponsePanel'

const STEPS = [
  { id: 'input', label: 'Token Input' },
  { id: 'request', label: 'Request' },
  { id: 'result', label: 'New Tokens' },
]

export function RefreshTokenFlow() {
  const store = usePlaygroundStore()

  const [currentStep, setCurrentStep] = useState('input')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const [localToken, setLocalToken] = useState(store.refreshToken)
  const [localClientId, setLocalClientId] = useState(store.clientId)
  const [localClientSecret, setLocalClientSecret] = useState(store.clientSecret)

  const handleGo = async () => {
    store.setRefreshToken(localToken)
    store.setClientId(localClientId)
    store.setClientSecret(localClientSecret)
    setCompleted(['input'])
    setCurrentStep('request')
  }

  const handleRequest = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      const formBody: Record<string, string> = {
        grant_type: 'refresh_token',
        refresh_token: localToken,
      }
      const headers: Record<string, string> = {}
      if (localClientId && localClientSecret) {
        headers['Authorization'] = 'Basic ' + btoa(`${localClientId}:${localClientSecret}`)
      }

      const result = await api.postForm('/oauth2/token', formBody, { headers })
      const r = result as Record<string, unknown>
      store.persistTokens(
        (r.access_token as string) || '',
        (r.refresh_token as string) || '',
        (r.id_token as string) || '',
      )

      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
      setCompleted(['input', 'request'])
      setCurrentStep('result')
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
    setCurrentStep('input')
    setCompleted([])
    setResponse(null)
    setError('')
    setHttpStatus(null)
  }

  return (
    <div className="space-y-4">
      <FlowStepper steps={STEPS} currentStep={currentStep} completedSteps={completed} />

      {currentStep === 'input' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">
            {store.refreshToken ? 'Refresh token auto-filled from previous flow.' : 'Paste the refresh token to exchange for new tokens.'}
          </p>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Refresh Token *</label>
            <textarea value={localToken} onChange={(e) => setLocalToken(e.target.value)} placeholder="Paste refresh token..." rows={3} className="w-full rounded-xl border border-surface-2 bg-surface-1 p-3 font-mono text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none resize-y" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Client ID (optional)</label>
              <input value={localClientId} onChange={(e) => setLocalClientId(e.target.value)} placeholder="client_id" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Client Secret (optional)</label>
              <input value={localClientSecret} onChange={(e) => setLocalClientSecret(e.target.value)} type="password" autoComplete="off" placeholder="secret" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
          </div>
          <button onClick={handleGo} disabled={!localToken} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50">
            Next <ArrowRight size={16} />
          </button>
        </div>
      )}

      {currentStep === 'request' && (
        <div className="space-y-3">
          <div className="rounded-xl border border-surface-2 bg-surface-2/50 p-4 space-y-1">
            <code className="block text-xs font-mono text-text-secondary">POST /oauth2/token</code>
            <code className="block text-xs font-mono text-text-muted">grant_type=refresh_token</code>
            <code className="block text-xs font-mono text-text-muted truncate">refresh_token={localToken.slice(0, 30)}...</code>
          </div>
          <button onClick={handleRequest} disabled={loading} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50">
            {loading ? <Loader2 size={16} className="animate-spin" /> : <RefreshCw size={16} />}
            Refresh Tokens
          </button>
        </div>
      )}

      {currentStep === 'result' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 p-3 rounded-xl bg-semantic-success/10 border border-semantic-success/20">
            <span className="text-xs text-semantic-success">New tokens obtained and auto-saved.</span>
          </div>
          <button onClick={handleReset} className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-3">
            <RefreshCw size={16} /> Refresh Again
          </button>
        </div>
      )}

      <ResponsePanel response={response} status={httpStatus} error={error} loading={loading} />
    </div>
  )
}
