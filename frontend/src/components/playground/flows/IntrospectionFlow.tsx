import { useState } from 'react'
import { Eye, Loader2, RefreshCw } from 'lucide-react'
import { api } from '@/lib/api'
import { usePlaygroundStore } from '@/stores/playgroundStore'
import { FlowStepper } from '../FlowStepper'
import { ResponsePanel } from '../ResponsePanel'

const STEPS = [
  { id: 'input', label: 'Token' },
  { id: 'auth', label: 'Client Auth' },
  { id: 'result', label: 'Result' },
]

export function IntrospectionFlow() {
  const store = usePlaygroundStore()

  const [currentStep, setCurrentStep] = useState('input')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const [localToken, setLocalToken] = useState(store.accessToken)
  const [localHint, setLocalHint] = useState('')
  const [localClientId, setLocalClientId] = useState(store.clientId)
  const [localClientSecret, setLocalClientSecret] = useState(store.clientSecret)

  const handleInputNext = () => {
    store.setAccessToken(localToken)
    setCompleted(['input'])
    setCurrentStep('auth')
  }

  const handleIntrospect = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      const formBody: Record<string, string> = { token: localToken }
      if (localHint) formBody.token_type_hint = localHint
      const headers: Record<string, string> = {}
      if (localClientId && localClientSecret) {
        headers['Authorization'] = 'Basic ' + btoa(`${localClientId}:${localClientSecret}`)
      }

      const result = await api.postForm('/oauth2/introspect', formBody, { headers })
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
      setCompleted(['input', 'auth'])
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
            RFC 7662 — Token introspection. {store.accessToken ? 'Access token auto-filled from previous flow.' : 'Paste the token to introspect.'}
          </p>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Token *</label>
            <textarea value={localToken} onChange={(e) => setLocalToken(e.target.value)} placeholder="eyJhbGciOiJSUzI1NiIs..." rows={4} className="w-full rounded-xl border border-surface-2 bg-surface-1 p-3 font-mono text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none resize-y" />
          </div>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Token Type Hint</label>
            <select value={localHint} onChange={(e) => setLocalHint(e.target.value)} className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 text-sm text-text-primary focus:border-brand-violet focus:outline-none">
              <option value="">Auto-detect</option>
              <option value="access_token">Access Token</option>
              <option value="refresh_token">Refresh Token</option>
            </select>
          </div>
          <button onClick={handleInputNext} disabled={!localToken} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50">
            Next <Eye size={16} />
          </button>
        </div>
      )}

      {currentStep === 'auth' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">Client authentication via Basic Auth header. Required by the introspection endpoint.</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Client ID</label>
              <input value={localClientId} onChange={(e) => setLocalClientId(e.target.value)} placeholder="client_id" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Client Secret</label>
              <input value={localClientSecret} onChange={(e) => setLocalClientSecret(e.target.value)} type="password" autoComplete="off" placeholder="secret" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
          </div>
          <button onClick={handleIntrospect} disabled={loading} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50">
            {loading ? <Loader2 size={16} className="animate-spin" /> : <Eye size={16} />}
            Introspect Token
          </button>
        </div>
      )}

      {currentStep === 'result' && (
        <div className="space-y-3">
          <button onClick={handleReset} className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-3">
            <RefreshCw size={16} /> Introspect Another Token
          </button>
        </div>
      )}

      <ResponsePanel response={response} status={httpStatus} error={error} loading={loading} />
    </div>
  )
}
