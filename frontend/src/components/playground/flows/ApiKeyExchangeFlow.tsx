import { useState } from 'react'
import { Key, Loader2, RefreshCw } from 'lucide-react'
import { api } from '../../../lib/api'
import { usePlaygroundStore } from '../../../stores/playgroundStore'
import { FlowStepper } from '../FlowStepper'
import { ResponsePanel } from '../ResponsePanel'

const STEPS = [
  { id: 'input', label: 'API Key' },
  { id: 'result', label: 'Tokens' },
]

export function ApiKeyExchangeFlow() {
  const store = usePlaygroundStore()

  const [currentStep, setCurrentStep] = useState('input')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const [localApiKey, setLocalApiKey] = useState(store.apiKey)

  const handleExchange = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    store.setApiKey(localApiKey)
    try {
      const headers: Record<string, string> = {
        'Authorization': `Bearer ${localApiKey}`,
      }
      const result = await api.post('/api/token/api-key', undefined, { headers })
      const r = result as Record<string, unknown>
      store.persistTokens(
        (r.access_token as string) || '',
        (r.refresh_token as string) || '',
        (r.id_token as string) || '',
      )

      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
      setCompleted(['input'])
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
            Exchange an API key for a short-lived JWT access token.
          </p>
          <div className="flex items-center gap-3 p-3 rounded-xl bg-surface-2/50 border border-surface-2">
            <code className="text-xs font-mono text-text-secondary">POST /api/token/api-key</code>
            <code className="text-xs text-text-muted">Authorization: Bearer &lt;api_key&gt;</code>
          </div>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">API Key *</label>
            <input
              value={localApiKey}
              onChange={(e) => setLocalApiKey(e.target.value)}
              type="password" autoComplete="off"
              placeholder="ak_..."
              className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
            />
          </div>
          <button
            onClick={handleExchange}
            disabled={loading || !localApiKey}
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent hover:scale-[1.02] btn-cta"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <Key size={16} />}
            Exchange API Key
          </button>
        </div>
      )}

      {currentStep === 'result' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 p-3 rounded-xl bg-semantic-success/10 border border-semantic-success/20">
            <span className="text-xs text-semantic-success">Tokens obtained. Use them in other flows.</span>
          </div>
          <button onClick={handleReset} className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-3">
            <RefreshCw size={16} /> Exchange Another Key
          </button>
        </div>
      )}

      <ResponsePanel response={response} status={httpStatus} error={error} loading={loading} />
    </div>
  )
}
