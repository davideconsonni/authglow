import { useState } from 'react'
import { ArrowRight, Loader2, RefreshCw } from 'lucide-react'
import { api } from '@/lib/api'
import { usePlaygroundStore } from '@/stores/playgroundStore'
import { FlowStepper } from '../FlowStepper'
import { ResponsePanel } from '../ResponsePanel'

const STEPS = [
  { id: 'config', label: 'Configure' },
  { id: 'request', label: 'Request Token' },
  { id: 'result', label: 'Token' },
]

export function ClientCredentialsFlow() {
  const store = usePlaygroundStore()

  const [currentStep, setCurrentStep] = useState('config')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const [localClientId, setLocalClientId] = useState(store.clientId)
  const [localClientSecret, setLocalClientSecret] = useState(store.clientSecret)
  const [localScopes, setLocalScopes] = useState(store.scopes)

  const handleConfigNext = () => {
    store.setClientId(localClientId)
    store.setClientSecret(localClientSecret)
    store.setScopes(localScopes)
    setCompleted(['config'])
    setCurrentStep('request')
  }

  const handleRequest = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      const formBody: Record<string, string> = {
        grant_type: 'client_credentials',
        scope: localScopes,
      }
      const headers: Record<string, string> = {}
      if (localClientId && localClientSecret) {
        headers['Authorization'] = 'Basic ' + btoa(`${localClientId}:${localClientSecret}`)
      }

      const result = await api.postForm('/oauth2/token', formBody, { headers })
      const r = result as Record<string, unknown>
      store.setAccessToken((r.access_token as string) || '')

      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
      setCompleted(['config', 'request'])
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
            Machine-to-machine authentication. No user interaction required.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Client ID *</label>
              <input value={localClientId} onChange={(e) => setLocalClientId(e.target.value)} placeholder="your_client_id" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Client Secret *</label>
              <input value={localClientSecret} onChange={(e) => setLocalClientSecret(e.target.value)} type="password" autoComplete="off" placeholder="secret" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
            </div>
          </div>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Scopes</label>
            <input value={localScopes} onChange={(e) => setLocalScopes(e.target.value)} placeholder="read write" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
          </div>
          <button onClick={handleConfigNext} disabled={!localClientId || !localClientSecret} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50">
            Next <ArrowRight size={16} />
          </button>
        </div>
      )}

      {currentStep === 'request' && (
        <div className="space-y-3">
          <div className="rounded-xl border border-surface-2 bg-surface-2/50 p-4 space-y-1">
            <code className="block text-xs font-mono text-text-secondary">POST /oauth2/token</code>
            <code className="block text-xs font-mono text-text-muted">grant_type=client_credentials</code>
            <code className="block text-xs font-mono text-text-muted">scope={localScopes}</code>
            <code className="block text-xs font-mono text-text-muted">Authorization: Basic ...</code>
          </div>
          <button
            onClick={handleRequest}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <ArrowRight size={16} />}
            Request Token
          </button>
        </div>
      )}

      {currentStep === 'result' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 p-3 rounded-xl bg-semantic-success/10 border border-semantic-success/20">
            <span className="text-xs text-semantic-success">Access token obtained. Switch to Introspection or UserInfo to use it.</span>
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
