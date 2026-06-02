import { useState } from 'react'
import { BookOpen, Loader2, RefreshCw } from 'lucide-react'
import { api } from '@/lib/api'
import { FlowStepper } from '../FlowStepper'
import { ResponsePanel } from '../ResponsePanel'

const STEPS = [
  { id: 'fetch', label: 'Fetch' },
  { id: 'result', label: 'Metadata' },
]

export function OidcDiscoveryFlow() {
  const [currentStep, setCurrentStep] = useState('fetch')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const handleFetch = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      const result = await api.get('/.well-known/openid-configuration')
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
      setCompleted(['fetch'])
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
    setCurrentStep('fetch')
    setCompleted([])
    setResponse(null)
    setError('')
    setHttpStatus(null)
  }

  return (
    <div className="space-y-4">
      <FlowStepper steps={STEPS} currentStep={currentStep} completedSteps={completed} />

      {currentStep === 'fetch' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">
            OpenID Connect Discovery — Returns the OIDC provider metadata including all endpoint URLs, supported scopes, response types, and cryptographic keys URI.
          </p>
          <div className="flex items-center gap-3 p-3 rounded-xl bg-surface-2/50 border border-surface-2">
            <code className="text-sm font-mono text-text-secondary">GET /.well-known/openid-configuration</code>
          </div>
          <button
            onClick={handleFetch}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <BookOpen size={16} />}
            Fetch Discovery Document
          </button>
        </div>
      )}

      {currentStep === 'result' && (
        <div className="space-y-3">
          <button onClick={handleReset} className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-3">
            <RefreshCw size={16} /> Fetch Again
          </button>
        </div>
      )}

      <ResponsePanel response={response} status={httpStatus} error={error} loading={loading} />
    </div>
  )
}
