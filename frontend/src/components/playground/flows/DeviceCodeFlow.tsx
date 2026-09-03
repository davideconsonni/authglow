import { useState, useEffect, useRef } from 'react'
import { ArrowRight, Loader2, RefreshCw, Copy, Check } from 'lucide-react'
import { api } from '../../../lib/api'
import { usePlaygroundStore } from '../../../stores/playgroundStore'
import { FlowStepper } from '../FlowStepper'
import { ResponsePanel } from '../ResponsePanel'
import { ScopePicker } from '../../shared/ScopePicker'

const STEPS = [
  { id: 'config', label: 'Configure' },
  { id: 'request', label: 'Request' },
  { id: 'display', label: 'Display' },
  { id: 'verify', label: 'Verify' },
  { id: 'poll', label: 'Poll & Token' },
]

interface DeviceAuthResponse {
  device_code: string
  user_code: string
  verification_uri: string
  verification_uri_complete?: string
  expires_in: number
  interval: number
}

export function DeviceCodeFlow() {
  const store = usePlaygroundStore()

  const [currentStep, setCurrentStep] = useState('config')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const [localClientId, setLocalClientId] = useState(store.clientId)
  const [localScopes, setLocalScopes] = useState(store.scopes)

  const [deviceAuth, setDeviceAuth] = useState<DeviceAuthResponse | null>(null)
  const [copied, setCopied] = useState(false)
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current)
    }
  }, [])

  const handleRequest = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      const formBody: Record<string, string> = {}
      if (localClientId) formBody.client_id = localClientId
      if (localScopes) formBody.scope = localScopes.replace(/\s+/g, ' ').trim()

      const result = await api.postForm('/oauth2/device/authorize', formBody)
      const da = result as DeviceAuthResponse
      setDeviceAuth(da)
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
      setCompleted(['config', 'request'])
      setCurrentStep('display')
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) setHttpStatus((err as { status: number }).status)
      const msg = err instanceof Error ? err.message : 'Failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async () => {
    if (!deviceAuth) return
    setLoading(true)
    setError('')
    try {
      // Step 1: Lookup user_code
      await api.post('/api/oauth2/device/verify', {
        user_code: deviceAuth.user_code,
      })
      // Step 2: Approve
      await api.post('/api/oauth2/device/approve', {
        user_code: deviceAuth.user_code,
      })
      setCompleted(['config', 'request', 'display', 'verify'])
      setCurrentStep('poll')
      setHttpStatus(200)
      setResponse(JSON.stringify({ status: 'approved', user_code: deviceAuth.user_code }, null, 2))
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) setHttpStatus((err as { status: number }).status)
      const msg = err instanceof Error ? err.message : 'Failed to approve'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleStartPolling = () => {
    if (!deviceAuth) return
    const intervalMs = (deviceAuth.interval || 5) * 1000
    let attempts = 0

    const poll = async () => {
      attempts++
      setLoading(true)
      setError('')
      try {
        const formBody: Record<string, string> = {
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: deviceAuth.device_code,
        }
        if (localClientId) formBody.client_id = localClientId

        const result = await api.postForm('/oauth2/token', formBody)
        const r = result as Record<string, unknown>
        store.persistTokens(
          (r.access_token as string) || '',
          (r.refresh_token as string) || '',
          (r.id_token as string) || '',
        )
        setHttpStatus(200)
        setResponse(JSON.stringify(result, null, 2))
        setCompleted(['config', 'request', 'display', 'verify', 'poll'])
        if (pollingRef.current) clearInterval(pollingRef.current)
      } catch (err: unknown) {
        if (err instanceof Error && 'status' in err) {
          const status = (err as { status: number }).status
          setHttpStatus(status)
          if (status === 400) {
            // authorization_pending or slow_down — keep polling
            setResponse(JSON.stringify({ status: 'pending', attempt: attempts }, null, 2))
            return
          }
          // Other errors — stop polling
          if (pollingRef.current) clearInterval(pollingRef.current)
          setError(err.message)
          setResponse(JSON.stringify({ error: err.message, attempt: attempts }, null, 2))
        }
      } finally {
        setLoading(false)
      }
    }

    // Poll immediately then at interval
    poll()
    pollingRef.current = setInterval(poll, intervalMs)
  }

  const handleReset = () => {
    if (pollingRef.current) clearInterval(pollingRef.current)
    setCurrentStep('config')
    setCompleted([])
    setResponse(null)
    setError('')
    setHttpStatus(null)
    setDeviceAuth(null)
  }

  return (
    <div className="space-y-4">
      <FlowStepper steps={STEPS} currentStep={currentStep} completedSteps={completed} />

      {currentStep === 'config' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">RFC 8628 — Device Authorization Grant. For TVs, CLIs, and input-constrained devices.</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Client ID</label>
              <input value={localClientId} onChange={(e) => setLocalClientId(e.target.value)} placeholder="your-client-id" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none" />
            </div>
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Scopes</label>
              <ScopePicker value={localScopes} onChange={setLocalScopes} placeholder="Add custom scope" />
            </div>
          </div>
          <button onClick={() => { store.setClientId(localClientId); store.setScopes(localScopes); setCompleted(['config']); setCurrentStep('request') }} disabled={!localClientId} className="btn-cta flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent hover:scale-[1.02]">
            Next <ArrowRight size={16} />
          </button>
        </div>
      )}

      {currentStep === 'request' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">Send the device authorization request. This creates a device_code and user_code.</p>
          <button onClick={handleRequest} disabled={loading} className="btn-cta flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent hover:scale-[1.02]">
            {loading ? <Loader2 size={16} className="animate-spin" /> : <ArrowRight size={16} />}
            Request Device Code
          </button>
        </div>
      )}

      {currentStep === 'display' && deviceAuth && (
        <div className="space-y-4">
          <p className="text-xs text-text-muted">Show this code to the user. They should visit the verification URL and enter it.</p>
          <div className="rounded-xl border border-surface-2 bg-surface-1 p-4 space-y-3">
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">User Code</label>
              <div className="flex items-center gap-2">
                <code className="flex-1 rounded-lg bg-surface-2 px-4 py-3 text-center text-2xl font-bold tracking-[0.5em] text-brand-accent font-mono">{deviceAuth.user_code}</code>
                <button
                  onClick={() => { navigator.clipboard.writeText(deviceAuth.user_code); setCopied(true); setTimeout(() => setCopied(false), 2000) }}
                  className="rounded-lg bg-surface-2 p-3 text-text-muted hover:text-text-secondary transition-colors"
                  title="Copy user code"
                >
                  {copied ? <Check size={16} className="text-semantic-success" /> : <Copy size={16} />}
                </button>
              </div>
            </div>
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">Verification URI</label>
              <code className="block break-all text-xs text-text-secondary">{deviceAuth.verification_uri_complete || deviceAuth.verification_uri}</code>
            </div>
            <div className="grid grid-cols-2 gap-3 text-xs text-text-muted">
              <div>Expires: <span className="text-text-primary">{deviceAuth.expires_in}s</span></div>
              <div>Poll interval: <span className="text-text-primary">{deviceAuth.interval}s</span></div>
            </div>
          </div>
          <button onClick={() => { setCompleted(['config', 'request', 'display']); setCurrentStep('verify') }} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent hover:scale-[1.02]">
            Next: Verify <ArrowRight size={16} />
          </button>
        </div>
      )}

      {currentStep === 'verify' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">Simulate the user approving the device authorization. (Requires an authenticated admin session.)</p>
          <button onClick={handleVerify} disabled={loading} className="btn-cta flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent hover:scale-[1.02]">
            {loading ? <Loader2 size={16} className="animate-spin" /> : <ArrowRight size={16} />}
            Approve Device
          </button>
        </div>
      )}

      {currentStep === 'poll' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">Start polling the token endpoint until the device is authorized or the code expires.</p>
          <button onClick={handleStartPolling} disabled={loading} className="btn-cta flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent hover:scale-[1.02]">
            {loading ? <Loader2 size={16} className="animate-spin" /> : <ArrowRight size={16} />}
            Start Polling
          </button>
          {completed.includes('poll') && (
            <div className="flex items-center gap-3 p-3 rounded-xl bg-semantic-success/10 border border-semantic-success/20">
              <span className="text-xs text-semantic-success">Tokens obtained via Device Code. Use them in any other flow.</span>
            </div>
          )}
        </div>
      )}

      {completed.includes('poll') || completed.includes('verify') ? (
        <button onClick={handleReset} className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-3">
          <RefreshCw size={16} /> Start Over
        </button>
      ) : null}

      <ResponsePanel response={response} status={httpStatus} error={error} loading={loading} />
    </div>
  )
}
