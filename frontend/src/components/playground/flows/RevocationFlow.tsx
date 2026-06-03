import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Trash2, Loader2, RefreshCw } from 'lucide-react'
import { api } from '@/lib/api'
import { decodeJwt } from '@/lib/jwt'
import { usePlaygroundStore } from '@/stores/playgroundStore'
import { FlowStepper } from '../FlowStepper'
import { JsonHighlight } from '../JsonHighlight'
import { ResponsePanel } from '../ResponsePanel'

const STEPS = [
  { id: 'input', label: 'Token' },
  { id: 'confirm', label: 'Confirm' },
  { id: 'done', label: 'Done' },
]

export function RevocationFlow() {
  const store = usePlaygroundStore()

  const [currentStep, setCurrentStep] = useState('input')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const [localToken, setLocalToken] = useState(store.accessToken || store.refreshToken)
  const [localHint, setLocalHint] = useState('')

  const decodedClaims = useMemo(() => decodeJwt(localToken), [localToken])
  const [showDecoded, setShowDecoded] = useState(true)

  const handleInputNext = () => {
    setCompleted(['input'])
    setCurrentStep('confirm')
  }

  const handleRevoke = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      const formBody: Record<string, string> = { token: localToken }
      if (localHint) formBody.token_type_hint = localHint

      await api.postForm('/oauth2/revoke', formBody)
      setHttpStatus(200)
      setResponse('{} (Token revoked — empty 200 response per RFC 7009)')
      setCompleted(['input', 'confirm'])
      setCurrentStep('done')
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
            RFC 7009 — Revoke an access or refresh token. Per spec, always returns 200 OK.
          </p>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Token to Revoke *</label>
            <textarea value={localToken} onChange={(e) => setLocalToken(e.target.value)} placeholder="Paste the token to revoke..." rows={4} className="w-full rounded-xl border border-surface-2 bg-surface-1 p-3 font-mono text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none resize-y" />
          </div>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Token Type Hint</label>
            <select value={localHint} onChange={(e) => setLocalHint(e.target.value)} className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 text-sm text-text-primary focus:border-brand-violet focus:outline-none">
              <option value="">Auto-detect</option>
              <option value="access_token">Access Token</option>
              <option value="refresh_token">Refresh Token</option>
            </select>
          </div>
          {decodedClaims && (
            <div className="rounded-xl border border-surface-2 bg-surface-1 overflow-hidden">
              <button
                onClick={() => setShowDecoded(!showDecoded)}
                className="flex items-center gap-2 w-full px-3 py-2 text-xs font-medium text-text-secondary hover:text-text-primary transition-colors"
              >
                {showDecoded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                Decoded Claims
              </button>
              {showDecoded && (
                <div className="border-t border-surface-2">
                  <div className="px-3 py-2 border-b border-surface-2">
                    <p className="text-[11px] font-medium text-text-muted mb-1">Header</p>
                    <JsonHighlight json={JSON.stringify(decodedClaims.header, null, 2)} maxHeight="max-h-[160px]" />
                  </div>
                  <div className="px-3 py-2">
                    <p className="text-[11px] font-medium text-text-muted mb-1">Payload</p>
                    <JsonHighlight json={JSON.stringify(decodedClaims.payload, null, 2)} maxHeight="max-h-[240px]" />
                  </div>
                </div>
              )}
            </div>
          )}
          <button onClick={handleInputNext} disabled={!localToken} className="flex items-center gap-2 rounded-xl bg-semantic-error px-4 py-2 text-sm font-semibold text-white hover:scale-[1.02] disabled:opacity-50">
            Next <Trash2 size={16} />
          </button>
        </div>
      )}

      {currentStep === 'confirm' && (
        <div className="space-y-3">
          <div className="rounded-xl border border-surface-2 bg-surface-2/50 p-4 space-y-1">
            <p className="text-xs text-text-secondary">
              You are about to revoke this token. This action cannot be undone.
            </p>
            <code className="block text-xs font-mono text-text-muted truncate">
              {localToken.slice(0, 50)}...
            </code>
          </div>
          <div className="flex gap-3">
            <button onClick={() => setCurrentStep('input')} className="rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2">
              Back
            </button>
            <button onClick={handleRevoke} disabled={loading} data-testid="confirm-revoke-btn" className="flex items-center gap-2 rounded-xl bg-semantic-error px-4 py-2 text-sm font-semibold text-white hover:scale-[1.02] disabled:opacity-50">
              {loading ? <Loader2 size={16} className="animate-spin" /> : <Trash2 size={16} />}
              Confirm Revocation
            </button>
          </div>
        </div>
      )}

      {currentStep === 'done' && (
        <div className="space-y-3">
          <div className="flex items-center gap-3 p-3 rounded-xl bg-semantic-warning/10 border border-semantic-warning/20">
            <span className="text-xs text-semantic-warning">Token has been revoked.</span>
          </div>
          <button onClick={handleReset} className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-3">
            <RefreshCw size={16} /> Revoke Another
          </button>
        </div>
      )}

      <ResponsePanel response={response} status={httpStatus} error={error} loading={loading} />
    </div>
  )
}
