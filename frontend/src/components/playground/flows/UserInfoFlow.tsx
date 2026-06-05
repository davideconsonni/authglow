import { useMemo, useState } from 'react'
import { Loader2, RefreshCw, User, Key, Zap } from 'lucide-react'
import { api } from '@/lib/api'
import { decodeJwt } from '@/lib/jwt'
import { usePlaygroundStore } from '@/stores/playgroundStore'
import { useAuthStore } from '@/stores/authStore'
import { useAuth } from '@/hooks/useAuth'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { FlowStepper } from '../FlowStepper'
import { JsonHighlight } from '../JsonHighlight'
import { ResponsePanel } from '../ResponsePanel'

const STEPS = [
  { id: 'token', label: 'Token' },
  { id: 'result', label: 'UserInfo' },
]

export function UserInfoFlow() {
  const store = usePlaygroundStore()
  const { user } = useAuth()

  const [currentStep, setCurrentStep] = useState('token')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const [localToken, setLocalToken] = useState(store.accessToken)

  const decodedClaims = useMemo(() => decodeJwt(localToken), [localToken])
  const [showDecoded, setShowDecoded] = useState(true)

  const handleFetch = async () => {
    store.setAccessToken(localToken)
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      const result = await api.get('/oauth2/userinfo', { headers: { Authorization: `Bearer ${localToken}` } })
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
      setCompleted(['token'])
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

  const handleUseMySession = () => {
    const token = useAuthStore.getState().accessToken
    if (token) {
      setLocalToken(token)
      store.setAccessToken(token)
    } else {
      setResponse(JSON.stringify({ info: 'No access token available. Login via password to see JWT claims. Federated login does not store tokens in browser.' }, null, 2))
      setCurrentStep('result')
    }
  }

  const handleFetchMyUserInfo = () => {
    const token = useAuthStore.getState().accessToken
    if (!token) {
      setResponse(JSON.stringify({ info: 'No access token in session. Login via password to see JWT claims.' }, null, 2))
      setCurrentStep('result')
      return
    }
    const decoded = decodeJwt(token)
    setHttpStatus(200)
    setResponse(JSON.stringify({
      header: decoded?.header,
      payload: decoded?.payload,
      permissions: decoded?.payload?.permissions,
      roles: decoded?.payload?.roles,
    }, null, 2))
    setCurrentStep('result')
  }

  const handleReset = () => {
    setCurrentStep('token')
    setCompleted([])
    setResponse(null)
    setError('')
    setHttpStatus(null)
  }

  return (
    <div className="space-y-4">
      <FlowStepper steps={STEPS} currentStep={currentStep} completedSteps={completed} />

      {currentStep === 'token' && (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">
            OpenID Connect UserInfo — Returns claims about the authenticated user.
            Requires an access token with the <code className="text-brand-violet">openid</code> scope.
          </p>
          <div>
            <label className="block mb-1 text-xs font-medium text-text-muted">Access Token *</label>
            <textarea
              value={localToken}
              onChange={(e) => setLocalToken(e.target.value)}
              placeholder="eyJhbGciOiJSUzI1NiIs..."
              rows={4}
              className="w-full rounded-xl border border-surface-2 bg-surface-1 p-3 font-mono text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none resize-y"
            />
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

          <div className="flex flex-wrap gap-2">
            <button
              onClick={handleFetch}
              disabled={loading || !localToken}
              className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <User size={16} />}
              Fetch UserInfo
            </button>
            <button
              onClick={handleFetchMyUserInfo}
              disabled={!user}
              className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm font-medium text-brand-violet hover:bg-surface-3 disabled:opacity-50"
            >
              <Zap size={16} />
              Fetch My UserInfo
            </button>
          </div>
          <p className="text-[11px] text-text-muted">
            <button onClick={handleUseMySession} className="underline hover:text-text-primary">
              Use my session token
            </button>
            {' · '}
            {user?.email || 'Not logged in'}
          </p>
        </div>
      )}

      {currentStep === 'result' && (
        <div className="space-y-3">
          <button onClick={handleReset} className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-3">
            <RefreshCw size={16} /> Fetch Another
          </button>
        </div>
      )}

      <ResponsePanel response={response} status={httpStatus} error={error} loading={loading} />
    </div>
  )
}
