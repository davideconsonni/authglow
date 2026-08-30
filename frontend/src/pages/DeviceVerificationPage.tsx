import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Loader2, XCircle, Smartphone } from 'lucide-react'
import { SealStamp } from '../components/shared/SealStamp'
import { api } from '../lib/api'
import { useAuth } from '../hooks/useAuth'
import { ROUTES } from '../lib/constants'
import { useDocumentTitle } from '../hooks/useDocumentTitle'

interface DeviceInfo {
  client_id: string
  scopes: string[]
  expires_at: string
}

type Step = 'input' | 'review' | 'result'

export function DeviceVerificationPage() {
  useDocumentTitle('Device Verification')
  const { isAuthenticated, isLoading } = useAuth()
  const [searchParams] = useSearchParams()

  const [userCode, setUserCode] = useState('')
  const [step, setStep] = useState<Step>('input')
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfo | null>(null)
  const [error, setError] = useState('')
  const [result, setResult] = useState<'approved' | 'denied' | ''>('')
  const [submitting, setSubmitting] = useState(false)

  const prefilledCode = searchParams.get('user_code') ?? ''

  useEffect(() => {
    if (prefilledCode) {
      setUserCode(prefilledCode)
      handleLookup(prefilledCode)
    }
  }, [])

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg-primary">
        <Loader2 className="h-8 w-8 animate-spin text-brand-accent" />
      </div>
    )
  }

  if (!isAuthenticated) {
    const loginPath = `${ROUTES.AUTH.LOGIN}?redirect=${encodeURIComponent(ROUTES.OAUTH_DEVICE_VERIFY)}`
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
        <div className="w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-8 text-center space-y-4">
          <div className="icon-chip mx-auto flex h-14 w-14 items-center justify-center rounded-2xl">
            <Smartphone className="h-7 w-7" />
          </div>
          <h2 className="text-xl font-semibold text-text-primary">Device Verification</h2>
          <p className="text-sm text-text-muted">Sign in to verify a device code.</p>
          <a
            href={loginPath}
            className="inline-flex items-center justify-center rounded-xl bg-gradient-cta px-6 py-2.5 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            Sign In
          </a>
        </div>
      </div>
    )
  }

  function cleanCode(raw: string) {
    return raw.trim().toUpperCase().replace(/\s/g, '')
  }

  async function handleLookup(code?: string) {
    const lookupCode = cleanCode(code || userCode)
    if (!lookupCode) {
      setError('Enter a code')
      return
    }
    setError('')
    setSubmitting(true)
    try {
      const data = await api.post<DeviceInfo>('/api/oauth2/device/verify', {
        user_code: lookupCode,
      })
      setDeviceInfo(data)
      setStep('review')
    } catch {
      setError('Invalid or expired code')
    } finally {
      setSubmitting(false)
    }
  }

  async function handleApprove() {
    setSubmitting(true)
    try {
      await api.post('/api/oauth2/device/approve', {
        user_code: cleanCode(userCode),
      })
      setResult('approved')
      setStep('result')
    } catch {
      setError('Failed to approve')
    } finally {
      setSubmitting(false)
    }
  }

  async function handleDeny() {
    setSubmitting(true)
    try {
      await api.post('/api/oauth2/device/deny', {
        user_code: cleanCode(userCode),
      })
      setResult('denied')
      setStep('result')
    } catch {
      setError('Failed to deny')
    } finally {
      setSubmitting(false)
    }
  }

  if (step === 'result') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
        <div className="w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-8 text-center space-y-4">
          {result === 'approved' ? (
            <>
              <SealStamp className="mx-auto h-14 w-14" />
              <h2 className="text-xl font-semibold text-text-primary">Device Authorized</h2>
              <p className="text-sm text-text-muted">You can return to your device now.</p>
            </>
          ) : (
            <>
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-error/10">
                <XCircle className="h-7 w-7 text-semantic-error" />
              </div>
              <h2 className="text-xl font-semibold text-text-primary">Access Denied</h2>
              <p className="text-sm text-text-muted">The device request was denied.</p>
            </>
          )}
          <button
            onClick={() => { setStep('input'); setUserCode(''); setResult('') }}
            className="inline-flex items-center justify-center rounded-xl bg-gradient-cta px-6 py-2.5 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            Verify another code
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center space-y-3">
          <div className="icon-chip mx-auto flex h-14 w-14 items-center justify-center rounded-2xl">
            <Smartphone className="h-7 w-7" />
          </div>
          <h1 className="text-2xl font-bold text-text-primary">Device Verification</h1>
        </div>

        {step === 'input' && (
          <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
            <p className="text-sm text-text-muted">
              Enter the code shown on your device to authorize it.
            </p>
            <input
              type="text"
              value={userCode}
              onChange={(e) => setUserCode(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
              placeholder="ABCD-EFGH"
              className="w-full rounded-xl border border-surface-2 bg-surface-2 px-4 py-3 text-center text-lg font-mono tracking-widest text-text-primary placeholder:text-text-muted/50 focus:border-brand-accent focus:outline-none focus:ring-1 focus:ring-brand-accent uppercase"
              maxLength={9}
            />
            {error && <p className="text-sm text-semantic-error" role="alert">{error}</p>}
            <button
              onClick={() => handleLookup()}
              disabled={submitting || !userCode.trim()}
              className="w-full inline-flex items-center justify-center rounded-xl bg-gradient-cta px-6 py-3 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Verify Code
            </button>
          </div>
        )}

        {step === 'review' && deviceInfo && (
          <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
            <div>
              <h3 className="text-sm font-medium text-text-muted">Application</h3>
              <p className="text-text-primary font-semibold">{deviceInfo.client_id}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-text-muted">Requested access</h3>
              <div className="flex flex-wrap gap-2 mt-1">
                {deviceInfo.scopes.map((scope) => (
                  <span
                    key={scope}
                    className="inline-flex items-center rounded-lg bg-surface-2 px-2.5 py-1 text-xs font-medium text-text-secondary"
                  >
                    {scope}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <h3 className="text-sm font-medium text-text-muted">Code</h3>
              <p className="text-text-primary font-mono text-lg tracking-widest">{cleanCode(userCode)}</p>
            </div>
            {error && <p className="text-sm text-semantic-error" role="alert">{error}</p>}
            <div className="flex gap-3">
              <button
                onClick={handleDeny}
                disabled={submitting}
                className="flex-1 inline-flex items-center justify-center rounded-xl border border-surface-2 bg-surface-2 px-4 py-3 text-sm font-semibold text-text-primary transition-all hover:bg-surface-3 disabled:opacity-50"
              >
                Deny
              </button>
              <button
                onClick={handleApprove}
                disabled={submitting}
                className="flex-1 inline-flex items-center justify-center rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50"
              >
                {submitting ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                Approve
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
