import { useSearchParams, Link } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { MailCheck, AlertCircle, Loader2, RefreshCw } from 'lucide-react'
import { api } from '@/lib/api'
import { ROUTES } from '@/lib/constants'

export function EmailVerifiedPage() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading')

  useEffect(() => {
    if (!token) {
      setStatus('error')
      return
    }

    const verify = async () => {
      try {
        await api.post('/api/email/verify', { token })
        setStatus('success')
      } catch {
        setStatus('error')
      }
    }

    verify()
  }, [token])

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
      <div className="w-full max-w-md space-y-6 text-center">
        <h1 className="text-2xl font-bold gradient-text">AuthGlow</h1>

        {status === 'loading' && (
          <div className="space-y-4">
            <Loader2 className="mx-auto h-8 w-8 animate-spin text-brand-violet" />
            <h2 className="text-xl font-semibold text-text-primary">Verifying your email...</h2>
          </div>
        )}

        {status === 'success' && (
          <div className="space-y-4 rounded-2xl border border-surface-2 bg-surface-1 p-8">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-success/10">
              <MailCheck className="h-7 w-7 text-semantic-success" />
            </div>
            <h2 className="text-xl font-semibold text-text-primary">Email verified</h2>
            <p className="text-sm text-text-muted">
              Your email has been successfully verified. You can now sign in to your account.
            </p>
            <Link
              to={ROUTES.AUTH.LOGIN}
              className="inline-flex items-center justify-center rounded-xl bg-gradient-cta px-6 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Sign in
            </Link>
          </div>
        )}

        {status === 'error' && (
          <div className="space-y-4 rounded-2xl border border-surface-2 bg-surface-1 p-8">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-error/10">
              <AlertCircle className="h-7 w-7 text-semantic-error" />
            </div>
            <h2 className="text-xl font-semibold text-text-primary">Verification failed</h2>
            <p className="text-sm text-text-muted">
              This verification link is invalid or has expired. You can request a new one.
            </p>
            <Link
              to={ROUTES.AUTH.LOGIN}
              className="inline-flex items-center gap-2 text-sm font-medium text-brand-violet hover:text-brand-blue transition-colors"
            >
              <RefreshCw size={14} />
              Request a new verification email
            </Link>
          </div>
        )}
      </div>
    </div>
  )
}
