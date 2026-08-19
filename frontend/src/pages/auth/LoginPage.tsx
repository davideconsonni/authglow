import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Mail, Loader2, RefreshCw } from 'lucide-react'
import { AuthLayout } from '../../components/auth/AuthLayout'
import { LoginForm } from '../../components/auth/LoginForm'
import { PasskeyLoginButton } from '../../components/auth/PasskeyLoginButton'
import { FederationLoginButtons } from '../../components/auth/FederationLoginButtons'
import { DemoInbox } from '../../components/shared/DemoInbox'
import { useDemoMeta } from '../../hooks/useDemoMeta'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { ROUTES } from '../../lib/constants'
import { api } from '../../lib/api'

export function LoginPage() {
  useDocumentTitle('Sign In')
  const location = useLocation()
  const state = location.state as { registered?: boolean; email?: string } | null
  const registered = state?.registered
  const registeredEmail = state?.email
  const { meta } = useDemoMeta()
  const [resending, setResending] = useState(false)
  const [resendSent, setResendSent] = useState(false)

  const handleResend = async () => {
    if (!registeredEmail) return
    setResending(true)
    try {
      await api.post('/api/email/resend-verification', { email: registeredEmail })
      setResendSent(true)
    } catch {
      // silently fail, user can retry
    } finally {
      setResending(false)
    }
  }

  return (
    <AuthLayout
      title="Welcome back"
      description="Sign in to your account to manage your identity and security."
    >
      {registered && (
        <div className="rounded-xl bg-semantic-success/10 border border-semantic-success/20 px-4 py-3">
          <div className="flex items-center gap-2 text-xs text-semantic-success">
            <Mail size={14} className="shrink-0" />
            Account created! Check your email for the verification link.
          </div>
          {registeredEmail && (
            <div className="mt-2 pt-2 border-t border-semantic-success/20">
              {resendSent ? (
                <p className="text-xs text-semantic-success">Verification email resent. Check your inbox.</p>
              ) : (
                <button
                  type="button"
                  onClick={handleResend}
                  disabled={resending}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-semantic-success hover:text-semantic-success/80 transition-colors disabled:opacity-50"
                >
                  {resending ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
                  Didn't receive the email? Resend
                </button>
              )}
            </div>
          )}
        </div>
      )}
      {meta.demo_mode && registeredEmail && (
        <DemoInbox email={registeredEmail} />
      )}
      <LoginForm />
      <PasskeyLoginButton />
      <FederationLoginButtons context="dashboard" />
      <p className="text-center text-sm text-text-muted">
        Don't have an account?{' '}
        <Link to={ROUTES.AUTH.REGISTER} className="font-medium text-brand-violet hover:text-brand-blue transition-colors">
          Create one
        </Link>
      </p>
      <p className="text-center text-sm text-text-muted">
        <Link to={ROUTES.AUTH.FORGOT_PASSWORD} className="font-medium text-text-secondary hover:text-text-primary transition-colors">
          Forgot your password?
        </Link>
      </p>
    </AuthLayout>
  )
}
