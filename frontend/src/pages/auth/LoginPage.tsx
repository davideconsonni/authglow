import { Link, useLocation } from 'react-router-dom'
import { Mail } from 'lucide-react'
import { AuthLayout } from '@/components/auth/AuthLayout'
import { LoginForm } from '@/components/auth/LoginForm'
import { PasskeyLoginButton } from '@/components/auth/PasskeyLoginButton'
import { FederationLoginButtons } from '@/components/auth/FederationLoginButtons'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'
import { ROUTES } from '@/lib/constants'

export function LoginPage() {
  useDocumentTitle('Sign In')
  const location = useLocation()
  const registered = (location.state as { registered?: boolean } | null)?.registered

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
        </div>
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
