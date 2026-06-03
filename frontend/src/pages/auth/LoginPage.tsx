import { Link } from 'react-router-dom'
import { AuthLayout } from '@/components/auth/AuthLayout'
import { LoginForm } from '@/components/auth/LoginForm'
import { PasskeyLoginButton } from '@/components/auth/PasskeyLoginButton'
import { FederationLoginButtons } from '@/components/auth/FederationLoginButtons'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'
import { ROUTES } from '@/lib/constants'

export function LoginPage() {
  useDocumentTitle('Sign In')
  return (
    <AuthLayout
      title="Welcome back"
      description="Sign in to your account to manage your identity and security."
    >
      <LoginForm />
      <PasskeyLoginButton />
      <FederationLoginButtons />
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
