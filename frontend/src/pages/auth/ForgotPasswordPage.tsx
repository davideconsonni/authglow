import { Link } from 'react-router-dom'
import { AuthLayout } from '../../components/auth/AuthLayout'
import { ForgotPasswordForm } from '../../components/auth/ForgotPasswordForm'
import { ROUTES } from '../../lib/constants'

export function ForgotPasswordPage() {
  return (
    <AuthLayout
      title="Reset your password"
      description="Enter your email address and we'll send you a link to reset your password."
    >
      <ForgotPasswordForm />
      <p className="text-center text-sm text-text-muted">
        Remember your password?{' '}
        <Link to={ROUTES.AUTH.LOGIN} className="font-medium text-brand-accent hover:text-brand-cool transition-colors">
          Sign in
        </Link>
      </p>
    </AuthLayout>
  )
}
