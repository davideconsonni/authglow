import { Link } from 'react-router-dom'
import { AuthLayout } from '../../components/auth/AuthLayout'
import { RegisterForm } from '../../components/auth/RegisterForm'
import { ROUTES } from '../../lib/constants'

export function RegisterPage() {
  return (
    <AuthLayout
      title="Create your account"
      description="Get started with AuthGlow. Your identity, your control."
    >
      <RegisterForm />
      <p className="text-center text-sm text-text-muted">
        Already have an account?{' '}
        <Link to={ROUTES.AUTH.LOGIN} className="font-medium text-brand-violet hover:text-brand-blue transition-colors">
          Sign in
        </Link>
      </p>
    </AuthLayout>
  )
}
