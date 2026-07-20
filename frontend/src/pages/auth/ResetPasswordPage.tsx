import { AuthLayout } from '../../components/auth/AuthLayout'
import { ResetPasswordForm } from '../../components/auth/ResetPasswordForm'

export function ResetPasswordPage() {
  return (
    <AuthLayout
      title="Set a new password"
      description="Choose a strong password for your account."
    >
      <ResetPasswordForm />
    </AuthLayout>
  )
}
