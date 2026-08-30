import { useSearchParams } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { MFAVerifyForm } from '../../components/auth/MFAVerifyForm'
import { ThemeSwitcher } from '../../components/shared/ThemeSwitcher'

export function MFAVerifyPage() {
  const [searchParams] = useSearchParams()
  const sessionToken = searchParams.get('session_token')

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-bg-primary p-8">
      <div className="absolute right-4 top-4 z-20">
        <ThemeSwitcher size="sm" />
      </div>
      <div className="w-full max-w-md space-y-8">
        <div className="text-center">
          <div className="icon-chip mx-auto flex h-16 w-16 items-center justify-center rounded-2xl">
            <Shield className="h-8 w-8" />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-text-primary">Two-Factor Authentication</h1>
          <p className="mt-2 text-sm text-text-muted">
            Enter your one-time code to continue
          </p>
        </div>

        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
          {sessionToken ? (
            <MFAVerifyForm />
          ) : (
            <p className="text-sm text-text-muted text-center">
              Invalid verification request. Missing session token.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
