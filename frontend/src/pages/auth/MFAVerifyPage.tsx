import { useSearchParams } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { MFAVerifyForm } from '../../components/auth/MFAVerifyForm'

export function MFAVerifyPage() {
  const [searchParams] = useSearchParams()
  const sessionToken = searchParams.get('session_token')

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
      <div className="w-full max-w-md space-y-8">
        <div className="text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-brand-violet/10 ring-1 ring-brand-violet/20 shadow-glow-violet">
            <Shield className="h-8 w-8 text-brand-violet" />
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
