import { useEffect, useState } from 'react'
import { Loader2, ShieldCheck } from 'lucide-react'
import { api } from '../lib/api'
import { ROUTES } from '../lib/constants'
import { SetupWizard } from '../components/setup/SetupWizard'
import { useDocumentTitle } from '../hooks/useDocumentTitle'

export function SetupPage() {
  useDocumentTitle('Setup')
  const [status, setStatus] = useState<'loading' | 'needed' | 'done'>('loading')

  useEffect(() => {
    const check = async () => {
      try {
        const data = await api.get<{ needs_setup: boolean }>('/api/setup/check')
        setStatus(data.needs_setup ? 'needed' : 'done')
      } catch {
        setStatus('needed')
      }
    }
    check()
  }, [])

  if (status === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg-primary">
        <Loader2 className="h-8 w-8 animate-spin text-brand-violet" />
      </div>
    )
  }

  if (status === 'done') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
        <div className="w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-8 text-center space-y-4">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-violet/10">
            <ShieldCheck className="h-7 w-7 text-brand-violet" />
          </div>
          <h2 className="text-xl font-semibold text-text-primary">Setup already completed</h2>
          <p className="text-sm text-text-muted">Your AuthGlow instance is ready.</p>
          <a
            href={ROUTES.AUTH.LOGIN}
            className="inline-flex items-center justify-center rounded-xl bg-gradient-cta px-6 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            Sign in
          </a>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
      <div className="w-full max-w-lg space-y-8">
        <div className="text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-brand-violet/10 ring-1 ring-brand-violet/20 shadow-glow-violet">
            <ShieldCheck className="h-8 w-8 text-brand-violet" />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-text-primary">Welcome to AuthGlow</h1>
          <p className="mt-2 text-sm text-text-muted">
            Create your administrator account to get started.
          </p>
        </div>

        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
          <SetupWizard />
        </div>
      </div>
    </div>
  )
}
