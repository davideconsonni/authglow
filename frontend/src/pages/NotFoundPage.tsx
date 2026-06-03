import { ArrowLeft, ShieldAlert } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

export function NotFoundPage() {
  const navigate = useNavigate()
  useDocumentTitle('Page Not Found')

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary p-6">
      <div className="flex flex-col items-center text-center max-w-sm">
        <div className="rounded-2xl bg-brand-violet/10 p-5">
          <ShieldAlert className="h-12 w-12 text-brand-violet" />
        </div>
        <h1 className="mt-6 text-3xl font-bold text-text-primary">404</h1>
        <p className="mt-2 text-lg font-semibold text-text-primary">Page not found</p>
        <p className="mt-1 text-sm text-text-muted">
          The page you are looking for doesn't exist or has been moved.
        </p>
        <button
          onClick={() => navigate('/dashboard')}
          className="mt-8 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-5 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          <ArrowLeft size={16} />
          Back to Dashboard
        </button>
      </div>
    </div>
  )
}
