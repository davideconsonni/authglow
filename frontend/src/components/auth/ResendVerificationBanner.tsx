import { useState } from 'react'
import { Mail, Loader2 } from 'lucide-react'
import { api } from '../../lib/api'

export function ResendVerificationBanner() {
  const [loading, setLoading] = useState(false)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState('')

  const handleResend = async () => {
    setLoading(true)
    setError('')
    try {
      await api.post('/api/email/resend-verification')
      setSent(true)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to resend verification email')
    } finally {
      setLoading(false)
    }
  }

  if (sent) {
    return (
      <div className="rounded-xl bg-semantic-success/10 px-4 py-2 text-xs text-semantic-success">
        Verification email sent. Check your inbox.
      </div>
    )
  }

  return (
    <div className="rounded-xl bg-semantic-info/10 border border-semantic-info/20 px-4 py-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-xs text-text-secondary">
          <Mail size={14} className="text-semantic-info shrink-0" />
          {error || 'Verify your email to enable all features.'}
        </div>
        <button
          onClick={handleResend}
          disabled={loading}
          className="rounded-lg bg-semantic-info/20 px-3 py-1 text-xs font-medium text-semantic-info hover:bg-semantic-info/30 transition-colors disabled:opacity-50 shrink-0"
        >
          {loading ? <Loader2 size={12} className="animate-spin" /> : 'Resend'}
        </button>
      </div>
    </div>
  )
}
