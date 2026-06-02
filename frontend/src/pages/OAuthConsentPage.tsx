import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Shield, Loader2 } from 'lucide-react'
import { api } from '@/lib/api'
import { ConsentScreen } from '@/components/oauth/ConsentScreen'

interface ConsentCheck {
  already_granted: boolean
  redirect_url?: string
  client_name?: string
  client_id?: string
  client_description?: string
  scopes?: Array<{
    name: string
    description: string
  }>
}

export function OAuthConsentPage() {
  const [searchParams] = useSearchParams()
  const sessionToken = searchParams.get('session_token')
  const [consentData, setConsentData] = useState<ConsentCheck | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!sessionToken) {
      setError('Invalid consent request. Missing session token.')
      setLoading(false)
      return
    }

    const checkConsent = async () => {
      try {
        const data = await api.post<ConsentCheck>(
          '/api/oauth2/consent/check',
          { session_token: sessionToken },
        )

        if (data.already_granted && data.redirect_url) {
          window.location.href = data.redirect_url
          return
        }

        setConsentData(data)
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : ''
        setError(message || 'Failed to load consent information.')
      } finally {
        setLoading(false)
      }
    }

    checkConsent()
  }, [sessionToken])

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg-primary">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-brand-violet" />
          <p className="text-sm text-text-muted">Loading consent information...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
        <div className="w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-8 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-error/10">
            <Shield className="h-7 w-7 text-semantic-error" />
          </div>
          <h2 className="mt-4 text-lg font-semibold text-text-primary">Consent Error</h2>
          <p className="mt-2 text-sm text-text-muted">{error}</p>
        </div>
      </div>
    )
  }

  if (!consentData || !consentData.client_name) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
        <div className="w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-8 text-center">
          <p className="text-sm text-text-muted">No consent information available.</p>
        </div>
      </div>
    )
  }

  return (
    <ConsentScreen
      sessionToken={sessionToken!}
      clientName={consentData.client_name!}
      clientDescription={consentData.client_description}
      scopes={consentData.scopes || []}
    />
  )
}
