import { useState, useEffect } from 'react'
import { Shield } from 'lucide-react'
import { api } from '../../lib/api'
import { API_URL } from '../../lib/constants'

interface FedProvider {
  id: string
  label: string
  description?: string | null
  icon_uri?: string | null
  logo_uri?: string | null
}

interface OAuth2Context {
  client_id: string
  oauth_redirect_uri: string
  scope: string
  app_state: string
  code_challenge: string
  code_challenge_method: string
  response_type: string
  oidc_nonce: string
}

interface FederationLoginButtonsProps {
  oauth2Context?: OAuth2Context
  context?: 'dashboard' | 'oauth2'
}

export function FederationLoginButtons({ oauth2Context, context }: FederationLoginButtonsProps) {
  const [providers, setProviders] = useState<FedProvider[]>([])

  useEffect(() => {
    let cancelled = false
    const params = context ? `?context=${context}` : ''
    api.get<FedProvider[]>(`/api/federation/providers${params}`)
      .then((data) => { if (!cancelled) setProviders(data) })
      .catch(() => { /* federation not available */ })
    return () => { cancelled = true }
  }, [context])

  if (providers.length === 0) return null

  const buildLoginUrl = (providerId: string) => {
    const params = new URLSearchParams()
    params.set('redirect_uri', window.location.origin + window.location.pathname)
    if (oauth2Context) {
      params.set('client_id', oauth2Context.client_id)
      params.set('oauth_redirect_uri', oauth2Context.oauth_redirect_uri)
      params.set('scope', oauth2Context.scope)
      if (oauth2Context.app_state) params.set('app_state', oauth2Context.app_state)
      if (oauth2Context.code_challenge) params.set('code_challenge', oauth2Context.code_challenge)
      if (oauth2Context.code_challenge_method) params.set('code_challenge_method', oauth2Context.code_challenge_method)
      if (oauth2Context.response_type) params.set('response_type', oauth2Context.response_type)
      if (oauth2Context.oidc_nonce) params.set('oidc_nonce', oauth2Context.oidc_nonce)
    }
    return `${API_URL}/api/federation/login/${providerId}?${params.toString()}`
  }

  return (
    <div className="mt-6">
      <div className="flex items-center gap-3 mb-4">
        <span className="flex-1 h-px bg-surface-2" />
        <span className="text-xs text-text-muted whitespace-nowrap">or continue with</span>
        <span className="flex-1 h-px bg-surface-2" />
      </div>
      <div className="space-y-2">
        {providers.map((p) => (
          <a
            key={p.id}
            href={buildLoginUrl(p.id)}
            data-testid={`fed-provider-${p.id}`}
            className="flex items-center justify-center gap-2 w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm font-medium text-text-secondary hover:bg-surface-2 hover:text-text-primary hover:border-surface-3 transition-colors"
          >
            {p.icon_uri ? (
              <img src={p.icon_uri} alt="" className="h-[18px] w-[18px] rounded object-contain" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }} />
            ) : (
              <Shield size={16} />
            )}
            {p.label}
          </a>
        ))}
      </div>
    </div>
  )
}