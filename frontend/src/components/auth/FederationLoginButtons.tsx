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
    <div className="fed-buttons-wrapper">
      <style>{`
        .fed-buttons-wrapper {
          margin-top: 1.5rem;
        }
        .fed-separator {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          margin-bottom: 1rem;
        }
        .fed-sep-line {
          flex: 1;
          height: 1px;
          background: #e2e8f0;
        }
        .fed-sep-text {
          font-size: 0.75rem;
          color: #718096;
          white-space: nowrap;
        }
        .fed-btn {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          width: 100%;
          padding: 0.625rem 1rem;
          border-radius: 12px;
          border: 1px solid #e2e8f0;
          background: #ffffff;
          color: #1a1a2e;
          font-size: 0.875rem;
          font-weight: 500;
          text-decoration: none;
          cursor: pointer;
          transition: all 150ms ease;
        }
        .fed-btn:hover {
          background: #f1f3f5;
          border-color: #475569;
        }
        .fed-btn + .fed-btn {
          margin-top: 0.5rem;
        }
        .fed-btn-icon {
          width: 18px;
          height: 18px;
          border-radius: 4px;
          object-fit: contain;
        }
      `}</style>
      <div className="fed-separator">
        <span className="fed-sep-line" />
        <span className="fed-sep-text">or continue with</span>
        <span className="fed-sep-line" />
      </div>
      {providers.map((p) => (
        <a
          key={p.id}
          href={buildLoginUrl(p.id)}
          className="fed-btn"
          data-testid={`fed-provider-${p.id}`}
        >
          {p.icon_uri ? (
            <img src={p.icon_uri} alt="" className="fed-btn-icon" onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }} />
          ) : (
            <Shield size={16} />
          )}
          {p.label}
        </a>
      ))}
    </div>
  )
}