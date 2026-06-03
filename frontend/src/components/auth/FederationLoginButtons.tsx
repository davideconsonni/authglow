import { useState, useEffect } from 'react'
import { Shield } from 'lucide-react'
import { api } from '@/lib/api'
import { API_URL } from '@/lib/constants'

interface FedProvider {
  id: string
  label: string
  description?: string | null
  icon_uri?: string | null
  logo_uri?: string | null
}

export function FederationLoginButtons() {
  const [providers, setProviders] = useState<FedProvider[]>([])

  useEffect(() => {
    let cancelled = false
    api.get<FedProvider[]>('/api/federation/providers')
      .then((data) => { if (!cancelled) setProviders(data) })
      .catch(() => { /* federation not available */ })
    return () => { cancelled = true }
  }, [])

  if (providers.length === 0) return null

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
          href={`${API_URL}/api/federation/login/${p.id}?redirect_uri=${encodeURIComponent(window.location.origin + window.location.pathname)}`}
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