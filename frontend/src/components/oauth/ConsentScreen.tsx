import { useState } from 'react'
import { Shield, Globe, Mail, User, Lock, Key, ExternalLink, type LucideIcon } from 'lucide-react'
import { Loader2 } from 'lucide-react'
import { api } from '@/lib/api'

const SCOPE_ICONS: Record<string, LucideIcon> = {
  'openid': Key,
  'profile': User,
  'email': Mail,
  'offline_access': Lock,
  'default': Globe,
}

function getScopeIcon(scope: string): LucideIcon {
  const key = scope.toLowerCase()
  return SCOPE_ICONS[key] || SCOPE_ICONS.default
}

interface ConsentScreenProps {
  sessionToken?: string | null
  clientName: string
  clientDescription?: string | null
  clientLogoUri?: string | null
  clientHomepageUri?: string | null
  clientTermsUri?: string | null
  clientPrivacyUri?: string | null
  branding?: Record<string, unknown> | null
  scopes: Array<{ name: string; description: string }>
  preview?: boolean
}

function brandingToCss(b: Record<string, unknown> | null | undefined): string {
  if (!b) return ''
  const props: string[] = []
  if (typeof b.primary_color === 'string' && b.primary_color) props.push(`--brand-primary: ${b.primary_color}`)
  if (typeof b.surface_color === 'string' && b.surface_color) props.push(`--brand-surface: ${b.surface_color}`)
  if (typeof b.text_color === 'string' && b.text_color) props.push(`--brand-text: ${b.text_color}`)
  if (typeof b.font_family === 'string' && b.font_family) props.push(`--brand-font: ${b.font_family}`)
  if (typeof b.border_radius === 'string' && b.border_radius) props.push(`--brand-radius: ${b.border_radius}`)
  if (typeof b.logo_url === 'string' && b.logo_url) props.push(`--brand-logo: url(${b.logo_url})`)
  return props.length ? `.authglow-consent { ${props.join('; ')} }` : ''
}

export function ConsentScreen({
  sessionToken,
  clientName,
  clientDescription,
  clientLogoUri,
  clientHomepageUri,
  clientTermsUri,
  clientPrivacyUri,
  branding,
  scopes,
  preview = false,
}: ConsentScreenProps) {
  const [approving, setApproving] = useState(false)
  const [denying, setDenying] = useState(false)
  const [generalError, setGeneralError] = useState('')

  const handleApprove = async () => {
    if (preview || !sessionToken) return
    setApproving(true)
    setGeneralError('')
    try {
      const data = await api.postForm<{ redirect_url: string }>(
        '/oauth2/consent',
        {
          session_token: sessionToken,
          approved: 'true',
          remember: 'true',
        },
      )
      window.location.href = data.redirect_url
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setGeneralError(message || 'Failed to approve consent.')
      setApproving(false)
    }
  }

  const handleDeny = async () => {
    if (preview || !sessionToken) return
    setDenying(true)
    setGeneralError('')
    try {
      const data = await api.postForm<{ redirect_url: string }>(
        '/oauth2/consent',
        {
          session_token: sessionToken,
          approved: 'false',
          remember: 'false',
        },
      )
      window.location.href = data.redirect_url
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setGeneralError(message || 'Failed to deny consent.')
      setDenying(false)
    }
  }

  const hasLinks = clientHomepageUri || clientTermsUri || clientPrivacyUri

  return (
    <div className="authglow-consent">
      <style>{`
        /* Neutral base — overrideable via custom_css */
        .authglow-consent {
          --bg-primary: #f8f9fa;
          --bg-surface: #ffffff;
          --bg-subtle: #f1f3f5;
          --text-primary: #1a1a2e;
          --text-secondary: #4a5568;
          --text-muted: #718096;
          --border-color: #e2e8f0;
          --brand-color: #475569;
          --brand-hover: #334155;
          --brand-color-subtle: #eaecf0;
          --brand-color-border: #cbd5e1;
          --brand-shadow: rgba(71, 85, 105, 0.25);
          --brand-text: #ffffff;
          --error-color: #dc2626;
          --error-bg: #fef2f2;
          --success-color: #16a34a;
          --radius: 16px;
          --radius-sm: 10px;
          --font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
          --transition: 150ms ease;
          display: flex;
          min-height: ${preview ? 'auto' : '100vh'};
          align-items: ${preview ? 'flex-start' : 'center'};
          justify-content: center;
          background: var(--bg-primary);
          padding: 2rem;
          font-family: var(--font-family);
          color: var(--text-primary);
        }
        .authglow-consent * { box-sizing: border-box; }
        .authglow-consent .consent-card {
          width: 100%;
          max-width: 32rem;
        }
        .authglow-consent .consent-logo-area {
          text-align: center;
        }
        .authglow-consent .consent-logo-img {
          height: 56px;
          width: 56px;
          border-radius: 12px;
          object-fit: contain;
          background: var(--bg-surface);
          border: 1px solid var(--border-color);
          display: inline-block;
        }
        .authglow-consent .consent-logo-icon {
          display: inline-flex;
          height: 56px;
          width: 56px;
          align-items: center;
          justify-content: center;
          border-radius: var(--radius);
          background: var(--brand-color-subtle);
          border: 1px solid var(--brand-color-border);
          color: var(--brand-color);
        }
        .authglow-consent .consent-header {
          margin-top: 1rem;
          text-align: center;
        }
        .authglow-consent .consent-title {
          font-size: 1.25rem;
          font-weight: 700;
          color: var(--text-primary);
        }
        .authglow-consent .consent-title .consent-app-name {
          color: var(--brand-color);
          font-weight: 700;
        }
        .authglow-consent .consent-description {
          margin-top: 0.5rem;
          font-size: 0.875rem;
          color: var(--text-muted);
        }
        .authglow-consent .consent-section {
          margin-top: 1.5rem;
          background: var(--bg-surface);
          border: 1px solid var(--border-color);
          border-radius: var(--radius);
          padding: 1.5rem;
        }
        .authglow-consent .consent-section-title {
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--text-secondary);
          margin-bottom: 1rem;
        }
        .authglow-consent .scope-list {
          list-style: none;
          padding: 0;
          margin: 0;
        }
        .authglow-consent .scope-item {
          display: flex;
          align-items: flex-start;
          gap: 0.75rem;
          margin-bottom: 0.75rem;
        }
        .authglow-consent .scope-item:last-child { margin-bottom: 0; }
        .authglow-consent .scope-icon {
          display: flex;
          width: 2rem;
          height: 2rem;
          flex-shrink: 0;
          align-items: center;
          justify-content: center;
          border-radius: 0.5rem;
          background: var(--bg-subtle);
          color: var(--text-secondary);
          margin-top: 0.125rem;
        }
        .authglow-consent .scope-name {
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--text-primary);
        }
        .authglow-consent .scope-desc {
          font-size: 0.75rem;
          color: var(--text-muted);
        }
        .authglow-consent .consent-remember {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          cursor: pointer;
          margin-top: 1rem;
          padding-top: 1rem;
          border-top: 1px solid var(--border-color);
        }
        .authglow-consent .consent-remember-box {
          display: flex;
          width: 1.25rem;
          height: 1.25rem;
          flex-shrink: 0;
          align-items: center;
          justify-content: center;
          border-radius: 0.375rem;
          border: 1px solid var(--border-color);
          background: var(--bg-subtle);
          transition: all var(--transition);
        }
        .authglow-consent .consent-remember-box.checked {
          border-color: var(--brand-color);
          background: var(--brand-color);
          color: var(--brand-text);
        }
        .authglow-consent .consent-remember-label {
          font-size: 0.875rem;
          color: var(--text-secondary);
        }
        .authglow-consent .consent-links {
          margin-top: 1rem;
          padding-top: 0.75rem;
          border-top: 1px solid var(--border-color);
        }
        .authglow-consent .consent-links-title {
          font-size: 0.6875rem;
          font-weight: 500;
          color: var(--text-muted);
          text-transform: uppercase;
          letter-spacing: 0.05em;
          margin-bottom: 0.5rem;
        }
        .authglow-consent .consent-link {
          display: inline-flex;
          align-items: center;
          gap: 0.25rem;
          font-size: 0.75rem;
          color: var(--brand-color);
          text-decoration: none;
          transition: color var(--transition);
        }
        .authglow-consent .consent-link:hover { color: var(--brand-hover); }
        .authglow-consent .consent-link + .consent-link { margin-left: 1rem; }
        .authglow-consent .consent-error {
          margin-top: 1.5rem;
          padding: 0.75rem 1rem;
          border-radius: var(--radius-sm);
          border: 1px solid var(--color, $ef4444 / 30%);
          background: var(--error-bg);
          color: var(--error-color);
          font-size: 0.875rem;
        }
        .authglow-consent .consent-preview-badge {
          margin-top: 1.5rem;
          text-align: center;
          padding: 0.625rem 1rem;
          border-radius: var(--radius-sm);
          border: 1px solid var(--border-color);
          background: var(--bg-subtle);
          font-size: 0.75rem;
          color: var(--text-muted);
        }
        .authglow-consent .consent-actions {
          display: flex;
          gap: 0.75rem;
          margin-top: 1.5rem;
        }
        .authglow-consent .btn-deny {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          padding: 0.75rem 1rem;
          border-radius: var(--radius-sm);
          border: 1px solid var(--border-color);
          background: transparent;
          color: var(--text-secondary);
          font-size: 0.875rem;
          font-weight: 500;
          cursor: pointer;
          transition: all var(--transition);
        }
        .authglow-consent .btn-deny:hover { background: var(--bg-subtle); }
        .authglow-consent .btn-deny:disabled { cursor: not-allowed; opacity: 0.5; }
        .authglow-consent .btn-approve {
          flex: 1;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 0.5rem;
          padding: 0.75rem 1rem;
          border-radius: var(--radius-sm);
          border: none;
          background: var(--brand-color);
          color: var(--brand-text);
          font-size: 0.875rem;
          font-weight: 600;
          cursor: pointer;
          transition: all var(--transition);
          box-shadow: 0 2px 8px var(--brand-shadow);
        }
        .authglow-consent .btn-approve:hover { background: var(--brand-hover); transform: scale(1.02); }
        .authglow-consent .btn-approve:disabled { cursor: not-allowed; opacity: 0.5; transform: none; }
        .authglow-consent .btn-approve:active { transform: scale(0.98); }
        .authglow-consent .spinner {
          animation: consent-spin 1s linear infinite;
          width: 16px; height: 16px;
        }
        @keyframes consent-spin { to { transform: rotate(360deg); } }

        /* Branding custom properties — generated from structured branding (VAPT-037) */
        ${brandingToCss(branding)}
      `}</style>

      <div className="consent-card">

        {/* Logo */}
        <div className="consent-logo-area">
          {clientLogoUri ? (
            <img src={clientLogoUri} alt={`${clientName} logo`} className="consent-logo-img"
              onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }} />
          ) : (
            <div className="consent-logo-icon">
              <Shield size={28} />
            </div>
          )}
        </div>

        {/* Header */}
        <div className="consent-header">
          <h1 className="consent-title">
            Authorize <span className="consent-app-name">{clientName}</span>
          </h1>
          {clientDescription && (
            <p className="consent-description">{clientDescription}</p>
          )}
        </div>

        {/* Scope list */}
        <div className="consent-section">
          <p className="consent-section-title">{clientName} is requesting access to:</p>
          <ul className="scope-list">
            {scopes.map((scope) => {
              const Icon = getScopeIcon(scope.name)
              return (
                <li key={scope.name} className="scope-item">
                  <div className="scope-icon"><Icon size={16} /></div>
                  <div>
                    <p className="scope-name">{scope.name}</p>
                    <p className="scope-desc">{scope.description}</p>
                  </div>
                </li>
              )
            })}
          </ul>

          {/* Branding links */}
          {hasLinks && (
            <div className="consent-links">
              <p className="consent-links-title">Application details</p>
              {clientHomepageUri && (
                <a href={clientHomepageUri} target="_blank" rel="noopener noreferrer" className="consent-link">
                  Homepage <ExternalLink size={10} />
                </a>
              )}
              {clientTermsUri && (
                <a href={clientTermsUri} target="_blank" rel="noopener noreferrer" className="consent-link">
                  Terms of Service <ExternalLink size={10} />
                </a>
              )}
              {clientPrivacyUri && (
                <a href={clientPrivacyUri} target="_blank" rel="noopener noreferrer" className="consent-link">
                  Privacy Policy <ExternalLink size={10} />
                </a>
              )}
            </div>
          )}
        </div>

        {/* Preview badge */}
        {preview && (
          <div className="consent-preview-badge">
            This is a preview of how the consent screen will appear to users. Actions are disabled.
          </div>
        )}

        {/* Error */}
        {generalError && (
          <div className="consent-error" role="alert">{generalError}</div>
        )}

        {/* Actions */}
        {!preview && (
          <div className="consent-actions">
            <button onClick={handleDeny} disabled={denying || approving} className="btn-deny">
              {denying ? <Loader2 className="spinner" /> : null}
              Deny
            </button>
            <button onClick={handleApprove} disabled={approving || denying} className="btn-approve">
              {approving ? <Loader2 className="spinner" /> : null}
              Approve
            </button>
          </div>
        )}
      </div>
    </div>
  )
}