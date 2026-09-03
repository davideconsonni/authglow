import { useState } from 'react'
import { Shield, Globe, Mail, User, Lock, Key, ExternalLink, Loader2, type LucideIcon } from 'lucide-react'
import { api } from '../../lib/api'
import { ThemeSwitcher } from '../shared/ThemeSwitcher'
import { brandingStyle } from '../../lib/clientBranding'

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
  redirectUri?: string | null
  branding?: Record<string, unknown> | null
  scopes: Array<{ name: string; description: string }>
  preview?: boolean
}

export function ConsentScreen({
  sessionToken,
  clientName,
  clientDescription,
  clientLogoUri,
  clientHomepageUri,
  clientTermsUri,
  clientPrivacyUri,
  redirectUri,
  branding,
  scopes,
  preview = false,
}: ConsentScreenProps) {
  const [approving, setApproving] = useState(false)
  const [denying, setDenying] = useState(false)
  const [generalError, setGeneralError] = useState('')
  const [rememberConsent, setRememberConsent] = useState(false)

  let redirectOrigin = ''
  if (redirectUri) {
    try {
      redirectOrigin = new URL(redirectUri).origin
    } catch {
      redirectOrigin = redirectUri
    }
  }

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
          remember: String(rememberConsent),
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
    <div
      className="authglow-consent relative flex min-h-screen items-center justify-center bg-bg-primary p-8 text-text-primary"
      style={brandingStyle(branding)}
    >
      <div className="absolute right-4 top-4 z-20">
        <ThemeSwitcher size="sm" />
      </div>

      <div className="w-full max-w-md space-y-0">
        {/* Logo */}
        <div className="text-center">
          {clientLogoUri ? (
            <img src={clientLogoUri} alt={`${clientName} logo`} className="mx-auto h-14 w-14 rounded-xl object-contain bg-surface-1 border border-surface-2"
              onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }} />
          ) : (
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-xl bg-surface-2 border border-surface-2 text-text-secondary">
              <Shield size={28} />
            </div>
          )}
        </div>

        {/* Header */}
        <div className="mt-4 text-center">
          <h1 className="text-lg font-bold text-text-primary">
            Authorize{' '}
            <span style={{ color: 'var(--brand-primary, var(--color-brand-accent))' }}>{clientName}</span>
          </h1>
          {clientDescription && (
            <p className="mt-2 text-sm text-text-muted">{clientDescription}</p>
          )}
        </div>

        {/* Scope list */}
        <div className="consent-card mt-6 border border-surface-2 p-5" data-testid="consent-card">
          <p className="text-sm font-medium text-text-secondary mb-4">{clientName} is requesting access to:</p>
          <ul className="space-y-3">
            {scopes.map((scope) => {
              const Icon = getScopeIcon(scope.name)
              return (
                <li key={scope.name} className="flex items-start gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-2 text-text-secondary">
                    <Icon size={16} />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-text-primary">{scope.name}</p>
                    <p className="text-xs text-text-muted">{scope.description}</p>
                  </div>
                </li>
              )
            })}
          </ul>

          {redirectOrigin && (
            <div className="mt-4 rounded-xl border border-surface-2 bg-surface-2/50 p-3">
              <p className="text-[11px] font-medium uppercase tracking-wider text-text-muted">Redirect destination</p>
              <p className="mt-1 break-all text-xs font-mono text-text-secondary">{redirectOrigin}</p>
            </div>
          )}

          {!preview && (
            <label className="mt-4 flex items-start gap-2 text-xs text-text-secondary">
              <input
                type="checkbox"
                checked={rememberConsent}
                onChange={(event) => setRememberConsent(event.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-surface-3 accent-brand-accent"
              />
              <span>Remember this decision for future requests from this application</span>
            </label>
          )}

          {/* Branding links */}
          {hasLinks && (
            <div className="mt-4 pt-4 border-t border-surface-2">
              <p className="text-[11px] font-medium text-text-muted uppercase tracking-wider mb-2">Application details</p>
              <div className="flex flex-wrap gap-3">
                {clientHomepageUri && (
                  <a href={clientHomepageUri} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-brand-accent hover:text-brand-alt transition-colors">
                    Homepage <ExternalLink size={10} />
                  </a>
                )}
                {clientTermsUri && (
                  <a href={clientTermsUri} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-brand-accent hover:text-brand-alt transition-colors">
                    Terms of Service <ExternalLink size={10} />
                  </a>
                )}
                {clientPrivacyUri && (
                  <a href={clientPrivacyUri} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-brand-accent hover:text-brand-alt transition-colors">
                    Privacy Policy <ExternalLink size={10} />
                  </a>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Preview badge */}
        {preview && (
          <div className="mt-4 rounded-xl border border-surface-2 bg-surface-2/50 p-3 text-center text-xs text-text-muted">
            This is a preview of how the consent screen will appear to users. Actions are disabled.
          </div>
        )}

        {/* Error */}
        {generalError && (
          <div className="mt-4 rounded-xl border border-semantic-error/30 bg-semantic-error/10 p-3 text-sm text-semantic-error" role="alert">
            {generalError}
          </div>
        )}

        {/* Actions */}
        {!preview && (
          <div className="mt-6 flex gap-3">
            <button
              onClick={handleDeny}
              disabled={denying || approving}
              className="flex-1 flex items-center justify-center gap-2 rounded-xl border border-surface-2 px-4 py-3 text-sm font-medium text-text-secondary hover:bg-surface-2 transition-colors btn-cta disabled:cursor-not-allowed"
            >
              {denying ? <Loader2 size={16} className="animate-spin" /> : null}
              Deny
            </button>
            <button
              onClick={handleApprove}
              disabled={approving || denying}
              className="consent-approve-btn flex-1 flex items-center justify-center gap-2 px-4 py-3 text-sm font-semibold shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98] btn-cta disabled:cursor-not-allowed disabled:hover:scale-100"
            >
              {approving ? <Loader2 size={16} className="animate-spin" /> : null}
              Approve
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
