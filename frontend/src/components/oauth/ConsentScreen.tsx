import { useState } from 'react'
import { Shield, Check, Globe, Mail, User, Lock, Key, type LucideIcon } from 'lucide-react'
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
  sessionToken: string
  clientName: string
  clientDescription?: string
  scopes: Array<{ name: string; description: string }>
}

export function ConsentScreen({
  sessionToken,
  clientName,
  clientDescription,
  scopes,
}: ConsentScreenProps) {
  const [remember, setRemember] = useState(false)
  const [approving, setApproving] = useState(false)
  const [denying, setDenying] = useState(false)
  const [generalError, setGeneralError] = useState('')

  const handleApprove = async () => {
    setApproving(true)
    setGeneralError('')
    try {
      const data = await api.post<{ redirect_url: string }>(
        '/oauth2/consent',
        {
          session_token: sessionToken,
          consent: 'approve',
          remember,
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
    setDenying(true)
    setGeneralError('')
    try {
      const data = await api.post<{ redirect_url: string }>(
        '/oauth2/consent',
        {
          session_token: sessionToken,
          consent: 'deny',
        },
      )
      window.location.href = data.redirect_url
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setGeneralError(message || 'Failed to deny consent.')
      setDenying(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
      <div className="w-full max-w-lg space-y-6">
        {/* Header */}
        <div className="text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-brand-violet/10 ring-1 ring-brand-violet/20">
            <Shield className="h-8 w-8 text-brand-violet" />
          </div>
          <h1 className="mt-4 text-2xl font-bold text-text-primary">
            Authorize <span className="gradient-text">{clientName}</span>
          </h1>
          {clientDescription && (
            <p className="mt-2 text-sm text-text-muted">{clientDescription}</p>
          )}
        </div>

        {/* Scope list */}
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
          <p className="text-sm font-medium text-text-secondary">
            {clientName} is requesting access to:
          </p>
          <ul className="space-y-3">
            {scopes.map((scope) => {
              const Icon = getScopeIcon(scope.name)
              return (
                <li key={scope.name} className="flex items-start gap-3">
                  <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-surface-2">
                    <Icon size={16} className="text-text-secondary" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-text-primary">{scope.name}</p>
                    <p className="text-xs text-text-muted">{scope.description}</p>
                  </div>
                </li>
              )
            })}
          </ul>

          {/* Remember checkbox */}
          <label className="flex items-center gap-3 cursor-pointer">
            <button
              role="checkbox"
              aria-checked={remember}
              onClick={() => setRemember(!remember)}
              className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-md border transition-colors ${
                remember
                  ? 'border-brand-violet bg-brand-violet'
                  : 'border-surface-3 bg-surface-2'
              }`}
            >
              {remember && <Check size={12} className="text-white" />}
            </button>
            <span className="text-sm text-text-secondary">
              Remember this decision for future requests
            </span>
          </label>
        </div>

        {/* Error */}
        {generalError && (
          <div className="rounded-xl border border-semantic-error/30 bg-semantic-error/10 px-4 py-3 text-sm text-semantic-error" role="alert">
            {generalError}
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-3">
          <button
            onClick={handleDeny}
            disabled={denying || approving}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl border border-surface-2 bg-transparent px-4 py-3 text-sm font-medium text-text-secondary hover:bg-surface-2 transition-colors disabled:cursor-not-allowed disabled:opacity-50"
          >
            {denying ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Deny
          </button>
          <button
            onClick={handleApprove}
            disabled={approving || denying}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {approving ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Approve
          </button>
        </div>
      </div>
    </div>
  )
}
