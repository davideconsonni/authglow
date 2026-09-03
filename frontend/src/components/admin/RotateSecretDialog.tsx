import { useEffect, useRef, useState } from 'react'
import { AlertTriangle, Loader2, KeyRound, RefreshCw, Sparkles, Trash2 } from 'lucide-react'
import { api } from '../../lib/api'
import { cn } from '../../lib/utils'

/**
 * The set of destructive admin actions that require a server-issued
 * safeword. The dialog uses ``purpose`` to compute the right URL
 * paths and to pick the right copy + icon.
 *
 * - ``secret``         rotate OAuth client secret
 * - ``jwt_key``        rotate OAuth client JWT signing key
 * - ``api_key_delete`` permanently delete an API key
 * - ``api_key_rotate`` regenerate the plaintext secret for an API key
 * - ``jwk_rotate``     rotate the global JWT signing keyring
 */
export type RotateSecretPurpose =
  | 'secret'
  | 'jwt_key'
  | 'api_key_delete'
  | 'api_key_rotate'
  | 'jwk_rotate'

interface RotateSecretDialogProps {
  open: boolean
  /**
   * Identifier the challenge is bound to. For OAuth-client
   * actions this is the ``client_id``; for API-key delete it is
   * the ``key_id``; for the global JWK rotation it is
   * ``"global"``.
   */
  targetId: string | null
  /** Human-readable label (client name, key name, …) shown in the dialog. */
  targetLabel?: string
  purpose: RotateSecretPurpose
  onClose: () => void
  /**
   * Called on success. For rotation actions the new credential
   * is passed (so the caller can show the show-once modal). For
   * delete actions no payload is provided.
   */
  onSuccess: (newCredential?: string) => void
  onError: (message: string) => void
}

type Phase = 'confirm' | 'safeword' | 'error'

interface Challenge {
  challengeId: string
  word: string
  expiresAt: string
}

interface PurposeCopy {
  title: string
  confirmMessage: string
  safewordTitle: string
  safewordHelper: string
  rotateLabel: string
  generateLabel: string
  rotatingLabel: string
  /** Icon component class — drawn next to the title. */
  Icon: typeof KeyRound
  /** URL for the POST that issues a challenge. */
  challengePath: (targetId: string) => string
  /** URL for the destructive POST that consumes the challenge. */
  actionPath: (targetId: string) => string
  /**
   * Body shape for the destructive call. Returns ``null`` for
   * DELETE requests — those send the body via ``request()``
   * because Starlette's TestClient ``delete()`` does not accept
   * a JSON body. In production the runtime supports DELETE
   * with body, but we route through ``request()`` to keep the
   * frontend API uniform.
   */
  actionMethod: 'POST' | 'DELETE'
  /** Field name in the success response (e.g. ``new_client_secret``). */
  successField: string | null
}

const COPY: Record<RotateSecretPurpose, PurposeCopy> = {
  secret: {
    title: 'Rotate client secret?',
    confirmMessage:
      'The current secret will be invalidated immediately. Any application using this client will stop working until you distribute the new secret. This action cannot be undone.',
    safewordTitle: 'Type the safeword to confirm',
    safewordHelper:
      'Copy the safeword below and type it back exactly to authorize the rotation. The challenge expires in 60 seconds.',
    rotateLabel: 'Rotate secret',
    generateLabel: 'Generate safeword',
    rotatingLabel: 'Rotating…',
    Icon: KeyRound,
    challengePath: (id) => `/api/oauth-clients/${id}/rotate-secret/challenge`,
    actionPath: (id) => `/api/oauth-clients/${id}/rotate-secret`,
    actionMethod: 'POST',
    successField: 'new_client_secret',
  },
  jwt_key: {
    title: 'Rotate JWT signing key?',
    confirmMessage:
      'The current JWT signing key will be invalidated immediately. Any application authenticating with client_secret_jwt will fail until it is reconfigured with the new key. This action cannot be undone.',
    safewordTitle: 'Type the safeword to confirm',
    safewordHelper:
      'Copy the safeword below and type it back exactly to authorize the rotation. The challenge expires in 60 seconds.',
    rotateLabel: 'Rotate JWT key',
    generateLabel: 'Generate safeword',
    rotatingLabel: 'Rotating…',
    Icon: Sparkles,
    challengePath: (id) => `/api/oauth-clients/${id}/rotate-jwt-key/challenge`,
    actionPath: (id) => `/api/oauth-clients/${id}/rotate-jwt-key`,
    actionMethod: 'POST',
    successField: 'new_client_secret',
  },
  api_key_delete: {
    title: 'Delete API key?',
    confirmMessage:
      'The API key will be permanently removed. Any service using it will lose access immediately. This action cannot be undone — consider deactivating the key first if you might want to restore it later.',
    safewordTitle: 'Type the safeword to confirm',
    safewordHelper:
      'Copy the safeword below and type it back exactly to authorize the deletion. The challenge expires in 60 seconds.',
    rotateLabel: 'Delete key',
    generateLabel: 'Generate safeword',
    rotatingLabel: 'Deleting…',
    Icon: Trash2,
    challengePath: (id) => `/api/keys/${id}/delete/challenge`,
    actionPath: (id) => `/api/keys/${id}`,
    actionMethod: 'DELETE',
    successField: null,
  },
  api_key_rotate: {
    title: 'Regenerate API key secret?',
    confirmMessage:
      'The current secret will be invalidated immediately. Any service using this key will lose access until it is reconfigured with the new secret. The new secret is shown once. The key keeps its name, scopes, and identifier — only the credential material changes.',
    safewordTitle: 'Type the safeword to confirm',
    safewordHelper:
      'Copy the safeword below and type it back exactly to authorize the regeneration. The challenge expires in 60 seconds.',
    rotateLabel: 'Regenerate secret',
    generateLabel: 'Generate safeword',
    rotatingLabel: 'Regenerating…',
    Icon: KeyRound,
    challengePath: (id) => `/api/keys/${id}/rotate/challenge`,
    actionPath: (id) => `/api/keys/${id}/rotate`,
    actionMethod: 'POST',
    // The backend includes the new plaintext key in this field.
    successField: 'api_key',
  },
  jwk_rotate: {
    title: 'Rotate JWT signing keyring?',
    confirmMessage:
      'A new active signing key will be generated. The previous key will continue to verify tokens for a short verifying window, then become invalid. All clients that cache the JWKS will pick up the new key on their next refresh. This action cannot be undone.',
    safewordTitle: 'Type the safeword to confirm',
    safewordHelper:
      'Copy the safeword below and type it back exactly to authorize the rotation. The challenge expires in 60 seconds.',
    rotateLabel: 'Rotate keyring',
    generateLabel: 'Generate safeword',
    rotatingLabel: 'Rotating…',
    Icon: RefreshCw,
    // JWK rotation is global: there is no per-id target. The
    // component still passes a non-null targetId so the URL
    // template works uniformly.
    challengePath: () => `/api/admin/jwk-keys/rotate/challenge`,
    actionPath: () => `/api/admin/jwk-keys/rotate`,
    actionMethod: 'POST',
    successField: 'new_kid',
  },
}

export function RotateSecretDialog({
  open,
  targetId,
  targetLabel,
  purpose,
  onClose,
  onSuccess,
  onError,
}: RotateSecretDialogProps) {
  const [phase, setPhase] = useState<Phase>('confirm')
  const [challenge, setChallenge] = useState<Challenge | null>(null)
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const copy = COPY[purpose]
  const Icon = copy.Icon

  useEffect(() => {
    if (!open) {
      setPhase('confirm')
      setChallenge(null)
      setTyped('')
      setBusy(false)
      setLocalError(null)
    }
  }, [open])

  useEffect(() => {
    if (phase === 'safeword') {
      requestAnimationFrame(() => inputRef.current?.focus())
    }
  }, [phase])

  if (!open || !targetId) return null

  const requestChallenge = async () => {
    setLocalError(null)
    setBusy(true)
    try {
      const data = await api.post<{
        challenge_id: string
        word: string
        expires_at: string
      }>(copy.challengePath(targetId))
      setChallenge({
        challengeId: data.challenge_id,
        word: data.word,
        expiresAt: data.expires_at,
      })
      setPhase('safeword')
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to generate safeword'
      setLocalError(msg)
      setPhase('error')
    } finally {
      setBusy(false)
    }
  }

  const performAction = async () => {
    if (!challenge) return
    setBusy(true)
    try {
      const body = { challenge_id: challenge.challengeId, word: typed }
      let data: Record<string, unknown>
      if (copy.actionMethod === 'POST') {
        data = await api.post<Record<string, unknown>>(copy.actionPath(targetId), body)
      } else {
        // DELETE with body — goes through the generic request()
        // method on the api client.
        data = await api.delete<Record<string, unknown>>(
          copy.actionPath(targetId),
          { body }
        )
      }
      const newCred = copy.successField ? (data[copy.successField] as string | undefined) : undefined
      onSuccess(newCred)
      onClose()
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to perform action'
      setLocalError(msg)
      setPhase('error')
      onError(msg)
    } finally {
      setBusy(false)
    }
  }

  const wordMatches = !!challenge && typed.trim().toLowerCase() === challenge.word.toLowerCase()

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      data-testid="rotate-secret-dialog"
    >
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={busy ? undefined : onClose}
        data-testid="rotate-secret-backdrop"
      />
      <div
        className="relative z-10 mx-4 w-full sm:max-w-lg sm:rounded-2xl rounded-xl border border-surface-2 bg-surface-1 p-6 shadow-glow-accent"
        role="alertdialog"
        aria-modal="true"
      >
        {phase === 'confirm' && (
          <div className="space-y-4">
            <div className="flex items-start gap-4">
              <div className="rounded-xl bg-semantic-error/10 p-2">
                <Icon className="text-semantic-error" size={24} />
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-text-primary">
                  {copy.title}
                </h3>
                {targetLabel && (
                  <p className="mt-1 text-xs text-text-muted">Target: {targetLabel}</p>
                )}
                <p className="mt-2 text-sm text-text-muted">{copy.confirmMessage}</p>
              </div>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={onClose}
                disabled={busy}
                className="rounded-xl bg-surface-2 px-4 min-h-[44px] py-2 text-sm font-medium text-text-secondary hover:bg-surface-3 transition-colors btn-cta"
              >
                Cancel
              </button>
              <button
                onClick={requestChallenge}
                disabled={busy}
                data-testid="rotate-secret-generate"
                className="inline-flex items-center gap-2 rounded-xl bg-semantic-error hover:bg-semantic-error/90 px-4 min-h-[44px] py-2 text-sm font-medium text-white transition-colors btn-cta"
              >
                {busy ? <Loader2 size={14} className="animate-spin" /> : <AlertTriangle size={14} />}
                {copy.generateLabel}
              </button>
            </div>
          </div>
        )}

        {phase === 'safeword' && challenge && (
          <div className="space-y-4" data-testid="rotate-secret-safeword-phase">
            <div className="flex items-start gap-4">
              <div className="rounded-xl bg-semantic-error/10 p-2">
                <Icon className="text-semantic-error" size={24} />
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-text-primary">
                  {copy.safewordTitle}
                </h3>
                <p className="mt-1 text-xs text-text-muted">{copy.safewordHelper}</p>
              </div>
            </div>

            <div className="rounded-xl border border-semantic-warning/30 bg-semantic-warning/5 p-4 space-y-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-semantic-warning">
                Safeword
              </p>
              <code
                data-testid="rotate-secret-word"
                className="block select-all break-all font-mono text-2xl text-text-primary tracking-wider"
              >
                {challenge.word}
              </code>
              <p className="text-[11px] text-text-muted">
                Select and copy, then paste it into the field below to confirm.
              </p>
            </div>

            <div className="space-y-2">
              <label
                htmlFor="rotate-secret-typed"
                className="block text-sm font-medium text-text-secondary"
              >
                Type the safeword to confirm
              </label>
              <input
                id="rotate-secret-typed"
                ref={inputRef}
                type="text"
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                autoComplete="off"
                spellCheck={false}
                autoCapitalize="off"
                data-testid="rotate-secret-input"
                className={cn(
                  'w-full rounded-xl border bg-surface-1 px-4 py-3 text-sm font-mono text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-2 transition-colors',
                  'border-surface-2 focus:border-brand-accent focus:ring-brand-accent/20'
                )}
                placeholder="paste-or-type-the-safeword"
                disabled={busy}
              />
              {typed && !wordMatches && (
                <p className="text-xs text-semantic-warning" data-testid="rotate-secret-mismatch">
                  Safeword does not match yet.
                </p>
              )}
            </div>

            <div className="flex justify-between gap-3 pt-2">
              <button
                onClick={onClose}
                disabled={busy}
                className="rounded-xl bg-surface-2 px-4 min-h-[44px] py-2 text-sm font-medium text-text-secondary hover:bg-surface-3 transition-colors btn-cta"
              >
                Cancel
              </button>
              <button
                onClick={performAction}
                disabled={busy || !wordMatches}
                data-testid="rotate-secret-confirm"
                className="inline-flex items-center gap-2 rounded-xl bg-semantic-error hover:bg-semantic-error/90 px-4 min-h-[44px] py-2 text-sm font-medium text-white transition-colors btn-cta disabled:cursor-not-allowed"
              >
                {busy ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                {busy ? copy.rotatingLabel : copy.rotateLabel}
              </button>
            </div>
          </div>
        )}

        {phase === 'error' && (
          <div className="space-y-4" data-testid="rotate-secret-error-phase">
            <div className="flex items-start gap-4">
              <div className="rounded-xl bg-semantic-error/10 p-2">
                <AlertTriangle className="text-semantic-error" size={24} />
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-text-primary">Action failed</h3>
                <p className="mt-2 text-sm text-text-muted" data-testid="rotate-secret-error-message">
                  {localError ?? 'Unknown error'}
                </p>
              </div>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={onClose}
                className="rounded-xl bg-surface-2 px-4 min-h-[44px] py-2 text-sm font-medium text-text-secondary hover:bg-surface-3 transition-colors"
              >
                Close
              </button>
              <button
                onClick={() => {
                  setLocalError(null)
                  setPhase('confirm')
                }}
                data-testid="rotate-secret-retry"
                className="rounded-xl bg-gradient-cta px-4 min-h-[44px] py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98]"
              >
                Try again
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
