// RP-Initiated Logout flow (OIDC Session Management / RP-Initiated Logout).
//
// The app (Relying Party) sends the browser to /oauth2/logout with the
// user's id_token_hint, a validated post_logout_redirect_uri and an opaque
// state. AuthGlow clears the central SSO session and bounces the user back.
//
// WARNING surfaced in-UI: executing this ends the ADMIN's own SSO session.

import { useMemo, useState } from 'react'
import { Loader2, LogOut } from 'lucide-react'
import { generateOAuthState } from '../../../lib/oauthCrypto'
import { usePlaygroundStore } from '../../../stores/playgroundStore'
import { FlowStepper } from '../FlowStepper'

const STEPS = [
  { id: 'build', label: 'Build URL' },
  { id: 'execute', label: 'Execute' },
]

export function RpInitiatedLogoutFlow() {
  const storeIdToken = usePlaygroundStore((s) => s.idToken)

  const [currentStep, setCurrentStep] = useState('build')
  const [idToken, setIdToken] = useState(storeIdToken)
  const [postLogoutUri, setPostLogoutUri] = useState(
    `${window.location.origin}/admin/playground`,
  )
  const [state] = useState(() => generateOAuthState())
  const [navigating, setNavigating] = useState(false)

  const logoutUrl = useMemo(() => {
    const params = new URLSearchParams()
    if (idToken.trim()) params.set('id_token_hint', idToken.trim())
    if (postLogoutUri.trim()) params.set('post_logout_redirect_uri', postLogoutUri.trim())
    if (state) params.set('state', state)
    return `/oauth2/logout?${params.toString()}`
  }, [idToken, postLogoutUri, state])

  const handleExecute = () => {
    setNavigating(true)
    // Full navigation — this is the point of the demo: the browser leaves
    // the SPA, hits the logout endpoint and comes back to post_logout_uri
    // with ?state=... appended by the server.
    window.location.assign(logoutUrl)
  }

  return (
    <div className="space-y-4">
      <FlowStepper steps={STEPS} currentStep={currentStep} completedSteps={currentStep === 'execute' ? ['build'] : []} />

      {currentStep === 'build' && (
        <div className="space-y-3" data-testid="rp-logout-build-step">
          <p className="text-xs text-text-muted">
            OIDC RP-Initiated Logout — instead of logging out of one app while staying signed
            in to the SSO, the app redirects the browser here to end the CENTRAL session too.
          </p>
          <div className="flex items-center gap-3 p-3 rounded-xl bg-surface-2/50 border border-surface-2">
            <code className="text-sm font-mono text-text-secondary">GET /oauth2/logout</code>
          </div>

          <div className="space-y-2">
            <label htmlFor="rp-id-token-hint" className="block text-xs font-medium text-text-secondary">
              id_token_hint <span className="text-text-muted">(required for redirect; pre-filled from earlier flows)</span>
            </label>
            <textarea
              id="rp-id-token-hint"
              data-testid="rp-id-token-hint"
              value={idToken}
              onChange={(e) => setIdToken(e.target.value)}
              rows={3}
              placeholder="eyJhbGciOiJSUzI1NiIs..."
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none break-all"
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="rp-post-logout-uri" className="block text-xs font-medium text-text-secondary">
              post_logout_redirect_uri <span className="text-text-muted">(must be on the client's allowlist)</span>
            </label>
            <input
              id="rp-post-logout-uri"
              data-testid="rp-post-logout-uri"
              value={postLogoutUri}
              onChange={(e) => setPostLogoutUri(e.target.value)}
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-3 py-2 text-sm font-mono text-text-primary focus:border-brand-accent focus:outline-none"
            />
          </div>

          <button
            onClick={() => setCurrentStep('execute')}
            disabled={!idToken.trim() || !postLogoutUri.trim()}
            data-testid="rp-logout-next-btn"
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent hover:scale-[1.02] btn-cta"
          >
            Next: review & execute
          </button>
        </div>
      )}

      {currentStep === 'execute' && (
        <div className="space-y-3" data-testid="rp-logout-execute-step">
          <p className="text-xs font-medium text-text-secondary">Constructed logout URL:</p>
          <code
            data-testid="rp-logout-url"
            className="block rounded-xl border border-surface-2 bg-surface-2/50 p-3 font-mono text-[11px] text-text-secondary break-all"
          >
            {logoutUrl}
          </code>
          <div className="rounded-xl border border-semantic-warning/30 bg-semantic-warning/5 p-3">
            <p className="text-[11px] text-semantic-warning flex items-start gap-2">
              <LogOut size={14} className="mt-0.5 shrink-0" />
              This ends your AuthGlow SSO session — you will need to sign in again afterwards.
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleExecute}
              disabled={navigating}
              data-testid="rp-logout-execute-btn"
              className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent hover:scale-[1.02] btn-cta"
            >
              {navigating ? <Loader2 size={16} className="animate-spin" /> : <LogOut size={16} />}
              Open logout URL
            </button>
            <button
              onClick={() => setCurrentStep('build')}
              className="rounded-xl px-3 py-2 text-xs text-text-muted hover:text-text-secondary"
            >
              Back
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
