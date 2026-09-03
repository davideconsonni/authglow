// Dynamic Client Registration flow (RFC 7591 / 7592).
//
// Walks the full lifecycle: register a client via POST /oauth2/register
// (public — no auth), then manage it with HTTP Basic (client_id:secret)
// via RFC 7592 GET/PUT/DELETE. The plaintext secret is returned exactly
// once, at registration time.

import { useState } from 'react'
import { Loader2, RefreshCw, Trash2, UserPlus } from 'lucide-react'
import { api } from '../../../lib/api'
import { usePlaygroundStore } from '../../../stores/playgroundStore'
import { FlowStepper } from '../FlowStepper'
import { ResponsePanel } from '../ResponsePanel'

const STEPS = [
  { id: 'register', label: 'Register' },
  { id: 'manage', label: 'Manage' },
  { id: 'deleted', label: 'Deleted' },
]

export function DcrFlow() {
  const setStoreClientId = usePlaygroundStore((s) => s.setClientId)
  const setStoreClientSecret = usePlaygroundStore((s) => s.setClientSecret)

  const [currentStep, setCurrentStep] = useState('register')
  const [completed, setCompleted] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)

  const [clientName, setClientName] = useState('Playground Demo App')
  const [redirectUris, setRedirectUris] = useState(
    'http://localhost:5173/admin/playground/oauth/callback',
  )
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')

  const basicHeader = () => `Basic ${btoa(`${clientId}:${clientSecret}`)}`

  const handleRegister = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      const payload = {
        client_name: clientName,
        redirect_uris: redirectUris.split(',').map(u => u.trim()).filter(Boolean),
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic',
      }
      const result = await api.post<Record<string, unknown>>('/oauth2/register', payload)
      setHttpStatus(201)
      setResponse(JSON.stringify(result, null, 2))
      const newId = String(result.client_id ?? '')
      const newSecret = String(result.client_secret ?? '')
      setClientId(newId)
      setClientSecret(newSecret)
      // Share with the rest of the playground (other flows reuse these).
      setStoreClientId(newId)
      if (newSecret) setStoreClientSecret(newSecret)
      setCompleted(['register'])
      setCurrentStep('manage')
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) setHttpStatus((err as { status: number }).status)
      const msg = err instanceof Error ? err.message : 'Failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleUpdate = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    try {
      const result = await api.put<Record<string, unknown>>(
        `/oauth2/register/${encodeURIComponent(clientId)}`,
        { client_name: `${clientName} (updated)` },
        { headers: { Authorization: basicHeader() } },
      )
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) setHttpStatus((err as { status: number }).status)
      const msg = err instanceof Error ? err.message : 'Failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    try {
      await api.delete(`/oauth2/register/${encodeURIComponent(clientId)}`, {
        headers: { Authorization: basicHeader() },
      })
      setHttpStatus(204)
      setResponse(JSON.stringify({ result: 'Registration deleted (HTTP 204 No Content)' }))
      setCompleted(['register', 'manage'])
      setCurrentStep('deleted')
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) setHttpStatus((err as { status: number }).status)
      const msg = err instanceof Error ? err.message : 'Failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleReset = () => {
    setCurrentStep('register')
    setCompleted([])
    setResponse(null)
    setError('')
    setHttpStatus(null)
    setClientId('')
    setClientSecret('')
  }

  return (
    <div className="space-y-4">
      <FlowStepper steps={STEPS} currentStep={currentStep} completedSteps={completed} />

      {currentStep === 'register' && (
        <div className="space-y-3" data-testid="dcr-register-step">
          <p className="text-xs text-text-muted">
            Dynamic Client Registration — the app registers ITSELF via API instead of an admin
            creating it manually. The client_secret is returned only once, in this response.
          </p>
          <div className="flex items-center gap-3 p-3 rounded-xl bg-surface-2/50 border border-surface-2">
            <code className="text-sm font-mono text-text-secondary">POST /oauth2/register</code>
          </div>
          <div className="space-y-2">
            <label htmlFor="dcr-client-name" className="block text-xs font-medium text-text-secondary">Client name</label>
            <input
              id="dcr-client-name"
              data-testid="dcr-client-name"
              value={clientName}
              onChange={(e) => setClientName(e.target.value)}
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary focus:border-brand-accent focus:outline-none"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="dcr-redirect-uris" className="block text-xs font-medium text-text-secondary">
              Redirect URIs (comma separated)
            </label>
            <textarea
              id="dcr-redirect-uris"
              data-testid="dcr-redirect-uris"
              value={redirectUris}
              onChange={(e) => setRedirectUris(e.target.value)}
              rows={2}
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-3 py-2 text-sm font-mono text-text-primary focus:border-brand-accent focus:outline-none"
            />
          </div>
          <button
            onClick={handleRegister}
            disabled={loading}
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent hover:scale-[1.02] btn-cta"
          >
            {loading ? <Loader2 size={16} className="animate-spin" /> : <UserPlus size={16} />}
            Register Client
          </button>
        </div>
      )}

      {currentStep === 'manage' && (
        <div className="space-y-3" data-testid="dcr-manage-step">
          <p className="text-xs text-text-muted">
            Registered! Now manage the registration with RFC 7592 endpoints authenticated via
            HTTP Basic (<code>client_id:client_secret</code>).
          </p>
          <div className="rounded-xl border border-semantic-warning/30 bg-semantic-warning/5 p-3">
            <p className="font-mono text-[11px] text-text-secondary break-all" data-testid="dcr-client-id">
              client_id: {clientId}
            </p>
            {clientSecret && (
              <p className="mt-1 font-mono text-[11px] text-semantic-warning break-all">
                client_secret (shown once): {clientSecret}
              </p>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={handleUpdate}
              disabled={loading}
              className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-3 btn-cta"
            >
              <RefreshCw size={14} /> Update name (PUT)
            </button>
            <button
              onClick={handleDelete}
              disabled={loading}
              data-testid="dcr-delete-btn"
              className="flex items-center gap-2 rounded-xl border border-semantic-error/40 px-4 py-2 text-sm text-semantic-error hover:bg-semantic-error/10 btn-cta"
            >
              <Trash2 size={14} /> Delete registration (DELETE)
            </button>
            <button onClick={handleReset} className="rounded-xl px-3 py-2 text-xs text-text-muted hover:text-text-secondary">
              Start over
            </button>
          </div>
        </div>
      )}

      {currentStep === 'deleted' && (
        <div className="space-y-3" data-testid="dcr-deleted-step">
          <p className="text-xs text-semantic-success">
            Registration deleted — the client_id no longer exists on the server.
          </p>
          <button onClick={handleReset} className="flex items-center gap-2 rounded-xl bg-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-3">
            <RefreshCw size={16} /> Register another client
          </button>
        </div>
      )}

      <ResponsePanel response={response} status={httpStatus} error={error} loading={loading} />
    </div>
  )
}
