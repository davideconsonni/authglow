import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Loader2, Plus } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { PageHeader } from '@/components/layout/PageHeader'
import { CopyButton } from '@/components/shared/CopyButton'
import { ROUTES } from '@/lib/constants'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'
import { notify } from '@/stores/toastStore'

interface OAuthClient {
  client_id: string
  client_name?: string
  name?: string
}

interface DeviceAuthResult {
  device_code: string
  user_code: string
  verification_uri: string
  verification_uri_complete: string
  expires_in: number
  interval: number
}

export function DeviceAuthNewTool() {
  useDocumentTitle('New Device Authorization')
  const [selectedClient, setSelectedClient] = useState('')
  const [scope, setScope] = useState('read')
  const [result, setResult] = useState<DeviceAuthResult | null>(null)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState('')

  const { data: clientsData, isLoading: clientsLoading } = useApiQuery<OAuthClient[]>(
    ['admin-oauth-clients'],
    '/api/oauth-clients',
  )
  const clients: OAuthClient[] = Array.isArray(clientsData) ? clientsData : []

  const handleGenerate = async () => {
    if (!selectedClient) {
      setError('Select a client')
      return
    }
    setError('')
    setGenerating(true)
    try {
      const data = await api.postForm<DeviceAuthResult>('/oauth2/device/authorize', {
        client_id: selectedClient,
        scope: scope || 'read',
      })
      setResult(data)
      notify.success('Device authorization generated')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to generate'
      setError(msg)
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <PageHeader
          title="New Device Authorization"
          description="Generate a device code for testing or headless client setup."
        />
        <Link
          to={ROUTES.ADMIN.DEVICE_AUTHORIZATIONS}
          className="text-sm text-brand-violet hover:underline"
        >
          Back to list
        </Link>
      </div>

      <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-5 max-w-lg">
        {clientsLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-brand-violet" />
          </div>
        ) : clients.length === 0 ? (
          <div className="text-center py-8 text-text-muted">
            <p className="text-sm">No OAuth clients configured.</p>
            <Link to={ROUTES.ADMIN.OAUTH_CLIENTS} className="text-sm text-brand-violet hover:underline mt-1 inline-block">
              Create a client first
            </Link>
          </div>
        ) : (
          <>
            <div className="space-y-2">
              <label className="block text-sm font-medium text-text-primary">Client</label>
              <select
                value={selectedClient}
                onChange={(e) => { setSelectedClient(e.target.value); setResult(null) }}
                className="w-full rounded-xl border border-surface-2 bg-surface-2 px-4 py-3 text-sm text-text-primary focus:border-brand-violet focus:outline-none focus:ring-1 focus:ring-brand-violet"
              >
                <option value="">Select a client...</option>
                {clients.map((c) => (
                  <option key={c.client_id} value={c.client_id}>
                    {c.client_name || c.name || c.client_id}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <label className="block text-sm font-medium text-text-primary">Scope</label>
              <input
                type="text"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                placeholder="read write profile"
                className="w-full rounded-xl border border-surface-2 bg-surface-2 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted/50 focus:border-brand-violet focus:outline-none focus:ring-1 focus:ring-brand-violet"
              />
            </div>
            {error && <p className="text-sm text-semantic-error" role="alert">{error}</p>}
            <button
              onClick={handleGenerate}
              disabled={generating || !selectedClient}
              className="w-full inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-cta px-6 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              Generate
            </button>
          </>
        )}

        {result && (
          <div className="space-y-4 pt-4 border-t border-surface-2">
            <h3 className="text-sm font-semibold text-text-primary">Generated Codes</h3>
            <div className="space-y-3">
              <div className="rounded-xl bg-surface-2 p-3 space-y-1">
                <p className="text-xs text-text-muted">User Code</p>
                <div className="flex items-center justify-between gap-2">
                  <code className="text-lg font-mono font-bold text-text-primary tracking-widest">{result.user_code}</code>
                  <CopyButton text={result.user_code} />
                </div>
              </div>
              <div className="rounded-xl bg-surface-2 p-3 space-y-1">
                <p className="text-xs text-text-muted">Device Code</p>
                <div className="flex items-center justify-between gap-2">
                  <code className="text-xs font-mono text-text-secondary break-all">{result.device_code}</code>
                  <CopyButton text={result.device_code} />
                </div>
              </div>
              <div className="rounded-xl bg-surface-2 p-3 space-y-1">
                <p className="text-xs text-text-muted">Verification URI</p>
                <div className="flex items-center justify-between gap-2">
                  <code className="text-sm text-brand-violet">{result.verification_uri_complete}</code>
                  <CopyButton text={result.verification_uri_complete} />
                </div>
              </div>
              <div className="flex gap-4 text-xs text-text-muted">
                <span>Expires: {result.expires_in}s</span>
                <span>Poll interval: {result.interval}s</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
