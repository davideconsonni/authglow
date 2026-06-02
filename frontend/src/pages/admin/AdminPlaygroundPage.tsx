import { useState, useMemo } from 'react'
import {
  Send,
  Loader2,
  Copy,
  Check,
  Globe,
  Eye,
  UserCheck,
  Trash2,
  Key,
  BookOpen,
  Braces,
} from 'lucide-react'
import { api } from '@/lib/api'
import { PageHeader } from '@/components/layout/PageHeader'

type Tab = 'generic' | 'introspect' | 'userinfo' | 'revoke' | 'apikey-exchange' | 'discovery'

const TABS: { id: Tab; label: string; icon: typeof Braces }[] = [
  { id: 'generic', label: 'Generic', icon: Braces },
  { id: 'introspect', label: 'Introspect', icon: Eye },
  { id: 'userinfo', label: 'UserInfo', icon: UserCheck },
  { id: 'revoke', label: 'Revoke', icon: Trash2 },
  { id: 'apikey-exchange', label: 'API Key Exchange', icon: Key },
  { id: 'discovery', label: 'OIDC Discovery', icon: BookOpen },
]

const JSON_KEY = /("(?:[^"\\]|\\.)*")\s*:/g
const JSON_STRING = /("(?:[^"\\]|\\.)*")/g
const JSON_NUMBER = /(-?\d+\.?\d*(?:[eE][+-]?\d+)?)/g
const JSON_BOOL_NULL = /\b(true|false|null)\b/g

function highlightJson(json: string): string {
  let html = json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')

  html = html.replace(JSON_KEY, '<span class="text-brand-violet">$1</span>:')
  html = html.replace(JSON_BOOL_NULL, '<span class="text-amber-400">$1</span>')
  html = html.replace(JSON_NUMBER, '<span class="text-emerald-400">$1</span>')
  html = html.replace(JSON_STRING, (match) => {
    if (match.includes('text-brand-violet')) return match
    return `<span class="text-emerald-300">${match}</span>`
  })

  return html
}

function JsonHighlight({ json }: { json: string }) {
  const highlighted = useMemo(() => highlightJson(json), [json])

  return (
    <pre
      className="min-h-[200px] max-h-[500px] overflow-auto rounded-xl border border-surface-2 bg-surface-2/50 p-4 font-mono text-xs whitespace-pre-wrap leading-relaxed"
      dangerouslySetInnerHTML={{ __html: highlighted }}
    />
  )
}

export function AdminPlaygroundPage() {
  const [tab, setTab] = useState<Tab>('generic')

  const [method, setMethod] = useState<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'>('GET')
  const [endpoint, setEndpoint] = useState('/.well-known/openid-configuration')
  const [body, setBody] = useState('')
  const [response, setResponse] = useState('')
  const [httpStatus, setHttpStatus] = useState<number | null>(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')

  const [introspectToken, setIntrospectToken] = useState('')
  const [introspectHint, setIntrospectHint] = useState('')
  const [introspectClientId, setIntrospectClientId] = useState('')
  const [introspectClientSecret, setIntrospectClientSecret] = useState('')

  const [revokeToken, setRevokeToken] = useState('')
  const [revokeHint, setRevokeHint] = useState('')

  const [apiKeyValue, setApiKeyValue] = useState('')

  const setTabAndPreset = (t: Tab) => {
    setTab(t)
    setResponse('')
    setHttpStatus(null)
    setError('')
    switch (t) {
      case 'generic':
        break
      case 'introspect':
        setMethod('POST')
        setEndpoint('/oauth2/introspect')
        break
      case 'userinfo':
        setMethod('GET')
        setEndpoint('/oauth2/userinfo')
        break
      case 'revoke':
        setMethod('POST')
        setEndpoint('/oauth2/revoke')
        break
      case 'apikey-exchange':
        setMethod('POST')
        setEndpoint('/api/token/api-key')
        break
      case 'discovery':
        setMethod('GET')
        setEndpoint('/.well-known/openid-configuration')
        break
    }
  }

  const handleCopy = () => {
    if (!response) return
    navigator.clipboard.writeText(response)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleGenericSend = async () => {
    setLoading(true)
    setError('')
    setResponse('')
    setHttpStatus(null)
    try {
      let result: unknown
      switch (method) {
        case 'GET':
          result = await api.get(endpoint)
          break
        case 'POST':
          result = await api.post(endpoint, body ? JSON.parse(body) : undefined)
          break
        case 'PUT':
          result = await api.put(endpoint, body ? JSON.parse(body) : undefined)
          break
        case 'PATCH':
          result = await api.patch(endpoint, body ? JSON.parse(body) : undefined)
          break
        case 'DELETE':
          result = await api.delete(endpoint)
          break
      }
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) {
        setHttpStatus((err as { status: number }).status)
      }
      const msg = err instanceof Error ? err.message : 'Request failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleIntrospect = async () => {
    setLoading(true)
    setError('')
    setResponse('')
    setHttpStatus(null)
    try {
      const formBody: Record<string, string> = { token: introspectToken }
      if (introspectHint) formBody.token_type_hint = introspectHint
      const headers: Record<string, string> = {}
      if (introspectClientId && introspectClientSecret) {
        headers['Authorization'] = 'Basic ' + btoa(`${introspectClientId}:${introspectClientSecret}`)
      }
      const result = await api.postForm('/oauth2/introspect', formBody, { headers })
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) {
        setHttpStatus((err as { status: number }).status)
      }
      const msg = err instanceof Error ? err.message : 'Request failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleUserinfo = async () => {
    setLoading(true)
    setError('')
    setResponse('')
    setHttpStatus(null)
    try {
      const result = await api.get('/oauth2/userinfo')
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) {
        setHttpStatus((err as { status: number }).status)
      }
      const msg = err instanceof Error ? err.message : 'Request failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleRevoke = async () => {
    setLoading(true)
    setError('')
    setResponse('')
    setHttpStatus(null)
    try {
      const formBody: Record<string, string> = { token: revokeToken }
      if (revokeHint) formBody.token_type_hint = revokeHint
      const result = await api.postForm('/oauth2/revoke', formBody)
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2) || '{} (Token revoked — empty 200 response per RFC 7009)')
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) {
        setHttpStatus((err as { status: number }).status)
      }
      const msg = err instanceof Error ? err.message : 'Request failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleApiKeyExchange = async () => {
    setLoading(true)
    setError('')
    setResponse('')
    setHttpStatus(null)
    try {
      const headers: Record<string, string> = {
        'Authorization': `Bearer ${apiKeyValue}`,
      }
      const result = await api.post('/api/token/api-key', undefined, { headers })
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) {
        setHttpStatus((err as { status: number }).status)
      }
      const msg = err instanceof Error ? err.message : 'Request failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleDiscovery = async () => {
    setLoading(true)
    setError('')
    setResponse('')
    setHttpStatus(null)
    try {
      const result = await api.get('/.well-known/openid-configuration')
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) {
        setHttpStatus((err as { status: number }).status)
      }
      const msg = err instanceof Error ? err.message : 'Request failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const statusBadge = httpStatus !== null && (
    <span
      className={`rounded-lg px-2 py-0.5 text-xs font-medium ${
        httpStatus < 400
          ? 'bg-semantic-success/10 text-semantic-success'
          : 'bg-semantic-error/10 text-semantic-error'
      }`}
    >
      {httpStatus}
    </span>
  )

  return (
    <div>
      <PageHeader
        title="API Playground"
        description="Debug OAuth2 / OIDC endpoints interactively. Test introspection, revoke tokens, exchange API keys, and explore the OIDC discovery document."
      />

      <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-5">
        <div className="flex gap-1 overflow-x-auto pb-1">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setTabAndPreset(id)}
              className={`flex items-center gap-1.5 rounded-xl px-3.5 py-2 text-xs font-medium whitespace-nowrap transition-colors ${
                tab === id
                  ? 'bg-brand-violet/20 text-brand-violet'
                  : 'text-text-muted hover:text-text-secondary hover:bg-surface-2'
              }`}
            >
              <Icon size={14} />
              {label}
            </button>
          ))}
        </div>

        {tab === 'generic' && (
          <div className="space-y-4">
            <div className="flex gap-3">
              <div className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-1">
                {(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const).map((m) => (
                  <button
                    key={m}
                    onClick={() => setMethod(m)}
                    className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
                      method === m
                        ? m === 'GET'
                          ? 'bg-green-500/20 text-green-400'
                          : m === 'DELETE'
                            ? 'bg-semantic-error/20 text-semantic-error'
                            : 'bg-brand-violet/20 text-brand-violet'
                        : 'text-text-muted hover:text-text-secondary'
                    }`}
                  >
                    {m}
                  </button>
                ))}
              </div>
              <div className="relative flex-1">
                <Globe size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                <input
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  placeholder="/api/endpoint"
                  className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 pl-9 pr-4 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
                />
              </div>
              <button
                onClick={handleGenericSend}
                disabled={loading || !endpoint}
                className="flex items-center gap-2 rounded-xl bg-gradient-cta px-5 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50"
              >
                {loading ? <Loader2 size={16} className="animate-spin" /> : <Send size={16} />}
                Send
              </button>
            </div>
            {(method === 'POST' || method === 'PUT' || method === 'PATCH') && (
              <div>
                <p className="mb-1 text-xs font-medium text-text-muted">Request Body (JSON)</p>
                <textarea
                  value={body}
                  onChange={(e) => setBody(e.target.value)}
                  placeholder='{ "key": "value" }'
                  rows={5}
                  className="w-full rounded-xl border border-surface-2 bg-surface-1 p-3 font-mono text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none resize-y"
                />
              </div>
            )}
          </div>
        )}

        {tab === 'introspect' && (
          <div className="space-y-3">
            <p className="text-xs text-text-muted">
              RFC 7662 — Introspect an access or refresh token. Requires client authentication via Basic Auth.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block mb-1 text-xs font-medium text-text-muted">Token *</label>
                <textarea
                  value={introspectToken}
                  onChange={(e) => setIntrospectToken(e.target.value)}
                  placeholder="eyJhbGciOiJSUzI1NiIs..."
                  rows={3}
                  className="w-full rounded-xl border border-surface-2 bg-surface-1 p-3 font-mono text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none resize-y"
                />
              </div>
              <div className="space-y-3">
                <div>
                  <label className="block mb-1 text-xs font-medium text-text-muted">Token Type Hint</label>
                  <select
                    value={introspectHint}
                    onChange={(e) => setIntrospectHint(e.target.value)}
                    className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 text-sm text-text-primary focus:border-brand-violet focus:outline-none"
                  >
                    <option value="">Auto-detect</option>
                    <option value="access_token">Access Token</option>
                    <option value="refresh_token">Refresh Token</option>
                  </select>
                </div>
                <div>
                  <label className="block mb-1 text-xs font-medium text-text-muted">Client ID (Basic Auth)</label>
                  <input
                    value={introspectClientId}
                    onChange={(e) => setIntrospectClientId(e.target.value)}
                    placeholder="client_id"
                    className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block mb-1 text-xs font-medium text-text-muted">Client Secret (Basic Auth)</label>
                  <input
                    value={introspectClientSecret}
                    onChange={(e) => setIntrospectClientSecret(e.target.value)}
                    type="password"
                    placeholder="client_secret"
                    className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
                  />
                </div>
              </div>
            </div>
            <button
              onClick={handleIntrospect}
              disabled={loading || !introspectToken}
              className="flex items-center gap-2 rounded-xl bg-gradient-cta px-5 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <Eye size={16} />}
              Introspect Token
            </button>
          </div>
        )}

        {tab === 'userinfo' && (
          <div className="space-y-3">
            <p className="text-xs text-text-muted">
              OpenID Connect UserInfo endpoint. Sends the current Bearer token from your session. Returns claims about the authenticated user.
            </p>
            <div className="flex items-center gap-3 p-3 rounded-xl bg-surface-2/50 border border-surface-2">
              <Globe size={14} className="text-text-muted shrink-0" />
              <code className="text-sm font-mono text-text-secondary">GET /oauth2/userinfo</code>
            </div>
            <button
              onClick={handleUserinfo}
              disabled={loading}
              className="flex items-center gap-2 rounded-xl bg-gradient-cta px-5 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <UserCheck size={16} />}
              Fetch UserInfo
            </button>
          </div>
        )}

        {tab === 'revoke' && (
          <div className="space-y-3">
            <p className="text-xs text-text-muted">
              RFC 7009 — Revoke an access or refresh token. Per spec, always returns 200 OK to prevent token scanning.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block mb-1 text-xs font-medium text-text-muted">Token *</label>
                <textarea
                  value={revokeToken}
                  onChange={(e) => setRevokeToken(e.target.value)}
                  placeholder="Paste the token to revoke..."
                  rows={3}
                  className="w-full rounded-xl border border-surface-2 bg-surface-1 p-3 font-mono text-xs text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none resize-y"
                />
              </div>
              <div>
                <label className="block mb-1 text-xs font-medium text-text-muted">Token Type Hint</label>
                <select
                  value={revokeHint}
                  onChange={(e) => setRevokeHint(e.target.value)}
                  className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 text-sm text-text-primary focus:border-brand-violet focus:outline-none"
                >
                  <option value="">Auto-detect</option>
                  <option value="access_token">Access Token</option>
                  <option value="refresh_token">Refresh Token</option>
                </select>
              </div>
            </div>
            <button
              onClick={handleRevoke}
              disabled={loading || !revokeToken}
              className="flex items-center gap-2 rounded-xl bg-semantic-error px-5 py-2 text-sm font-semibold text-white transition-all hover:scale-[1.02] disabled:opacity-50"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <Trash2 size={16} />}
              Revoke Token
            </button>
          </div>
        )}

        {tab === 'apikey-exchange' && (
          <div className="space-y-3">
            <p className="text-xs text-text-muted">
              Exchange an API key for a short-lived JWT access token. Send the API key as a Bearer token in the Authorization header.
            </p>
            <div className="flex items-center gap-3 p-3 rounded-xl bg-surface-2/50 border border-surface-2">
              <Globe size={14} className="text-text-muted shrink-0" />
              <code className="text-sm font-mono text-text-secondary">POST /api/token/api-key</code>
              <span className="text-xs text-text-muted">Authorization: Bearer &lt;api_key&gt;</span>
            </div>
            <div>
              <label className="block mb-1 text-xs font-medium text-text-muted">API Key *</label>
              <input
                value={apiKeyValue}
                onChange={(e) => setApiKeyValue(e.target.value)}
                type="password"
                placeholder="ag_..."
                className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 px-3 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>
            <button
              onClick={handleApiKeyExchange}
              disabled={loading || !apiKeyValue}
              className="flex items-center gap-2 rounded-xl bg-gradient-cta px-5 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <Key size={16} />}
              Exchange API Key
            </button>
          </div>
        )}

        {tab === 'discovery' && (
          <div className="space-y-3">
            <p className="text-xs text-text-muted">
              OpenID Connect Discovery — Returns the OIDC provider metadata including all endpoint URLs, supported scopes, and cryptographic keys URI.
            </p>
            <div className="flex items-center gap-3 p-3 rounded-xl bg-surface-2/50 border border-surface-2">
              <Globe size={14} className="text-text-muted shrink-0" />
              <code className="text-sm font-mono text-text-secondary">GET /.well-known/openid-configuration</code>
            </div>
            <button
              onClick={handleDiscovery}
              disabled={loading}
              className="flex items-center gap-2 rounded-xl bg-gradient-cta px-5 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50"
            >
              {loading ? <Loader2 size={16} className="animate-spin" /> : <BookOpen size={16} />}
              Fetch Discovery
            </button>
          </div>
        )}

        <div className="relative">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-2">
              <p className="text-xs font-medium text-text-muted">Response</p>
              {statusBadge}
            </div>
            {response && (
              <button
                onClick={handleCopy}
                className="flex items-center gap-1 text-xs text-text-muted hover:text-text-secondary transition-colors"
              >
                {copied ? <Check size={12} className="text-semantic-success" /> : <Copy size={12} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            )}
          </div>
          {error && (
            <div className="mb-2 rounded-xl bg-semantic-error/10 px-3 py-1.5 text-xs text-semantic-error">
              {error}
            </div>
          )}
          {response ? (
            <JsonHighlight json={response} />
          ) : (
            <pre className="min-h-[200px] max-h-[500px] overflow-auto rounded-xl border border-surface-2 bg-surface-2/50 p-4 font-mono text-xs text-text-muted">
              {loading ? '' : 'Select a tab and execute a request...'}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}
