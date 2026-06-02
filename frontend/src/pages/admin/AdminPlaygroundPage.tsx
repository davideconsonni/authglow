import { useState } from 'react'
import { Send, Loader2, Copy, Check, Globe } from 'lucide-react'
import { api } from '@/lib/api'
import { PageHeader } from '@/components/layout/PageHeader'

export function AdminPlaygroundPage() {
  const [method, setMethod] = useState<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'>('GET')
  const [endpoint, setEndpoint] = useState('/.well-known/openid-configuration')
  const [body, setBody] = useState('')
  const [response, setResponse] = useState('')
  const [status, setStatus] = useState<number | null>(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')

  const handleSend = async () => {
    setLoading(true)
    setError('')
    setResponse('')
    setStatus(null)
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
      setStatus(200)
      setResponse(JSON.stringify(result, null, 2))
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Request failed')
      setResponse(JSON.stringify({ error: err instanceof Error ? err.message : 'Unknown' }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = () => {
    if (!response) return
    navigator.clipboard.writeText(response)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div>
      <PageHeader title="API Playground" description="Test OAuth2/OIDC endpoints interactively." />

      <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
        <div className="flex gap-3">
          <div className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-1">
            {(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const).map((m) => (
              <button
                key={m}
                onClick={() => setMethod(m)}
                className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
                  method === m
                    ? m === 'GET' ? 'bg-green-500/20 text-green-400' :
                      m === 'DELETE' ? 'bg-semantic-error/20 text-semantic-error' :
                      'bg-brand-violet/20 text-brand-violet'
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
            onClick={handleSend}
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

        <div className="relative">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-2">
              <p className="text-xs font-medium text-text-muted">Response</p>
              {status && (
                <span className={`rounded-lg px-2 py-0.5 text-xs font-medium ${
                  status < 400 ? 'bg-semantic-success/10 text-semantic-success' : 'bg-semantic-error/10 text-semantic-error'
                }`}>
                  {status}
                </span>
              )}
            </div>
            {response && (
              <button onClick={handleCopy} className="flex items-center gap-1 text-xs text-text-muted hover:text-text-secondary transition-colors">
                {copied ? <Check size={12} className="text-semantic-success" /> : <Copy size={12} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            )}
          </div>
          {error && <div className="mb-2 rounded-xl bg-semantic-error/10 px-3 py-1.5 text-xs text-semantic-error">{error}</div>}
          <pre className="min-h-[200px] max-h-[400px] overflow-auto rounded-xl border border-surface-2 bg-surface-2/50 p-4 font-mono text-xs text-text-secondary whitespace-pre-wrap">
            {response || (loading ? '' : 'Click "Send" to make a request...')}
          </pre>
        </div>
      </div>
    </div>
  )
}
