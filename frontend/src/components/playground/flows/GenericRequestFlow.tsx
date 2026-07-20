import { useState } from 'react'
import { Send, Loader2, Globe } from 'lucide-react'
import { api } from '../../../lib/api'
import { ResponsePanel } from '../ResponsePanel'

export function GenericRequestFlow() {
  const [method, setMethod] = useState<'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'>('GET')
  const [endpoint, setEndpoint] = useState('/.well-known/openid-configuration')
  const [body, setBody] = useState('')
  const [response, setResponse] = useState<string | null>(null)
  const [httpStatus, setHttpStatus] = useState<number | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSend = async () => {
    setLoading(true)
    setError('')
    setResponse(null)
    setHttpStatus(null)
    try {
      let result: unknown
      switch (method) {
        case 'GET': result = await api.get(endpoint); break
        case 'POST': result = await api.post(endpoint, body ? JSON.parse(body) : undefined); break
        case 'PUT': result = await api.put(endpoint, body ? JSON.parse(body) : undefined); break
        case 'PATCH': result = await api.patch(endpoint, body ? JSON.parse(body) : undefined); break
        case 'DELETE': result = await api.delete(endpoint); break
      }
      setHttpStatus(200)
      setResponse(JSON.stringify(result, null, 2))
    } catch (err: unknown) {
      if (err instanceof Error && 'status' in err) setHttpStatus((err as { status: number }).status)
      const msg = err instanceof Error ? err.message : 'Request failed'
      setError(msg)
      setResponse(JSON.stringify({ error: msg }, null, 2))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-3">
        <div className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-1">
          {(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMethod(m)}
              className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
                method === m
                  ? m === 'GET' ? 'bg-green-500/20 text-green-400'
                    : m === 'DELETE' ? 'bg-semantic-error/20 text-semantic-error'
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
          onClick={handleSend}
          disabled={loading || !endpoint}
          className="flex items-center gap-2 rounded-xl bg-gradient-cta px-5 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02] disabled:opacity-50"
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

      <ResponsePanel response={response} status={httpStatus} error={error} loading={loading} />
    </div>
  )
}
