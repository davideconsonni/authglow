import { Copy, Check, Braces, FileCode2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { cn } from '../../lib/utils'
import { JsonHighlight } from './JsonHighlight'
import { JwtDecoder } from './JwtDecoder'

interface ResponsePanelProps {
  response: string | null
  status: number | null
  error: string
  loading: boolean
  loadingText?: string
  emptyText?: string
  maxHeight?: string
}

function hasJwtTokens(response: string): boolean {
  try {
    const parsed = JSON.parse(response)
    return !!(parsed.access_token || parsed.refresh_token || parsed.id_token)
  } catch {
    return false
  }
}

export function ResponsePanel({
  response,
  status,
  error,
  loading,
  loadingText = 'Waiting for request...',
  emptyText = 'Execute a request to see the response.',
  maxHeight,
}: ResponsePanelProps) {
  const [copied, setCopied] = useState(false)
  const [tab, setTab] = useState<'raw' | 'decoded'>('raw')

  const showDecodedTab = useMemo(
    () => (response ? hasJwtTokens(response) : false),
    [response],
  )

  const handleCopy = () => {
    if (!response) return
    navigator.clipboard.writeText(response)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const statusBadge = status !== null && (
    <span
      className={`rounded-lg px-2 py-0.5 text-xs font-medium ${
        status < 400
          ? 'bg-semantic-success/10 text-semantic-success'
          : 'bg-semantic-error/10 text-semantic-error'
      }`}
    >
      {status}
    </span>
  )

  return (
    <div className="relative">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <p className="text-xs font-medium text-text-muted">Response</p>
          {statusBadge}
          {showDecodedTab && (
            <div className="flex items-center rounded-lg border border-surface-2 bg-surface-1">
              <button
                onClick={() => setTab('raw')}
                className={cn(
                  'flex items-center gap-1 rounded-l-lg px-2 py-0.5 text-[10px] font-medium transition-colors',
                  tab === 'raw'
                    ? 'bg-surface-2 text-text-primary'
                    : 'text-text-muted hover:text-text-secondary',
                )}
              >
                <Braces size={10} />
                Raw
              </button>
              <button
                onClick={() => setTab('decoded')}
                className={cn(
                  'flex items-center gap-1 rounded-r-lg px-2 py-0.5 text-[10px] font-medium transition-colors',
                  tab === 'decoded'
                    ? 'bg-surface-2 text-text-primary'
                    : 'text-text-muted hover:text-text-secondary',
                )}
              >
                <FileCode2 size={10} />
                Decoded
              </button>
            </div>
          )}
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
        tab === 'raw' ? (
          <JsonHighlight json={response} maxHeight={maxHeight} />
        ) : (
          <JwtDecoder response={response} />
        )
      ) : (
        <pre className="min-h-[120px] max-h-[500px] overflow-auto rounded-xl border border-surface-2 bg-surface-2/50 p-4 font-mono text-xs text-text-muted">
          {loading ? loadingText : emptyText}
        </pre>
      )}
    </div>
  )
}
