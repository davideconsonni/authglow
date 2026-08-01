import { useMemo } from 'react'
import { JsonHighlight } from './JsonHighlight'

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  const pad = base64.length % 4
  if (pad) base64 += '='.repeat(4 - pad)
  return atob(base64)
}

function decodeJwt(token: string): Record<string, unknown> | null {
  const parts = token.split('.')
  if (parts.length < 2) return null
  try {
    return JSON.parse(base64UrlDecode(parts[1]))
  } catch {
    return null
  }
}

export function JwtDecoder({ response }: { response: string }) {
  const tokens = useMemo(() => {
    try {
      const parsed = JSON.parse(response)
      const found: { label: string; value: string }[] = []
      if (parsed.access_token) found.push({ label: 'Access Token', value: parsed.access_token })
      if (parsed.refresh_token) found.push({ label: 'Refresh Token', value: parsed.refresh_token })
      if (parsed.id_token) found.push({ label: 'ID Token', value: parsed.id_token })
      return found
    } catch {
      return []
    }
  }, [response])

  if (tokens.length === 0) {
    return (
      <div className="min-h-[120px] rounded-xl border border-surface-2 bg-surface-2/50 p-4 flex items-center justify-center text-xs text-text-muted">
        No JWT tokens found in this response.
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {tokens.map(t => {
        const payload = decodeJwt(t.value)
        if (!payload) {
          return (
            <div key={t.label} className="rounded-xl border border-semantic-error/20 bg-semantic-error/5 p-3 text-xs text-semantic-error">
              {t.label}: failed to decode
            </div>
          )
        }
        return (
          <div key={t.label} className="space-y-1">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">{t.label}</p>
            <JsonHighlight json={JSON.stringify(payload, null, 2)} maxHeight="max-h-[400px]" />
          </div>
        )
      })}
    </div>
  )
}
