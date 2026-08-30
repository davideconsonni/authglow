import { useMemo } from 'react'
import { decodeJwt } from '../../lib/jwt'
import { cn } from '../../lib/utils'

interface JwtRibbonProps {
  token: string
  className?: string
}

export function JwtRibbon({ token, className }: JwtRibbonProps) {
  const decoded = useMemo(() => decodeJwt(token), [token])
  const parts = token.split('.')
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return null

  const headerTitle = decoded
    ? `header · alg: ${String(decoded.header.alg ?? '?')} · typ: ${String(decoded.header.typ ?? 'JWT')}`
    : 'header'
  const payloadTitle = decoded
    ? `payload · ${Object.keys(decoded.payload).length} claims · sub: ${String(decoded.payload.sub ?? '—')}`
    : 'payload'

  return (
    <div
      className={cn('flex flex-wrap items-center gap-1 break-all font-mono text-xs', className)}
      data-testid="jwt-ribbon"
    >
      <span className="jwt-seg jwt-seg-header" title={headerTitle}>{parts[0]}</span>
      <span className="text-text-muted" aria-hidden="true">.</span>
      <span className="jwt-seg jwt-seg-payload" title={payloadTitle}>{parts[1]}</span>
      <span className="text-text-muted" aria-hidden="true">.</span>
      <span className="jwt-seg jwt-seg-signature" title="signature (not verified client-side)">{parts[2]}</span>
    </div>
  )
}
