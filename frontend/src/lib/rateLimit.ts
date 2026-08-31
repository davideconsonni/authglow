/**
 * Rate-limit limit-string helpers shared by the admin rate-limits UI.
 *
 * slowapi limit strings come in two shapes: the shorthand accepted by
 * ``limits.parse_many`` (``"10/minute"``) and the ``str(RateLimitItem)``
 * form returned by the backend (``"10 per 1 minute"``). These helpers
 * parse both, compose the canonical shorthand, and normalize for
 * change detection.
 */

// Granularities accepted by ``limits.parse_many`` (the backend stays
// the source of truth — an invalid string still gets a 400 from
// PUT /api/admin/rate-limits/config).
export const RATE_LIMIT_PERIODS = [
  'second',
  'minute',
  'hour',
  'day',
  'month',
  'year',
] as const
export type RateLimitPeriod = (typeof RATE_LIMIT_PERIODS)[number]

export interface ParsedRateLimit {
  amount: number
  period: RateLimitPeriod
}

/**
 * Parse a slowapi limit string into (amount, period) for the
 * structured editor. Returns ``null`` for values the two-control
 * editor cannot represent (e.g. multi-window ``"5 per 2 hours"``) —
 * callers fall back to a raw text editor.
 */
export function parseRateLimit(value: string): ParsedRateLimit | null {
  const match = value
    .trim()
    .match(/^(\d+)\s*(?:\/|per\s+(\d+)\s*)?(second|minute|hour|day|month|year)s?$/i)
  if (!match) return null
  const amount = Number(match[1])
  const multiplier = match[2] ? Number(match[2]) : 1
  if (!Number.isFinite(amount) || amount < 1 || multiplier !== 1) return null
  return { amount, period: match[3].toLowerCase() as RateLimitPeriod }
}

export function formatRateLimit(parsed: ParsedRateLimit): string {
  return `${parsed.amount}/${parsed.period}`
}

/**
 * Canonical form used for change detection: ``"10 per 1 minute"`` and
 * ``"10/minute"`` normalize to the same string.
 */
export function normalizeRateLimit(value: string): string {
  const parsed = parseRateLimit(value)
  return parsed ? formatRateLimit(parsed) : value.trim()
}
