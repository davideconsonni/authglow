import { useEffect, useState } from 'react'
import { Loader2, RotateCcw, Save } from 'lucide-react'
import { cn } from '../../lib/utils'
import {
  RATE_LIMIT_PERIODS,
  formatRateLimit,
  parseRateLimit,
  type RateLimitPeriod,
} from '../../lib/rateLimit'

const SHORTHAND_PATTERN = /^\d+\/(second|minute|hour|day|month|year)$/i

interface RateLimitInputProps {
  route: string
  value: string
  override: string | null
  dirty: boolean
  disabled: boolean
  saving: boolean
  onChange: (value: string) => void
  onSave: () => void
  onReset: () => void
}

export function RateLimitInput({
  route,
  value,
  override,
  dirty,
  disabled,
  saving,
  onChange,
  onSave,
  onReset,
}: RateLimitInputProps) {
  const parsed = parseRateLimit(value)
  const [amountText, setAmountText] = useState<string>(String(parsed?.amount ?? 1))

  // Re-sync the local amount field whenever the committed value changes
  // (save, reset, refetch from another admin's change).
  useEffect(() => {
    setAmountText(String(parsed?.amount ?? 1))
  }, [parsed?.amount])

  const amountValid =
    amountText.trim() !== '' && Number.isFinite(Number(amountText)) && Number(amountText) >= 1

  if (!parsed) {
    // Fallback: free-text editor for limits the structured controls
    // cannot represent (multi-window strings etc.).
    const invalid = dirty && !SHORTHAND_PATTERN.test(value.trim())
    return (
      <div className="flex items-center gap-2">
        <div>
          <input
            type="text"
            aria-label={`Limit for ${route}`}
            aria-invalid={invalid}
            placeholder="e.g. 10/minute"
            value={value}
            disabled={disabled}
            onChange={(e) => onChange(e.target.value)}
            className={cn(
              'w-36 rounded-lg border bg-surface-1 px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:ring-2 disabled:opacity-50',
              invalid
                ? 'border-semantic-error focus:border-semantic-error focus:ring-semantic-error/20'
                : dirty
                  ? 'border-brand-accent focus:border-brand-accent focus:ring-brand-accent/20'
                  : 'border-surface-2 focus:border-brand-accent focus:ring-brand-accent/20',
            )}
          />
          {invalid && (
            <p role="alert" className="mt-1 text-xs text-semantic-error">
              Format: 10/minute
            </p>
          )}
        </div>
        <SaveResetButtons
          route={route}
          showReset={override !== null}
          saveDisabled={!dirty || invalid || disabled}
          resetDisabled={disabled}
          saving={saving}
          onSave={onSave}
          onReset={onReset}
        />
      </div>
    )
  }

  const commitAmount = (text: string) => {
    setAmountText(text)
    const n = Number(text)
    if (text.trim() !== '' && Number.isFinite(n) && n >= 1) {
      onChange(formatRateLimit({ amount: n, period: parsed.period }))
    }
  }

  const changePeriod = (period: RateLimitPeriod) => {
    // Block period changes while the amount is invalid: the row stays
    // clean until both controls hold a representable value.
    if (!amountValid) return
    onChange(formatRateLimit({ amount: Number(amountText), period }))
  }

  return (
    <div className="flex items-center gap-2">
      <div className="flex items-center gap-1.5">
        <input
          type="number"
          min={1}
          aria-label={`Limit amount for ${route}`}
          value={amountText}
          disabled={disabled}
          onChange={(e) => commitAmount(e.target.value)}
          className="w-16 rounded-lg border border-surface-2 bg-surface-1 px-2 py-1.5 text-sm text-text-primary focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20 disabled:opacity-50"
        />
        <select
          aria-label={`Limit period for ${route}`}
          value={parsed.period}
          disabled={disabled}
          onChange={(e) => changePeriod(e.target.value as RateLimitPeriod)}
          className="w-28 rounded-lg border border-surface-2 bg-surface-1 px-2 py-1.5 text-sm text-text-primary focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20 disabled:opacity-50"
        >
          {RATE_LIMIT_PERIODS.map((period) => (
            <option key={period} value={period}>
              per {period}
            </option>
          ))}
        </select>
      </div>
      <SaveResetButtons
        route={route}
        showReset={override !== null}
        saveDisabled={!dirty || !amountValid || disabled}
        resetDisabled={disabled}
        saving={saving}
        onSave={onSave}
        onReset={onReset}
      />
    </div>
  )
}

function SaveResetButtons({
  route,
  showReset,
  saveDisabled,
  resetDisabled,
  saving,
  onSave,
  onReset,
}: {
  route: string
  showReset: boolean
  saveDisabled: boolean
  resetDisabled: boolean
  saving: boolean
  onSave: () => void
  onReset: () => void
}) {
  return (
    <>
      <button
        type="button"
        aria-label={`Save limit for ${route}`}
        disabled={saveDisabled}
        onClick={onSave}
        className={cn(
          'rounded-lg p-1.5 text-brand-accent transition-colors hover:bg-brand-wash',
          saveDisabled && 'cursor-not-allowed opacity-40',
        )}
      >
        {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
      </button>
      {showReset && (
        <button
          type="button"
          aria-label={`Reset limit for ${route}`}
          disabled={resetDisabled}
          onClick={onReset}
          className="rounded-lg p-1.5 text-text-muted transition-colors hover:bg-surface-2 hover:text-text-primary disabled:opacity-50"
        >
          <RotateCcw size={14} />
        </button>
      )}
    </>
  )
}
