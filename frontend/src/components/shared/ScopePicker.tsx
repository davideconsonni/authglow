import { useState, useEffect } from 'react'
import { api } from '../../lib/api'
import { X } from 'lucide-react'

interface ScopePickerProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  disabled?: boolean
  testId?: string
}

export function ScopePicker({
  value,
  onChange,
  placeholder = 'Select scopes',
  disabled = false,
  testId,
}: ScopePickerProps) {
  const [availableScopes, setAvailableScopes] = useState<string[]>([])
  const [customInput, setCustomInput] = useState('')

  useEffect(() => {
    api.get<{ scopes: string[] }>('/api/scopes')
      .then((data) => setAvailableScopes(Array.isArray(data?.scopes) ? data.scopes : []))
      .catch(() => setAvailableScopes([]))
  }, [])

  const selectedScopes = value.trim().split(/\s+/).filter(Boolean)

  const toggleScope = (scope: string) => {
    if (disabled) return
    const newScopes = selectedScopes.includes(scope)
      ? selectedScopes.filter((s) => s !== scope)
      : [...selectedScopes, scope]
    onChange(newScopes.join(' '))
  }

  const addCustomScope = () => {
    const trimmed = customInput.trim()
    if (!trimmed || disabled) return
    if (!selectedScopes.includes(trimmed)) {
      onChange([...selectedScopes, trimmed].join(' '))
    }
    setCustomInput('')
  }

  const removeScope = (scope: string) => {
    if (disabled) return
    onChange(selectedScopes.filter((s) => s !== scope).join(' '))
  }

  return (
    <div className="space-y-3">
      {/* Available scopes as chips */}
      {availableScopes.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {availableScopes.map((scope) => {
            const isSelected = selectedScopes.includes(scope)
            return (
              <button
                key={scope}
                type="button"
                onClick={() => toggleScope(scope)}
                disabled={disabled}
                className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                  isSelected
                    ? 'bg-brand-accent text-white'
                    : 'bg-surface-2 text-text-secondary hover:bg-surface-2/80'
                } ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
              >
                {scope}
              </button>
            )
          })}
        </div>
      )}

      {/* Selected scopes with remove buttons */}
      {selectedScopes.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {selectedScopes.map((scope) => (
            <span
              key={scope}
              className="inline-flex items-center gap-1 rounded-lg bg-brand-wash px-2.5 py-1 text-xs font-medium text-brand-accent"
            >
              {scope}
              {!disabled && (
                <button
                  type="button"
                  onClick={() => removeScope(scope)}
                  className="hover:text-brand-accent/70"
                  aria-label={`Remove ${scope}`}
                >
                  <X size={12} />
                </button>
              )}
            </span>
          ))}
        </div>
      )}

      {/* Custom scope input */}
      <div className="flex gap-2">
        <input
          type="text"
          value={customInput}
          onChange={(e) => setCustomInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              addCustomScope()
            }
          }}
          placeholder={placeholder}
          disabled={disabled}
          data-testid={testId ? `${testId}-custom-input` : undefined}
          className="flex-1 rounded-xl border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none disabled:opacity-50"
        />
        <button
          type="button"
          onClick={addCustomScope}
          disabled={disabled || !customInput.trim()}
          className="rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white disabled:opacity-50"
        >
          Add
        </button>
      </div>
    </div>
  )
}
