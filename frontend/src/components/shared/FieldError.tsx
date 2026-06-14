import type { ReactNode } from 'react'

interface FieldErrorProps {
  /** ID used by the input's ``aria-describedby`` to wire the message to its field. */
  id: string
  children: ReactNode
  className?: string
}

/**
 * Inline form-field error message. Single source of truth for the
 * "small red text under an input" pattern used across all auth, setup,
 * and profile forms.
 *
 * Wire the input as:
 *   <input id="email" aria-describedby={errors.email ? 'email-error' : undefined} ... />
 *   {errors.email && <FieldError id="email-error">{errors.email.message}</FieldError>}
 */
export function FieldError({ id, children, className }: FieldErrorProps) {
  return (
    <p
      id={id}
      role="alert"
      data-testid="field-error"
      className={`mt-1 text-[11px] text-semantic-error ${className ?? ''}`}
    >
      {children}
    </p>
  )
}
