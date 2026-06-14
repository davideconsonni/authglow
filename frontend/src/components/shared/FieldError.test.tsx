// @vitest-environment jsdom
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FieldError } from '@/components/shared/FieldError'

describe('FieldError', () => {
  it('renders children with role="alert"', () => {
    render(<FieldError id="email-error">Invalid email address</FieldError>)
    const el = screen.getByRole('alert')
    expect(el).toHaveTextContent('Invalid email address')
    expect(el).toHaveAttribute('id', 'email-error')
    expect(el).toHaveAttribute('data-testid', 'field-error')
  })

  it('uses the semantic-error color token', () => {
    render(<FieldError id="x-error">X</FieldError>)
    const el = screen.getByRole('alert')
    expect(el.className).toMatch(/text-semantic-error/)
  })

  it('renders nothing visible when children is empty (caller controls rendering)', () => {
    // FieldError is a presentational component: the parent decides whether
    // to render it at all (typical: {errors.email && <FieldError>...</FieldError>}).
    // When rendered with empty content, it still emits the wrapper.
    const { container } = render(<FieldError id="x-error">{''}</FieldError>)
    expect(container.querySelector('[role="alert"]')).toBeTruthy()
  })
})
