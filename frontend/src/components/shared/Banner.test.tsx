// @vitest-environment jsdom
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { Banner } from '@/components/shared/Banner'

describe('Banner', () => {
  it('renders children for the error variant with role="alert"', () => {
    render(<Banner variant="error">Something broke</Banner>)
    const el = screen.getByRole('alert')
    expect(el).toHaveTextContent('Something broke')
    expect(el).toHaveAttribute('data-variant', 'error')
    expect(el).toHaveAttribute('data-testid', 'banner')
  })

  it('renders success/warning/info with role="status"', () => {
    const { rerender } = render(<Banner variant="success">Saved</Banner>)
    expect(screen.getByRole('status')).toHaveTextContent('Saved')

    rerender(<Banner variant="warning">Heads up</Banner>)
    expect(screen.getByRole('status')).toHaveTextContent('Heads up')

    rerender(<Banner variant="info">FYI</Banner>)
    expect(screen.getByRole('status')).toHaveTextContent('FYI')
  })

  it('renders a default icon for each variant', () => {
    const { container } = render(<Banner variant="error">X</Banner>)
    expect(container.querySelector('svg')).toBeTruthy()
  })

  it('hides the icon when icon={null}', () => {
    const { container } = render(<Banner variant="info" icon={null}>No icon</Banner>)
    expect(container.querySelector('svg')).toBeNull()
  })

  it('renders a dismiss button when onDismiss is provided and calls it on click', () => {
    const onDismiss = vi.fn()
    render(<Banner variant="warning" onDismiss={onDismiss}>Dismissable</Banner>)
    const btn = screen.getByRole('button', { name: /dismiss message/i })
    expect(btn).toBeInTheDocument()
    fireEvent.click(btn)
    expect(onDismiss).toHaveBeenCalledTimes(1)
  })

  it('does not render a dismiss button when onDismiss is omitted', () => {
    render(<Banner variant="info">No dismiss</Banner>)
    expect(screen.queryByRole('button', { name: /dismiss message/i })).toBeNull()
  })

  it('applies size="sm" classes when requested', () => {
    render(<Banner variant="info" size="sm">Small</Banner>)
    const el = screen.getByRole('status')
    expect(el.className).toMatch(/text-xs/)
  })

  it('applies size="md" classes by default', () => {
    render(<Banner variant="info">Default</Banner>)
    const el = screen.getByRole('status')
    expect(el.className).toMatch(/text-sm/)
  })

  it('applies sticky positioning when sticky=true', () => {
    render(<Banner variant="error" sticky>Sticky error</Banner>)
    const el = screen.getByRole('alert')
    expect(el.className).toMatch(/sticky/)
  })

  it('respects an explicit role override', () => {
    render(<Banner variant="error" role="status">Quiet</Banner>)
    expect(screen.getByRole('status')).toHaveTextContent('Quiet')
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('forwards a custom data-testid', () => {
    render(<Banner variant="error" data-testid="my-banner">Hi</Banner>)
    expect(screen.getByTestId('my-banner')).toBeInTheDocument()
  })
})
