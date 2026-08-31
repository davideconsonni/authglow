// @vitest-environment jsdom
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('../../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), postForm: vi.fn() },
}))

import { ConsentScreen } from './ConsentScreen'

const BASE_PROPS = {
  sessionToken: 'sess-1',
  clientName: 'PaperSpace',
  scopes: [{ name: 'read', description: 'Read your documents' }],
}

describe('ConsentScreen branding contract', () => {
  it('injects --brand-* custom properties on the root when the client has branding', () => {
    render(<ConsentScreen {...BASE_PROPS} branding={{ primary_color: '#2E5BFF', surface_color: '#F4F6FF', font_family: 'Georgia' }} />)
    const style = document.querySelector('.authglow-consent')?.getAttribute('style') ?? ''
    expect(style).toContain('--brand-primary-light: #2E5BFF')
    expect(style).toContain('--brand-primary-dark: #2E5BFF')
    expect(style).toContain('--brand-surface-light: #F4F6FF')
    expect(style).toContain('--brand-font: Georgia')
  })

  it('renders no brand variables for clients without branding', () => {
    render(<ConsentScreen {...BASE_PROPS} branding={null} />)
    const root = document.querySelector('.authglow-consent')
    expect(root?.getAttribute('style') ?? '').not.toContain('--brand-primary')
  })

  it('keeps the themed structure (card + approve button classes) intact', () => {
    render(<ConsentScreen {...BASE_PROPS} />)
    expect(screen.getByTestId('consent-card')).toBeInTheDocument()
    expect(screen.getByText('PaperSpace')).toBeInTheDocument()
    expect(document.querySelector('.consent-approve-btn')).toBeTruthy()
    expect(document.querySelector('.consent-card')).toBeTruthy()
  })
})
