// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { DeviceCodeFlow } from './DeviceCodeFlow'

const mockStore = vi.hoisted(() => ({
  clientId: 'test-client',
  scopes: 'openid profile',
  setClientId: vi.fn(),
  setScopes: vi.fn(),
  persistTokens: vi.fn(),
}))

vi.mock('@/stores/playgroundStore', () => ({
  usePlaygroundStore: () => mockStore,
  generateState: () => 'random-state',
}))

vi.mock('@/lib/api', () => ({
  api: {
    postForm: vi.fn(),
    post: vi.fn(),
  },
}))

describe('DeviceCodeFlow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the configure step with client ID and scopes inputs', () => {
    render(<DeviceCodeFlow />)
    expect(screen.getByText('Client ID')).toBeInTheDocument()
    expect(screen.getByText('Scopes')).toBeInTheDocument()
  })

  it('renders the FlowStepper with all 5 steps', () => {
    render(<DeviceCodeFlow />)
    expect(screen.getByText('Configure')).toBeInTheDocument()
    expect(screen.getByText('Request')).toBeInTheDocument()
    expect(screen.getByText('Display')).toBeInTheDocument()
    expect(screen.getByText('Verify')).toBeInTheDocument()
    expect(screen.getByText('Poll & Token')).toBeInTheDocument()
  })

  it('shows the description text', () => {
    render(<DeviceCodeFlow />)
    expect(screen.getByText(/RFC 8628/)).toBeInTheDocument()
  })

  it('next button is present in configure step', () => {
    render(<DeviceCodeFlow />)
    expect(screen.getByText('Next')).toBeInTheDocument()
  })
})
