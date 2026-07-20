// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { RevocationFlow } from './RevocationFlow'

const mockStore = vi.hoisted(() => ({
  accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwic2NvcGVzIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJlbWFpbCJdLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTUxNjIzOTAyMn0.signature',
  refreshToken: '',
  setAccessToken: vi.fn(),
}))

vi.mock('../../../stores/playgroundStore', () => ({
  usePlaygroundStore: () => mockStore,
}))

vi.mock('../../../lib/api', () => ({
  api: {
    postForm: vi.fn(),
  },
}))

describe('RevocationFlow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockStore.accessToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwic2NvcGVzIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJlbWFpbCJdLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTUxNjIzOTAyMn0.signature'
    mockStore.refreshToken = ''
  })

  it('renders the token input step', () => {
    render(<RevocationFlow />)
    expect(screen.getByText('Token to Revoke *')).toBeInTheDocument()
    expect(screen.getByText('Token Type Hint')).toBeInTheDocument()
    expect(screen.getByText('Next')).toBeInTheDocument()
  })

  it('renders the FlowStepper with Token, Confirm and Done steps', () => {
    render(<RevocationFlow />)
    expect(screen.getByText('Token')).toBeInTheDocument()
    expect(screen.getByText('Confirm')).toBeInTheDocument()
    expect(screen.getByText('Done')).toBeInTheDocument()
  })

  it('shows decoded claims when a valid JWT is in the store', () => {
    render(<RevocationFlow />)
    expect(screen.getByText('Decoded Claims')).toBeInTheDocument()
    expect(screen.getByText('Header')).toBeInTheDocument()
    expect(screen.getByText('Payload')).toBeInTheDocument()
  })

  it('does not show decoded claims when token is empty', () => {
    mockStore.accessToken = ''
    render(<RevocationFlow />)
    expect(screen.queryByText('Decoded Claims')).not.toBeInTheDocument()
  })

  it('button is disabled when token is empty', () => {
    mockStore.accessToken = ''
    render(<RevocationFlow />)
    expect(screen.getByText('Next')).toBeDisabled()
  })
})
