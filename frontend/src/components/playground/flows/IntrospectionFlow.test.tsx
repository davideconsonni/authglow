// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { IntrospectionFlow } from './IntrospectionFlow'

const mockStore = vi.hoisted(() => ({
  accessToken: 'header.payload.sig',
  clientId: 'introspect-client',
  clientSecret: 'introspect-secret',
  refreshToken: '',
  apiKey: '',
  setAccessToken: vi.fn(),
  setClientId: vi.fn(),
  setClientSecret: vi.fn(),
  setRefreshToken: vi.fn(),
  setApiKey: vi.fn(),
  persistTokens: vi.fn(),
}))

vi.mock('../../../stores/playgroundStore', () => ({ usePlaygroundStore: () => mockStore }))

const mockApi = vi.hoisted(() => ({
  postForm: vi.fn(),
  post: vi.fn(),
  get: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
}))
vi.mock('../../../lib/api', () => ({ api: mockApi }))

vi.mock('../../../lib/jwt', () => ({
  decodeJwt: vi.fn(() => ({ header: { alg: 'RS256' }, payload: { sub: 'u-1' } })),
}))

vi.mock('../../shared/JwtRibbon', () => ({ JwtRibbon: () => <div data-testid="jwt-ribbon" /> }))

beforeEach(() => {
  vi.clearAllMocks()
  mockStore.accessToken = 'header.payload.sig'
  mockApi.postForm.mockResolvedValue({ active: true })
})

describe('IntrospectionFlow', () => {
  it('shows the auto-fill hint and the decoded claims', () => {
    render(<IntrospectionFlow />)
    expect(screen.getByText(/Access token auto-filled from previous flow./)).toBeInTheDocument()
    expect(screen.getByText('Decoded Claims')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Decoded Claims'))
    expect(screen.queryByTestId('jwt-ribbon')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('Decoded Claims'))
    expect(screen.getByTestId('jwt-ribbon')).toBeInTheDocument()
  })

  it('introspects a token and resets', async () => {
    render(<IntrospectionFlow />)
    fireEvent.click(screen.getByText('Next'))
    expect(screen.getByText(/Client authentication via Basic Auth header/)).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('introspect-btn'))
    await screen.findByText('true')
    expect(mockApi.postForm).toHaveBeenCalledWith(
      '/oauth2/introspect',
      { token: 'header.payload.sig' },
      { headers: { Authorization: `Basic ${btoa('introspect-client:introspect-secret')}` } },
    )

    fireEvent.click(screen.getByText('Introspect Another Token'))
    expect(screen.getByText(/Token introspection/)).toBeInTheDocument()
  })

  it('passes the token_type_hint when selected', async () => {
    render(<IntrospectionFlow />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'refresh_token' } })
    fireEvent.click(screen.getByText('Next'))
    fireEvent.click(screen.getByTestId('introspect-btn'))
    await screen.findByText('true')
    expect(mockApi.postForm).toHaveBeenCalledWith(
      '/oauth2/introspect',
      { token: 'header.payload.sig', token_type_hint: 'refresh_token' },
      expect.anything(),
    )
  })

  it('surfaces an introspection error', async () => {
    mockApi.postForm.mockRejectedValueOnce(new Error('introspect boom'))
    render(<IntrospectionFlow />)
    fireEvent.click(screen.getByText('Next'))
    fireEvent.click(screen.getByTestId('introspect-btn'))
    await screen.findByText('introspect boom')
  })
})
