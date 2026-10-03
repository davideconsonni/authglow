// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { RevocationFlow } from './RevocationFlow'

const mockStore = vi.hoisted(() => ({
  accessToken: 'access-token-1',
  refreshToken: '',
  clientId: 'client-1',
  clientSecret: 'secret-1',
}))
vi.mock('../../../stores/playgroundStore', () => ({ usePlaygroundStore: () => mockStore }))

const mockApi = vi.hoisted(() => ({ postForm: vi.fn() }))
vi.mock('../../../lib/api', () => ({ api: mockApi }))

beforeEach(() => {
  vi.clearAllMocks()
  mockStore.accessToken = 'access-token-1'
  mockStore.refreshToken = ''
  mockStore.clientId = 'client-1'
  mockStore.clientSecret = 'secret-1'
  mockApi.postForm.mockResolvedValue({})
})

function toConfirm() {
  fireEvent.click(screen.getByText('Next'))
}

describe('RevocationFlow', () => {
  it('walks from input to confirm and back', () => {
    render(<RevocationFlow />)
    expect(screen.getByText('Token to Revoke *')).toBeInTheDocument()
    toConfirm()
    expect(screen.getByTestId('confirm-revoke-btn')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Back'))
    expect(screen.getByText('Token to Revoke *')).toBeInTheDocument()
  })

  it('disables Next without a token', () => {
    mockStore.accessToken = ''
    mockStore.refreshToken = ''
    render(<RevocationFlow />)
    expect(screen.getByText('Next')).toBeDisabled()
  })

  it('revokes with Basic auth and the token type hint', async () => {
    render(<RevocationFlow />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'access_token' } })
    toConfirm()
    fireEvent.click(screen.getByTestId('confirm-revoke-btn'))
    await waitFor(() =>
      expect(mockApi.postForm).toHaveBeenCalledWith(
        '/oauth2/revoke',
        { token: 'access-token-1', token_type_hint: 'access_token', client_id: 'client-1' },
        { headers: { Authorization: `Basic ${btoa('client-1:secret-1')}` } },
      ),
    )
    expect(await screen.findByText('Token has been revoked.')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Revoke Another'))
    expect(screen.getByText('Token to Revoke *')).toBeInTheDocument()
  })

  it('revokes without credentials when none are configured', async () => {
    mockStore.clientId = ''
    mockStore.clientSecret = ''
    render(<RevocationFlow />)
    toConfirm()
    fireEvent.click(screen.getByTestId('confirm-revoke-btn'))
    await waitFor(() =>
      expect(mockApi.postForm).toHaveBeenCalledWith(
        '/oauth2/revoke',
        { token: 'access-token-1' },
        { headers: undefined },
      ),
    )
  })

  it('surfaces a revocation failure', async () => {
    const err = Object.assign(new Error('revoke boom'), { status: 400 })
    mockApi.postForm.mockRejectedValueOnce(err)
    render(<RevocationFlow />)
    toConfirm()
    fireEvent.click(screen.getByTestId('confirm-revoke-btn'))
    await waitFor(() => expect(mockApi.postForm).toHaveBeenCalled())
  })

  it('collapses the decoded claims', () => {
    mockStore.accessToken =
      'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.sig'
    render(<RevocationFlow />)
    expect(screen.getByText('Header')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Decoded Claims'))
    expect(screen.queryByText('Header')).not.toBeInTheDocument()
  })
})
