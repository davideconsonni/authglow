// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { DcrFlow } from './DcrFlow'
import { usePlaygroundStore } from '../../../stores/playgroundStore'

vi.mock('../../../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

vi.mock('../ResponsePanel', () => ({
  ResponsePanel: () => <div data-testid="response-panel" />,
}))

import { api } from '../../../lib/api'

const apiPostMock = api.post as ReturnType<typeof vi.fn>
const apiDeleteMock = api.delete as ReturnType<typeof vi.fn>

describe('DcrFlow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    usePlaygroundStore.setState({ clientId: '', clientSecret: '' })
  })

  it('registers a client via POST /oauth2/register and shares credentials with the playground', async () => {
    apiPostMock.mockResolvedValueOnce({
      client_id: 'dcr-client-1',
      client_secret: 'dcr-secret-1',
      client_name: 'Playground Demo App',
    })
    render(<DcrFlow />)

    fireEvent.change(screen.getByTestId('dcr-client-name'), {
      target: { value: 'Playground Demo App' },
    })
    fireEvent.click(screen.getByText('Register Client'))

    await waitFor(() => {
      expect(apiPostMock).toHaveBeenCalledWith('/oauth2/register', {
        client_name: 'Playground Demo App',
        redirect_uris: ['http://localhost:5173/admin/playground/oauth/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic',
      })
    })

    // Manage step reached, secret shown once.
    expect(screen.getByTestId('dcr-manage-step')).toBeInTheDocument()
    expect(screen.getByTestId('dcr-client-id').textContent).toContain('dcr-client-1')

    // Credentials shared with the rest of the playground.
    const { clientId, clientSecret } = usePlaygroundStore.getState()
    expect(clientId).toBe('dcr-client-1')
    expect(clientSecret).toBe('dcr-secret-1')
  })

  it('deletes the registration with HTTP Basic auth (RFC 7592)', async () => {
    apiPostMock.mockResolvedValueOnce({ client_id: 'dcr-client-2', client_secret: 's2' })
    apiDeleteMock.mockResolvedValue(undefined)
    render(<DcrFlow />)

    fireEvent.click(screen.getByText('Register Client'))
    await screen.findByTestId('dcr-manage-step')

    fireEvent.click(screen.getByTestId('dcr-delete-btn'))
    await waitFor(() => {
      expect(apiDeleteMock).toHaveBeenCalledWith(
        '/oauth2/register/dcr-client-2',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: `Basic ${btoa('dcr-client-2:s2')}`,
          }),
        }),
      )
    })
    expect(await screen.findByTestId('dcr-deleted-step')).toBeInTheDocument()
  })
})
