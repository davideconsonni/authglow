// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { DcrFlow } from './DcrFlow'

const mockStore = vi.hoisted(() => ({ setClientId: vi.fn(), setClientSecret: vi.fn() }))
vi.mock('../../../stores/playgroundStore', () => ({
  usePlaygroundStore: (selector?: (s: typeof mockStore) => unknown) =>
    selector ? selector(mockStore) : mockStore,
}))

const mockApi = vi.hoisted(() => ({ post: vi.fn(), put: vi.fn(), delete: vi.fn() }))
vi.mock('../../../lib/api', () => ({ api: mockApi }))

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.post.mockResolvedValue({ client_id: 'cid-1', client_secret: 'sec-1' })
  mockApi.put.mockResolvedValue({ client_id: 'cid-1' })
  mockApi.delete.mockResolvedValue({})
})

async function register() {
  render(<DcrFlow />)
  fireEvent.click(screen.getByText('Register Client'))
  await screen.findByTestId('dcr-manage-step')
}

describe('DcrFlow', () => {
  it('registers a client and shares the credentials with the store', async () => {
    render(<DcrFlow />)
    fireEvent.change(screen.getByTestId('dcr-client-name'), { target: { value: 'My App' } })
    fireEvent.change(screen.getByTestId('dcr-redirect-uris'), {
      target: { value: 'https://a/cb, https://b/cb' },
    })
    fireEvent.click(screen.getByText('Register Client'))

    expect(await screen.findByTestId('dcr-manage-step')).toBeInTheDocument()
    expect(mockApi.post).toHaveBeenCalledWith(
      '/oauth2/register',
      expect.objectContaining({
        client_name: 'My App',
        redirect_uris: ['https://a/cb', 'https://b/cb'],
        token_endpoint_auth_method: 'client_secret_basic',
      }),
    )
    expect(mockStore.setClientId).toHaveBeenCalledWith('cid-1')
    expect(mockStore.setClientSecret).toHaveBeenCalledWith('sec-1')
    expect(screen.getByTestId('dcr-client-id')).toHaveTextContent('client_id: cid-1')
    expect(screen.getByText(/client_secret \(shown once\): sec-1/)).toBeInTheDocument()
  })

  it('surfaces a registration failure', async () => {
    const err = Object.assign(new Error('register boom'), { status: 400 })
    mockApi.post.mockRejectedValueOnce(err)
    render(<DcrFlow />)
    fireEvent.click(screen.getByText('Register Client'))
    await waitFor(() => expect(mockApi.post).toHaveBeenCalled())
  })

  it('updates the registration with PUT', async () => {
    await register()
    fireEvent.click(screen.getByText('Update name (PUT)'))
    await waitFor(() =>
      expect(mockApi.put).toHaveBeenCalledWith(
        '/oauth2/register/cid-1',
        { client_name: 'Playground Demo App (updated)' },
        { headers: { Authorization: `Basic ${btoa('cid-1:sec-1')}` } },
      ),
    )
  })

  it('surfaces an update failure', async () => {
    await register()
    mockApi.put.mockRejectedValueOnce(new Error('update boom'))
    fireEvent.click(screen.getByText('Update name (PUT)'))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalled())
  })

  it('deletes the registration and moves to the deleted step', async () => {
    await register()
    fireEvent.click(screen.getByTestId('dcr-delete-btn'))
    expect(await screen.findByTestId('dcr-deleted-step')).toBeInTheDocument()
    expect(mockApi.delete).toHaveBeenCalledWith('/oauth2/register/cid-1', {
      headers: { Authorization: `Basic ${btoa('cid-1:sec-1')}` },
    })
    fireEvent.click(screen.getByText('Register another client'))
    expect(screen.getByTestId('dcr-register-step')).toBeInTheDocument()
  })

  it('surfaces a delete failure', async () => {
    await register()
    mockApi.delete.mockRejectedValueOnce(new Error('delete boom'))
    fireEvent.click(screen.getByTestId('dcr-delete-btn'))
    await waitFor(() => expect(mockApi.delete).toHaveBeenCalled())
  })

  it('does not store an empty client secret', async () => {
    mockApi.post.mockResolvedValueOnce({ client_id: 'cid-2', client_secret: '' })
    render(<DcrFlow />)
    fireEvent.click(screen.getByText('Register Client'))
    await screen.findByTestId('dcr-manage-step')
    expect(mockStore.setClientId).toHaveBeenCalledWith('cid-2')
    expect(mockStore.setClientSecret).not.toHaveBeenCalled()
  })

  it('resets from the manage step', async () => {
    await register()
    fireEvent.click(screen.getByText('Start over'))
    expect(screen.getByTestId('dcr-register-step')).toBeInTheDocument()
  })
})
