// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { DeviceAuthNewTool } from './DeviceAuthNewTool'

const mockApi = vi.hoisted(() => ({ postForm: vi.fn() }))
const mockQuery = vi.hoisted(() => ({
  data: undefined as unknown,
  isLoading: false,
}))

vi.mock('../../lib/api', () => ({ api: mockApi }))
vi.mock('../../hooks/useApi', () => ({
  useApiQuery: () => ({ data: mockQuery.data, isLoading: mockQuery.isLoading }),
}))
vi.mock('../../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))
vi.mock('../../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    Link: ({ to, children, ...rest }: { to: string; children: React.ReactNode }) => (
      <a href={to} {...rest}>
        {children}
      </a>
    ),
  }
})

const RESULT = {
  device_code: 'DEV-CODE',
  user_code: 'USER-CODE',
  verification_uri: 'https://verify',
  verification_uri_complete: 'https://verify?code=USER-CODE',
  expires_in: 600,
  interval: 5,
}

beforeEach(() => {
  vi.clearAllMocks()
  mockQuery.data = [{ client_id: 'c1', client_name: 'App One' }]
  mockQuery.isLoading = false
  mockApi.postForm.mockResolvedValue(RESULT)
})

describe('DeviceAuthNewTool', () => {
  it('shows the clients loading spinner', () => {
    mockQuery.isLoading = true
    render(<DeviceAuthNewTool />)
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
  })

  it('shows the empty-clients state', () => {
    mockQuery.data = []
    render(<DeviceAuthNewTool />)
    expect(screen.getByText('No OAuth clients configured.')).toBeInTheDocument()
  })

  it('generates a device authorization and shows the codes', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<DeviceAuthNewTool />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'c1' } })
    fireEvent.change(screen.getByPlaceholderText('read write profile'), {
      target: { value: 'read write' },
    })
    fireEvent.click(screen.getByText('Generate'))

    await waitFor(() =>
      expect(mockApi.postForm).toHaveBeenCalledWith('/oauth2/device/authorize', {
        client_id: 'c1',
        scope: 'read write',
      }),
    )
    expect(notify.success).toHaveBeenCalledWith('Device authorization generated')
    expect(await screen.findByText('USER-CODE')).toBeInTheDocument()
    expect(screen.getByText('DEV-CODE')).toBeInTheDocument()
    expect(screen.getByText('https://verify?code=USER-CODE')).toBeInTheDocument()
    expect(screen.getByText('Expires: 600s')).toBeInTheDocument()
    expect(screen.getByText('Poll interval: 5s')).toBeInTheDocument()
  })

  it('surfaces a generation failure', async () => {
    mockApi.postForm.mockRejectedValueOnce(new Error('generate failed'))
    render(<DeviceAuthNewTool />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'c1' } })
    fireEvent.click(screen.getByText('Generate'))
    expect(await screen.findByRole('alert')).toHaveTextContent('generate failed')
  })

  it('falls back to a default scope when the scope is cleared', async () => {
    render(<DeviceAuthNewTool />)
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'c1' } })
    fireEvent.change(screen.getByPlaceholderText('read write profile'), { target: { value: '' } })
    fireEvent.click(screen.getByText('Generate'))
    await waitFor(() =>
      expect(mockApi.postForm).toHaveBeenCalledWith('/oauth2/device/authorize', {
        client_id: 'c1',
        scope: 'read',
      }),
    )
  })
})