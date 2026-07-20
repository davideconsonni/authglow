// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AdminSettingsPage } from '../../pages/admin/AdminSettingsPage'

vi.mock('../../lib/api', () => ({
  api: {
    get: vi.fn(),
    patch: vi.fn(),
  },
  ApiError: class extends Error {
    status: number
    data: unknown
    constructor(status: number, data: unknown) {
      super(String(data))
      this.status = status
      this.data = data
    }
  },
}))

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({ user: { scopes: ['admin'], email: 'admin@test.com' }, isAuthenticated: true }),
}))

import { api } from '../../lib/api'

const apiGetMock = api.get as ReturnType<typeof vi.fn>

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/admin/settings']}>
        <AdminSettingsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AdminSettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  const mockSettings = {
    categories: ['general', 'security', 'sessions'],
    settings: [
      {
        key: 'app_name',
        value: 'AuthGlow',
        type: 'string',
        default: 'AuthGlow',
        label: 'Application name',
        category: 'general',
        restart_required: false,
        editable: true,
      },
      {
        key: 'debug',
        value: false,
        type: 'boolean',
        default: false,
        label: 'Debug mode',
        category: 'general',
        restart_required: true,
        editable: false,
      },
      {
        key: 'access_token_expire_minutes',
        value: 30,
        type: 'number',
        default: 30,
        label: 'Access token expiry (min)',
        category: 'sessions',
        restart_required: false,
        editable: true,
      },
    ],
  }

  it('renders category navigation', async () => {
    apiGetMock.mockResolvedValueOnce(mockSettings)
    renderPage()
    await waitFor(() => {
      const buttons = screen.getAllByText('General')
      expect(buttons.length).toBe(2) // nav button + heading
      expect(screen.getByText('Security')).toBeInTheDocument()
      expect(screen.getByText('Sessions')).toBeInTheDocument()
    })
  })

  it('shows settings for the active category', async () => {
    apiGetMock.mockResolvedValueOnce(mockSettings)
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Application name')).toBeInTheDocument()
      expect(screen.getByText('Debug mode')).toBeInTheDocument()
    })
  })

  it('shows restart_required badge', async () => {
    apiGetMock.mockResolvedValueOnce(mockSettings)
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Restart required')).toBeInTheDocument()
    })
  })

  it('fetches from the correct endpoint', async () => {
    apiGetMock.mockResolvedValueOnce(mockSettings)
    renderPage()
    await waitFor(() => {
      expect(apiGetMock).toHaveBeenCalledWith('/api/admin/settings')
    })
  })

  it('renders loading state initially', () => {
    apiGetMock.mockReturnValueOnce(new Promise(() => {}))
    renderPage()
    const spinners = document.querySelectorAll('.animate-spin')
    expect(spinners.length).toBeGreaterThan(0)
  })
})
