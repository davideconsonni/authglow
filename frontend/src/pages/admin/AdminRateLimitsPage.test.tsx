// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AdminRateLimitsPage } from '../../pages/admin/AdminRateLimitsPage'

vi.mock('../../lib/api', () => ({
  api: {
    get: vi.fn(),
    put: vi.fn(),
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
const apiPutMock = api.put as ReturnType<typeof vi.fn>

const mockStatus = {
  total_routes_limited: 2,
  default_limits_count: 0,
  exempt_routes_count: 3,
  storage_type: 'MemoryStorage',
  enabled: true,
}

const mockLimits = {
  total_routes: 2,
  rate_limits: [
    {
      route: '/api/auth/login',
      method: 'POST',
      limit: '10 per 1 minute',
      source: 'decorator',
      path: '/api/auth/login',
      override: null,
    },
    {
      route: '/api/meta',
      method: 'GET',
      limit: '5 per 1 hour',
      source: 'override',
      path: '/api/meta',
      override: '5 per 1 hour',
    },
  ],
}

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/admin/rate-limits']}>
        <AdminRateLimitsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AdminRateLimitsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    apiGetMock.mockImplementation((url: string) => {
      if (url === '/api/admin/rate-limits') return Promise.resolve(mockLimits)
      return Promise.resolve(mockStatus)
    })
    apiPutMock.mockResolvedValue({ enabled: true, overrides: {} })
  })

  it('fetches from the correct endpoints', async () => {
    renderPage()
    await waitFor(() => {
      expect(apiGetMock).toHaveBeenCalledWith('/api/admin/rate-limits')
      expect(apiGetMock).toHaveBeenCalledWith('/api/admin/rate-limits/status')
    })
  })

  it('renders status cards and table rows', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('Active')).toBeInTheDocument()
      expect(screen.getByText('/api/auth/login')).toBeInTheDocument()
      expect(screen.getByText('/api/meta')).toBeInTheDocument()
    })
  })

  it('toggles rate limiting globally via PUT', async () => {
    renderPage()
    const toggle = await screen.findByRole('switch', {
      name: 'Toggle rate limiting globally',
    })
    expect(toggle).toBeChecked()

    fireEvent.click(toggle)

    await waitFor(() => {
      expect(apiPutMock).toHaveBeenCalledWith('/api/admin/rate-limits/config', {
        enabled: false,
      })
    })
  })

  it('saves an inline limit edit via PUT', async () => {
    renderPage()
    const amount = await screen.findByLabelText('Limit amount for /api/auth/login')
    expect(amount).toHaveValue(10)

    fireEvent.change(amount, { target: { value: '3' } })
    fireEvent.click(screen.getByLabelText('Save limit for /api/auth/login'))

    await waitFor(() => {
      expect(apiPutMock).toHaveBeenCalledWith('/api/admin/rate-limits/config', {
        overrides: { '/api/auth/login': '3/minute' },
      })
    })
  })

  it('saves a period change via PUT', async () => {
    renderPage()
    const period = await screen.findByLabelText('Limit period for /api/auth/login')
    expect(period).toHaveValue('minute')

    fireEvent.change(period, { target: { value: 'hour' } })
    fireEvent.click(screen.getByLabelText('Save limit for /api/auth/login'))

    await waitFor(() => {
      expect(apiPutMock).toHaveBeenCalledWith('/api/admin/rate-limits/config', {
        overrides: { '/api/auth/login': '10/hour' },
      })
    })
  })

  it('does not mark the row dirty when the value is unchanged', async () => {
    renderPage()
    const period = await screen.findByLabelText('Limit period for /api/auth/login')

    // "10 per 1 minute" ≡ "10/minute": picking hour then back to minute
    // must clear the dirty mark and never trigger a PUT.
    fireEvent.change(period, { target: { value: 'hour' } })
    fireEvent.change(period, { target: { value: 'minute' } })

    const save = screen.getByLabelText('Save limit for /api/auth/login')
    expect(save).toBeDisabled()
    expect(apiPutMock).not.toHaveBeenCalled()
  })

  it('falls back to a text editor for non-representable limits', async () => {
    apiGetMock.mockImplementation((url: string) => {
      if (url === '/api/admin/rate-limits')
        return Promise.resolve({
          total_routes: 1,
          rate_limits: [
            {
              route: '/api/special',
              method: 'POST',
              limit: '5 per 2 hours',
              source: 'decorator',
              path: '/api/special',
              override: null,
            },
          ],
        })
      return Promise.resolve(mockStatus)
    })
    renderPage()
    const input = await screen.findByLabelText('Limit for /api/special')

    fireEvent.change(input, { target: { value: 'banana' } })

    const save = screen.getByLabelText('Save limit for /api/special')
    expect(save).toBeDisabled()
    expect(screen.getByRole('alert')).toHaveTextContent('Format: 10/minute')
    expect(apiPutMock).not.toHaveBeenCalled()
  })

  it('resets an overridden route to its default', async () => {
    renderPage()
    const reset = await screen.findByLabelText('Reset limit for /api/meta')

    fireEvent.click(reset)

    await waitFor(() => {
      expect(apiPutMock).toHaveBeenCalledWith('/api/admin/rate-limits/config', {
        overrides: { '/api/meta': null },
      })
    })
  })

  it('does not render a reset button for non-overridden routes', async () => {
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('/api/auth/login')).toBeInTheDocument()
    })
    expect(screen.queryByLabelText('Reset limit for /api/auth/login')).toBeNull()
  })

  it('disables save while the edited limit has an invalid format', async () => {
    renderPage()
    const amount = await screen.findByLabelText('Limit amount for /api/auth/login')

    // Zero/negative amounts are rejected by the editor itself.
    fireEvent.change(amount, { target: { value: '0' } })
    fireEvent.change(screen.getByLabelText('Limit period for /api/auth/login'), {
      target: { value: 'hour' },
    })

    const save = screen.getByLabelText('Save limit for /api/auth/login')
    expect(save).toBeDisabled()
    expect(apiPutMock).not.toHaveBeenCalled()
  })

  it('resets all overrides to defaults after confirmation', async () => {
    renderPage()
    const resetAll = await screen.findByTestId('rate-limits-reset-all')

    fireEvent.click(resetAll)
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))

    await waitFor(() => {
      expect(apiPutMock).toHaveBeenCalledWith('/api/admin/rate-limits/config', {
        overrides: { '/api/meta': null },
      })
    })
  })

  it('hides the global reset button when no overrides exist', async () => {
    apiGetMock.mockImplementation((url: string) => {
      if (url === '/api/admin/rate-limits')
        return Promise.resolve({
          total_routes: 1,
          rate_limits: [mockLimits.rate_limits[0]],
        })
      return Promise.resolve(mockStatus)
    })
    renderPage()
    await waitFor(() => {
      expect(screen.getByText('/api/auth/login')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('rate-limits-reset-all')).toBeNull()
  })
})
