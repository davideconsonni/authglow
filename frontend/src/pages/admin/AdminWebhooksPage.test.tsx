// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AdminWebhooksPage } from './AdminWebhooksPage'

const mockState = vi.hoisted(() => ({
  webhooks: [] as Array<Record<string, unknown>>,
  deliveries: {} as Record<string, Array<Record<string, unknown>>>,
}))

vi.mock('../../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn().mockResolvedValue({}),
    patch: vi.fn().mockResolvedValue({}),
    delete: vi.fn().mockResolvedValue({}),
  },
}))

vi.mock('../../hooks/useApi', () => ({
  useApiQuery: (_key: string[], endpoint: string) => {
    if (endpoint === '/api/admin/webhooks') {
      return { data: mockState.webhooks, refetch: vi.fn(), isLoading: false }
    }
    const m = endpoint.match(/\/api\/admin\/webhooks\/([^/]+)\/deliveries/)
    if (m) {
      return {
        data: mockState.deliveries[m[1]] ?? [],
        refetch: vi.fn(),
        isLoading: false,
      }
    }
    return { data: undefined, refetch: vi.fn(), isLoading: false }
  },
}))

vi.mock('../../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn() },
}))

import { api } from '../../lib/api'

const WH = {
  id: 'wh_abc12345678',
  url: 'https://hooks.example.com/x',
  events: ['user.created', 'login.failed'],
  active: true,
  masked_secret: 'whsec_ab12…',
  created_at: '2026-08-25T10:00:00Z',
  updated_at: '2026-08-25T10:00:00Z',
}

function Wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

describe('AdminWebhooksPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockState.webhooks = [WH]
    mockState.deliveries = {}
  })

  it('renders the registered webhook with masked secret and event chips', () => {
    render(<Wrapper><AdminWebhooksPage /></Wrapper>)
    expect(screen.getByText('https://hooks.example.com/x')).toBeInTheDocument()
    expect(screen.getByText(/whsec_ab12/)).toBeInTheDocument()
    expect(screen.getByText('user.created')).toBeInTheDocument()
  })

  it('create form posts url+events and reveals the secret once', async () => {
    const postMock = api.post as ReturnType<typeof vi.fn>
    postMock.mockResolvedValueOnce({ ...WH, id: 'wh_new9999999', secret: 'whsec_NEWSECRET123' })

    render(<Wrapper><AdminWebhooksPage /></Wrapper>)
    fireEvent.click(screen.getByTestId('webhooks-create-btn'))
    fireEvent.change(screen.getByLabelText(/Endpoint URL/), {
      target: { value: 'https://nuovo.example/hook' },
    })
    fireEvent.click(screen.getByLabelText('user.created'))
    fireEvent.click(screen.getByTestId('webhooks-create-confirm'))

    await waitFor(() => {
      expect(postMock).toHaveBeenCalledWith('/api/admin/webhooks', {
        url: 'https://nuovo.example/hook',
        events: ['user.created'],
      })
    })
    expect(await screen.findByTestId('secret-reveal-modal')).toBeInTheDocument()
    expect(screen.getByTestId('secret-reveal-value').textContent).toBe('whsec_NEWSECRET123')
  })

  it('sends a test event and opens the deliveries panel', async () => {
    const postMock = api.post as ReturnType<typeof vi.fn>
    postMock.mockResolvedValueOnce({
      delivered: true,
      attempts: [{ status_code: 200, error: null }],
    })
    mockState.deliveries = {
      [WH.id]: [
        {
          id: 'dlv_1',
          webhook_id: WH.id,
          event_type: 'webhook.test',
          attempt: 1,
          ok: true,
          status_code: 200,
          error: null,
          duration_ms: 120,
          delivered_at: '2026-08-25T10:05:00Z',
        },
      ],
    }

    render(<Wrapper><AdminWebhooksPage /></Wrapper>)
    fireEvent.click(screen.getByTestId(`webhook-test-${WH.id}`))

    await waitFor(() => {
      expect(postMock).toHaveBeenCalledWith(`/api/admin/webhooks/${WH.id}/test`)
    })
    const panel = await screen.findByTestId('deliveries-panel')
    expect(panel.textContent).toContain('webhook.test')
  })

  it('shows the empty deliveries placeholder when no log exists', async () => {
    mockState.deliveries = { [WH.id]: [] }
    render(<Wrapper><AdminWebhooksPage /></Wrapper>)
    fireEvent.click(screen.getByTitle('Delivery log'))
    expect(await screen.findByTestId('deliveries-panel-empty')).toBeInTheDocument()
  })

  it('edit opens a pre-filled form and saves via PATCH', async () => {
    const patchMock = api.patch as ReturnType<typeof vi.fn>
    patchMock.mockResolvedValueOnce({ ...WH, url: 'https://modificata.example/hook' })

    render(<Wrapper><AdminWebhooksPage /></Wrapper>)

    // Il form parte chiuso: apri in modalità modifica.
    expect(screen.queryByLabelText(/Endpoint URL/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId(`webhook-edit-${WH.id}`))

    const urlInput = screen.getByLabelText(/Endpoint URL/) as HTMLInputElement
    expect(urlInput.value).toBe('https://hooks.example.com/x')
    fireEvent.change(urlInput, { target: { value: 'https://modificata.example/hook' } })
    // aggiunge un secondo evento
    fireEvent.click(screen.getByLabelText('login.success'))

    fireEvent.click(screen.getByTestId('webhooks-create-confirm'))

    await waitFor(() => {
      expect(patchMock).toHaveBeenCalledWith(`/api/admin/webhooks/${WH.id}`, {
        url: 'https://modificata.example/hook',
        events: ['user.created', 'login.failed', 'login.success'],
      })
    })
  })

  it('delete calls DELETE on the endpoint', async () => {
    const deleteMock = api.delete as ReturnType<typeof vi.fn>
    deleteMock.mockResolvedValue({})
    render(<Wrapper><AdminWebhooksPage /></Wrapper>)
    fireEvent.click(screen.getByTitle('Delete webhook'))
    // ConfirmDialog: conferma con il bottone di testo "Delete"
    fireEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    await waitFor(() => {
      expect(deleteMock).toHaveBeenCalledWith(`/api/admin/webhooks/${WH.id}`)
    })
  })
})
