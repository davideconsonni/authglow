// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { DemoInbox } from '../../components/shared/DemoInbox'

vi.mock('../../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
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

import { api } from '../../lib/api'

const apiGetMock = api.get as ReturnType<typeof vi.fn>

function renderInbox(email: string | null = 'user@example.com') {
  return render(<DemoInbox email={email} />)
}

describe('DemoInbox', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows empty state with no emails', async () => {
    apiGetMock.mockImplementation((url: string) => {
      if (url.includes('/api/meta')) return Promise.resolve({ demo_mode: true })
      return Promise.resolve({ emails: [] })
    })
    renderInbox()
    await waitFor(() => {
      expect(apiGetMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/demo/inbox?email=user%40example.com'),
        expect.anything(),
      )
    })
    expect(screen.getByTestId('demo-inbox')).toBeInTheDocument()
    expect(screen.getByText(/No emails yet/)).toBeInTheDocument()
  })

  it('renders captured emails with subject and body', async () => {
    apiGetMock.mockImplementation((url: string) => {
      if (url.includes('/api/meta')) return Promise.resolve({ demo_mode: true })
      return Promise.resolve({
        emails: [
          {
            timestamp: '2026-08-19T10:00:00Z',
            to: ['user@example.com'],
            cc: [],
            subject: 'Verify your email',
            body_text: 'Your verification code is ABCD-EFGH-1234.',
            body_html: null,
            provider: 'console',
          },
        ],
      })
    })
    renderInbox()
    await waitFor(() => {
      expect(screen.getByTestId('demo-inbox-email')).toBeInTheDocument()
    })
    expect(screen.getByText('Verify your email')).toBeInTheDocument()
    expect(screen.getByText(/ABCD-EFGH-1234/)).toBeInTheDocument()
  })

  it('stays empty when demo mode is off', async () => {
    apiGetMock.mockImplementation((url: string) => {
      if (url.includes('/api/meta')) return Promise.resolve({ demo_mode: false })
      return Promise.resolve({ emails: [] })
    })
    renderInbox()
    await waitFor(() => {
      expect(apiGetMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/meta'),
        expect.anything(),
      )
    })
    expect(
      apiGetMock.mock.calls.some((call) => String(call[0]).includes('/api/demo/inbox')),
    ).toBe(false)
  })
})
