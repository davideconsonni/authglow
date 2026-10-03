// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { UserInfoFlow } from './UserInfoFlow'

const TOKEN =
  'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwic2NvcGVzIjpbIm9wZW5pZCJdLCJleHAiOjk5OTk5OTk5OTl9.signature'

const mockStore = vi.hoisted(() => ({ accessToken: '', setAccessToken: vi.fn() }))
vi.mock('../../../stores/playgroundStore', () => ({ usePlaygroundStore: () => mockStore }))

const mockApi = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('../../../lib/api', () => ({ api: mockApi }))

const mockAuth = vi.hoisted(() => ({ user: { email: 'me@example.com' } as unknown }))
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => ({ user: mockAuth.user }) }))

beforeEach(() => {
  vi.clearAllMocks()
  mockStore.accessToken = TOKEN
  mockAuth.user = { email: 'me@example.com' }
  mockApi.get.mockResolvedValue({ sub: 'user123' })
})

describe('UserInfoFlow — interactions', () => {
  it('collapses and expands the decoded claims', () => {
    render(<UserInfoFlow />)
    expect(screen.getByText('Header')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Decoded Claims'))
    expect(screen.queryByText('Header')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('Decoded Claims'))
    expect(screen.getByText('Header')).toBeInTheDocument()
  })

  it('fetches UserInfo and advances to the result step', async () => {
    render(<UserInfoFlow />)
    fireEvent.click(screen.getByText('Fetch UserInfo'))
    await waitFor(() =>
      expect(mockApi.get).toHaveBeenCalledWith('/oauth2/userinfo', {
        headers: { Authorization: `Bearer ${TOKEN}` },
      }),
    )
    expect(mockStore.setAccessToken).toHaveBeenCalledWith(TOKEN)
    expect(await screen.findByText('Fetch Another')).toBeInTheDocument()
  })

  it('records the HTTP status on a failed fetch', async () => {
    const err = Object.assign(new Error('unauthorized'), { status: 401 })
    mockApi.get.mockRejectedValueOnce(err)
    render(<UserInfoFlow />)
    fireEvent.click(screen.getByText('Fetch UserInfo'))
    await waitFor(() => expect(mockApi.get).toHaveBeenCalled())
    expect(screen.getByText('Access Token *')).toBeInTheDocument()
  })

  it('falls back to a generic message for non-Error rejections', async () => {
    mockApi.get.mockRejectedValueOnce('boom')
    render(<UserInfoFlow />)
    fireEvent.click(screen.getByText('Fetch UserInfo'))
    await waitFor(() => expect(mockApi.get).toHaveBeenCalled())
  })

  it('fetches my user info from the stored token', () => {
    render(<UserInfoFlow />)
    fireEvent.click(screen.getByText('Fetch My UserInfo'))
    expect(screen.getByText('Fetch Another')).toBeInTheDocument()
  })

  it('reports when no session token is captured', () => {
    mockStore.accessToken = ''
    render(<UserInfoFlow />)
    fireEvent.click(screen.getByText('Fetch My UserInfo'))
    expect(screen.getByText('Fetch Another')).toBeInTheDocument()
  })

  it('uses the session token and resets the flow', () => {
    render(<UserInfoFlow />)
    fireEvent.click(screen.getByText('Use my session token'))
    fireEvent.click(screen.getByText('Fetch My UserInfo'))
    fireEvent.click(screen.getByText('Fetch Another'))
    expect(screen.getByText('Access Token *')).toBeInTheDocument()
  })

  it('disables fetch when the token is cleared', () => {
    render(<UserInfoFlow />)
    fireEvent.change(screen.getByPlaceholderText('eyJhbGciOiJSUzI1NiIs...'), {
      target: { value: '' },
    })
    expect(screen.getByText('Fetch UserInfo')).toBeDisabled()
  })

  it('hides the my-userinfo button when no user is logged in', () => {
    mockAuth.user = null
    render(<UserInfoFlow />)
    expect(screen.getByText('Fetch My UserInfo')).toBeDisabled()
  })
})
