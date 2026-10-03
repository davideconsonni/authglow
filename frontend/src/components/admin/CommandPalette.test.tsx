// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { CommandPalette } from './CommandPalette'
import { ROUTES } from '../../lib/constants'

const mockNavigate = vi.hoisted(() => vi.fn())
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

const mockApi = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const PLACEHOLDER = 'Search users or OAuth clients...'

function open() {
  fireEvent.keyDown(window, { key: 'k', ctrlKey: true })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.get.mockImplementation(async (url: string) => {
    if (url.includes('/api/admin/users/search')) {
      return { items: [{ id: 'u1', email: 'u@example.com', first_name: 'Al', last_name: 'P' }] }
    }
    return [{ client_id: 'c1', client_name: 'Alpha' }]
  })
})

describe('CommandPalette', () => {
  it('renders nothing when closed', () => {
    render(<CommandPalette />)
    expect(screen.queryByPlaceholderText(PLACEHOLDER)).not.toBeInTheDocument()
  })

  it('opens with Ctrl+K and closes with Escape', () => {
    render(<CommandPalette />)
    open()
    expect(screen.getByPlaceholderText(PLACEHOLDER)).toBeInTheDocument()
    expect(screen.getByText('Type to search users and OAuth clients')).toBeInTheDocument()
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByPlaceholderText(PLACEHOLDER)).not.toBeInTheDocument()
  })

  it('does not search for fewer than two characters', async () => {
    render(<CommandPalette />)
    open()
    fireEvent.change(screen.getByPlaceholderText(PLACEHOLDER), { target: { value: 'a' } })
    await new Promise((r) => setTimeout(r, 250))
    expect(mockApi.get).not.toHaveBeenCalled()
  })

  it('searches and navigates to the matched user', async () => {
    render(<CommandPalette />)
    open()
    fireEvent.change(screen.getByPlaceholderText(PLACEHOLDER), { target: { value: 'al' } })
    const email = await screen.findByText('u@example.com')
    expect(mockApi.get).toHaveBeenCalledWith(expect.stringContaining('/api/admin/users/search'))
    expect(screen.getByText('Alpha')).toBeInTheDocument()

    fireEvent.click(email)
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.USERS)
  })

  it('navigates to the matched OAuth client', async () => {
    render(<CommandPalette />)
    open()
    fireEvent.change(screen.getByPlaceholderText(PLACEHOLDER), { target: { value: 'al' } })
    fireEvent.click(await screen.findByText('Alpha'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.OAUTH_CLIENTS)
  })

  it('shows the no-results state', async () => {
    mockApi.get.mockResolvedValue({ items: [] })
    render(<CommandPalette />)
    open()
    fireEvent.change(screen.getByPlaceholderText(PLACEHOLDER), { target: { value: 'zz' } })
    expect(await screen.findByText('No results for "zz"')).toBeInTheDocument()
  })

  it('clears results when the search request fails', async () => {
    mockApi.get.mockRejectedValue(new Error('down'))
    render(<CommandPalette />)
    open()
    fireEvent.change(screen.getByPlaceholderText(PLACEHOLDER), { target: { value: 'zz' } })
    expect(await screen.findByText('No results for "zz"')).toBeInTheDocument()
  })

  it('closes via the backdrop', () => {
    render(<CommandPalette />)
    open()
    fireEvent.click(screen.getByPlaceholderText(PLACEHOLDER).closest('.fixed')!.querySelector('.absolute') as HTMLElement)
    expect(screen.queryByPlaceholderText(PLACEHOLDER)).not.toBeInTheDocument()
  })
})