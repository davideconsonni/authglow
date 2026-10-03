// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ResendVerificationBanner } from './ResendVerificationBanner'

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.post.mockResolvedValue({})
})

describe('ResendVerificationBanner', () => {
  it('renders the prompt and confirms a successful resend', async () => {
    render(<ResendVerificationBanner />)
    expect(screen.getByText('Verify your email to enable all features.')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Resend'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/email/resend-verification'),
    )
    expect(await screen.findByText('Verification email sent. Check your inbox.')).toBeInTheDocument()
  })

  it('shows the error message on failure', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('rate limited'))
    render(<ResendVerificationBanner />)
    fireEvent.click(screen.getByText('Resend'))
    expect(await screen.findByText('rate limited')).toBeInTheDocument()
  })

  it('falls back to a generic error for non-Error rejections', async () => {
    mockApi.post.mockRejectedValueOnce('boom')
    render(<ResendVerificationBanner />)
    fireEvent.click(screen.getByText('Resend'))
    expect(await screen.findByText('Failed to resend verification email')).toBeInTheDocument()
  })
})
