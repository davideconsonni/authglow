import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { PhoneVerificationCard } from './PhoneVerificationCard'

const mockApi = vi.hoisted(() => ({
  post: vi.fn(),
}))

vi.mock('../../lib/api', () => ({
  api: mockApi,
}))

const defaultProps = {
  phone: null as string | null,
  phoneVerified: false,
  onVerified: vi.fn(),
}

describe('PhoneVerificationCard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockApi.post.mockResolvedValue({})
  })

  it('shows the phone input step when unverified', () => {
    render(<PhoneVerificationCard {...defaultProps} />)
    expect(screen.getByTestId('phone-verification-card')).toBeInTheDocument()
    expect(screen.getByTestId('phone-input')).toBeInTheDocument()
    expect(screen.getByTestId('send-code-button')).toBeInTheDocument()
  })

  it('shows the verified state when already verified', () => {
    render(<PhoneVerificationCard {...defaultProps} phone="+393391223345" phoneVerified />)
    expect(screen.getByTestId('phone-verified')).toBeInTheDocument()
  })

  it('sends the code and moves to the code step', async () => {
    render(<PhoneVerificationCard {...defaultProps} />)
    fireEvent.change(screen.getByTestId('phone-input'), { target: { value: '+393391223345' } })
    fireEvent.click(screen.getByTestId('send-code-button'))

    await waitFor(() => {
      expect(mockApi.post).toHaveBeenCalledWith('/api/phone/request', { phone: '+393391223345' })
    })
    expect(screen.getByTestId('code-input')).toBeInTheDocument()
  })

  it('rejects a non-E.164 phone number client-side', async () => {
    render(<PhoneVerificationCard {...defaultProps} />)
    fireEvent.change(screen.getByTestId('phone-input'), { target: { value: '3391223345' } })
    fireEvent.click(screen.getByTestId('send-code-button'))

    await waitFor(() => {
      expect(screen.getByText(/international format/i)).toBeInTheDocument()
    })
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('verifies the code and calls onVerified', async () => {
    const onVerified = vi.fn()
    render(<PhoneVerificationCard {...defaultProps} onVerified={onVerified} />)
    fireEvent.change(screen.getByTestId('phone-input'), { target: { value: '+393391223345' } })
    fireEvent.click(screen.getByTestId('send-code-button'))

    await waitFor(() => expect(screen.getByTestId('code-input')).toBeInTheDocument())
    fireEvent.change(screen.getByTestId('code-input'), { target: { value: '123456' } })
    fireEvent.click(screen.getByTestId('verify-code-button'))

    await waitFor(() => {
      expect(mockApi.post).toHaveBeenCalledWith('/api/phone/verify', {
        phone: '+393391223345',
        code: '123456',
      })
    })
    expect(onVerified).toHaveBeenCalled()
  })

  it('shows backend errors in an alert', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('A code was just sent. Wait before requesting a new one'))
    render(<PhoneVerificationCard {...defaultProps} />)
    fireEvent.change(screen.getByTestId('phone-input'), { target: { value: '+393391223345' } })
    fireEvent.click(screen.getByTestId('send-code-button'))

    await waitFor(() => {
      expect(screen.getByRole('alert')).toHaveTextContent(/just sent/i)
    })
  })
})
