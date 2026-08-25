// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { RpInitiatedLogoutFlow } from './RpInitiatedLogoutFlow'
import { usePlaygroundStore } from '../../../stores/playgroundStore'

describe('RpInitiatedLogoutFlow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    usePlaygroundStore.setState({ idToken: 'fake.idtoken.sig' })
    // jsdom: stub window.location.assign for the navigation assertion.
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign: vi.fn() },
      writable: true,
    })
  })

  it('pre-fills id_token_hint from the playground store', () => {
    render(<RpInitiatedLogoutFlow />)
    const textarea = screen.getByTestId('rp-id-token-hint') as HTMLTextAreaElement
    expect(textarea.value).toBe('fake.idtoken.sig')
  })

  it('builds the logout URL with hint, redirect uri and state', () => {
    render(<RpInitiatedLogoutFlow />)
    const uri = 'http://localhost:3000/admin/playground'
    fireEvent.change(screen.getByTestId('rp-post-logout-uri'), { target: { value: uri } })
    fireEvent.click(screen.getByTestId('rp-logout-next-btn'))

    const url = screen.getByTestId('rp-logout-url').textContent ?? ''
    expect(url).toContain('/oauth2/logout?')
    expect(url).toContain('id_token_hint=fake.idtoken.sig')
    expect(url).toContain(`post_logout_redirect_uri=${encodeURIComponent(uri)}`)
    expect(url).toMatch(/state=/)
  })

  it('navigates to the logout URL on execute', () => {
    render(<RpInitiatedLogoutFlow />)
    fireEvent.click(screen.getByTestId('rp-logout-next-btn'))
    fireEvent.click(screen.getByTestId('rp-logout-execute-btn'))

    const assign = window.location.assign as ReturnType<typeof vi.fn>
    expect(assign).toHaveBeenCalledTimes(1)
    const navigatedTo = String(assign.mock.calls[0][0])
    expect(navigatedTo).toContain('/oauth2/logout?')
  })
})
