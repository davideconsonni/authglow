// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { UserInfoFlow } from './UserInfoFlow'

const mockStore = vi.hoisted(() => ({
  accessToken: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwic2NvcGVzIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJlbWFpbCJdLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTUxNjIzOTAyMn0.signature',
  setAccessToken: vi.fn(),
}))

vi.mock('../../../stores/playgroundStore', () => ({
  usePlaygroundStore: () => mockStore,
}))

vi.mock('../../../lib/api', () => ({
  api: {
    get: vi.fn(),
  },
}))

describe('UserInfoFlow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockStore.accessToken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwic2NvcGVzIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJlbWFpbCJdLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTUxNjIzOTAyMn0.signature'
  })

  it('renders the token input step', () => {
    render(<UserInfoFlow />)
    expect(screen.getByText('Access Token *')).toBeInTheDocument()
    expect(screen.getByText('Fetch UserInfo')).toBeInTheDocument()
  })

  it('shows decoded claims when a valid JWT is in the store', () => {
    render(<UserInfoFlow />)
    expect(screen.getByText('Decoded Claims')).toBeInTheDocument()
    expect(screen.getByText('Header')).toBeInTheDocument()
    expect(screen.getByText('Payload')).toBeInTheDocument()
  })

  it('renders the FlowStepper with Token and UserInfo steps', () => {
    render(<UserInfoFlow />)
    expect(screen.getByText('Token')).toBeInTheDocument()
  })

  it('button is disabled when token is empty', () => {
    mockStore.accessToken = ''
    render(<UserInfoFlow />)
    expect(screen.getByText('Fetch UserInfo')).toBeDisabled()
  })
})
