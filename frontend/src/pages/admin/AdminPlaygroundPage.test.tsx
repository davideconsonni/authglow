// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'
import { AdminPlaygroundPage } from './AdminPlaygroundPage'
import { FLOWS } from '../../components/playground/flows'
import { usePlaygroundStore } from '../../stores/playgroundStore'

vi.mock('../../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))

vi.mock('../../components/playground/FlowSidebar', () => ({
  FlowSidebar: ({ onSelect }: { onSelect: (flow: string) => void }) => (
    <button data-testid="flow-sidebar-stub" onClick={() => onSelect('pkce')}>
      sidebar
    </button>
  ),
}))

vi.mock('../../components/playground/flows/AuthorizationCodeFlow', () => ({
  AuthorizationCodeFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/ClientCredentialsFlow', () => ({
  ClientCredentialsFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/PkceFlow', () => ({
  PkceFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/RefreshTokenFlow', () => ({
  RefreshTokenFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/IntrospectionFlow', () => ({
  IntrospectionFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/RevocationFlow', () => ({
  RevocationFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/ApiKeyExchangeFlow', () => ({
  ApiKeyExchangeFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/OidcDiscoveryFlow', () => ({
  OidcDiscoveryFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/UserInfoFlow', () => ({
  UserInfoFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/DeviceCodeFlow', () => ({
  DeviceCodeFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/TokenPreviewFlow', () => ({
  TokenPreviewFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/GenericRequestFlow', () => ({
  GenericRequestFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/DcrFlow', () => ({
  DcrFlow: () => <div data-testid="flow-stub" />,
}))
vi.mock('../../components/playground/flows/RpInitiatedLogoutFlow', () => ({
  RpInitiatedLogoutFlow: () => <div data-testid="flow-stub" />,
}))

beforeEach(() => {
  vi.clearAllMocks()
  act(() => usePlaygroundStore.setState({ currentFlow: 'authorization-code' }))
})

describe('AdminPlaygroundPage', () => {
  it('renders the default flow with title and description', () => {
    render(<AdminPlaygroundPage />)
    expect(screen.getByText('API Playground')).toBeInTheDocument()
    expect(screen.getByText('Authorization Code Flow')).toBeInTheDocument()
    expect(
      screen.getByText('Browser-based OAuth2 flow with redirect and authorization code exchange.'),
    ).toBeInTheDocument()
    expect(screen.getByTestId('flow-stub')).toBeInTheDocument()
  })

  it('switches flow from the mobile select', () => {
    render(<AdminPlaygroundPage />)
    fireEvent.change(screen.getByTestId('playground-flow-select'), { target: { value: 'pkce' } })
    expect(screen.getByText('PKCE Flow')).toBeInTheDocument()
  })

  it('switches flow from the sidebar callback', () => {
    render(<AdminPlaygroundPage />)
    fireEvent.click(screen.getByTestId('flow-sidebar-stub'))
    expect(screen.getByText('PKCE Flow')).toBeInTheDocument()
  })

  it('renders every flow without crashing', () => {
    render(<AdminPlaygroundPage />)
    for (const flow of FLOWS) {
      act(() => usePlaygroundStore.setState({ currentFlow: flow.id }))
      expect(screen.getByRole('heading', { level: 2 })).toBeInTheDocument()
      expect(screen.getAllByTestId('flow-stub').length).toBeGreaterThan(0)
    }
  })
})
