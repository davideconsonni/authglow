// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ClaimTemplatePicker, type ClaimTemplate } from './ClaimTemplatePicker'

const mockTemplates = vi.hoisted(() => ({
  data: [] as ClaimTemplate[] | undefined,
  isLoading: false,
}))

vi.mock('../../hooks/useApi', () => ({
  useApiQuery: () => ({
    data: mockTemplates.data,
    refetch: vi.fn(),
    isLoading: mockTemplates.isLoading,
  }),
}))

function Wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const RBAC_TEMPLATE: ClaimTemplate = {
  id: 'rbac-roles',
  label: 'RBAC Roles',
  description: 'Namespaced RBAC roles',
  claim_name: 'https://authglow.example.com/claims/roles',
  source: 'rbac_roles',
  include_in: ['access_token', 'id_token'],
  required_scope: null,
  source_config: {},
}

describe('ClaimTemplatePicker', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockTemplates.isLoading = false
    mockTemplates.data = [RBAC_TEMPLATE]
  })

  it('starts collapsed and toggles the gallery on click', () => {
    render(
      <Wrapper>
        <ClaimTemplatePicker onSelect={vi.fn()} />
      </Wrapper>,
    )
    expect(screen.queryByTestId('claim-template-list')).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId('claim-template-btn'))
    expect(screen.getByTestId('claim-template-list')).toBeInTheDocument()
    // aria-expanded reflects the open state for accessibility.
    expect(screen.getByTestId('claim-template-btn')).toHaveAttribute('aria-expanded', 'true')
  })

  it('renders one card per template with label and namespaced claim name', () => {
    render(
      <Wrapper>
        <ClaimTemplatePicker onSelect={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-template-btn'))
    const card = screen.getByTestId('claim-template-rbac-roles')
    expect(card.textContent).toContain('RBAC Roles')
    expect(card.textContent).toContain('https://authglow.example.com/claims/roles')
  })

  it('hands the raw template to onSelect and collapses', () => {
    const onSelect = vi.fn()
    render(
      <Wrapper>
        <ClaimTemplatePicker onSelect={onSelect} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-template-btn'))
    fireEvent.click(screen.getByTestId('claim-template-rbac-roles'))
    expect(onSelect).toHaveBeenCalledWith(RBAC_TEMPLATE)
    expect(screen.queryByTestId('claim-template-list')).not.toBeInTheDocument()
  })

  it('hides templates whose source is excluded', () => {
    mockTemplates.data = [
      RBAC_TEMPLATE,
      {
        ...RBAC_TEMPLATE,
        id: 'api-key-tier',
        source: 'api_key_field',
        claim_name: 'https://authglow.example.com/claims/api_key_tier',
      },
    ]
    render(
      <Wrapper>
        <ClaimTemplatePicker onSelect={vi.fn()} excludeSources={['api_key_field']} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-template-btn'))
    expect(screen.getByTestId('claim-template-rbac-roles')).toBeInTheDocument()
    expect(screen.queryByTestId('claim-template-api-key-tier')).not.toBeInTheDocument()
  })

  it('shows an empty-state message when no templates exist', () => {
    mockTemplates.data = []
    render(
      <Wrapper>
        <ClaimTemplatePicker onSelect={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-template-btn'))
    expect(screen.getByText('No templates available.')).toBeInTheDocument()
  })
})
