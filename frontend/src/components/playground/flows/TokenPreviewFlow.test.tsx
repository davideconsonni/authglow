// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TokenPreviewFlow } from './TokenPreviewFlow'

function Wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const mockApi = vi.hoisted(() => ({
  get: vi.fn(),
}))

const mockQueryData = vi.hoisted(() => ({
  clients: null as unknown,
  keys: null as unknown,
  policy: null as unknown,
}))

vi.mock('../../../lib/api', () => ({
  api: mockApi,
}))

vi.mock('../../../hooks/useApi', () => ({
  useApiQuery: (key: string[]) => {
    if (key[0] === 'admin-oauth-clients') {
      return { data: mockQueryData.clients, isLoading: false }
    }
    if (key[0] === 'admin-keys-preview') {
      return { data: mockQueryData.keys, isLoading: false }
    }
    if (key[0] === 'claim-policy-preview') {
      return { data: mockQueryData.policy, isLoading: false }
    }
    return { data: undefined, isLoading: false }
  },
}))

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({ user: { email: 'admin@test.com' } }),
}))

const DEFAULT_POLICY = {
  client_id: 'c1',
  is_custom: false,
  rules: [
    {
      claim_name: 'https://authglow.example.com/claims/roles',
      source: 'rbac_roles',
      source_config: {},
      include_in: ['access_token'],
      required_scope: null,
      description: null,
    },
  ],
  default_rules: [],
}

describe('TokenPreviewFlow - client selection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.clients = [
      { client_id: 'c1', client_name: 'Test Client', allowed_scopes: ['read', 'write'] },
      { client_id: 'c2', client_name: 'Other Client', allowed_scopes: ['openid'] },
    ]
    mockQueryData.policy = { ...DEFAULT_POLICY }
  })

  it('lists the available OAuth clients as cards', () => {
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    expect(screen.getByTestId('token-preview-clients')).toBeInTheDocument()
    expect(screen.getByTestId('preview-client-c1')).toBeInTheDocument()
    expect(screen.getByTestId('preview-client-c2')).toBeInTheDocument()
  })

  it('moves to the preview step when a client is selected', async () => {
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('preview-client-c1'))
    await waitFor(() => {
      expect(screen.getByTestId('preview-payload-panel')).toBeInTheDocument()
    })
  })

  it('shows an empty-state message when no clients are configured', () => {
    mockQueryData.clients = []
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    expect(screen.getByText(/No OAuth clients configured yet/i)).toBeInTheDocument()
  })
})

describe('TokenPreviewFlow - preview payload', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.clients = [{ client_id: 'c1', client_name: 'Test' }]
  })

  it('renders the namespaced RBAC claim for a default policy', async () => {
    mockQueryData.policy = { ...DEFAULT_POLICY }
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('preview-client-c1'))
    const json = await screen.findByTestId('preview-payload-json')
    expect(json.textContent).toContain('https://authglow.example.com/claims/roles')
    expect(json.textContent).toMatch(/"admin"/)
    expect(json.textContent).toMatch(/"developer"/)
  })

  it('shows a user_field claim as a placeholder', async () => {
    mockQueryData.policy = {
      client_id: 'c1',
      is_custom: true,
      rules: [
        {
          claim_name: 'https://authglow/claims/tenant_id',
          source: 'user_field',
          source_config: { user_field: 'tenant_id' },
          include_in: ['access_token'],
          required_scope: null,
          description: null,
        },
      ],
      default_rules: [],
    }
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('preview-client-c1'))
    const json = await screen.findByTestId('preview-payload-json')
    expect(json.textContent).toContain('<user.tenant_id>')
  })

  it('shows a static value claim as the literal', async () => {
    mockQueryData.policy = {
      client_id: 'c1',
      is_custom: true,
      rules: [
        {
          claim_name: 'https://authglow/claims/environment',
          source: 'static',
          source_config: { value: 'production' },
          include_in: ['access_token'],
          required_scope: null,
          description: null,
        },
      ],
      default_rules: [],
    }
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('preview-client-c1'))
    const json = await screen.findByTestId('preview-payload-json')
    expect(json.textContent).toContain('"production"')
  })

  it('filters out claims when the required scope is missing', async () => {
    mockQueryData.policy = {
      client_id: 'c1',
      is_custom: true,
      rules: [
        {
          claim_name: 'https://authglow/claims/roles',
          source: 'rbac_roles',
          source_config: {},
          include_in: ['access_token'],
          required_scope: 'special',
          description: null,
        },
      ],
      default_rules: [],
    }
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('preview-client-c1'))
    // Default scopes don't include "special" → claim filtered out
    const json = await screen.findByTestId('preview-payload-json')
    expect(json.textContent).not.toContain('https://authglow/claims/roles')
  })

  it('includes the claim when the required scope is granted', async () => {
    mockQueryData.policy = {
      client_id: 'c1',
      is_custom: true,
      rules: [
        {
          claim_name: 'https://authglow/claims/roles',
          source: 'rbac_roles',
          source_config: {},
          include_in: ['access_token'],
          required_scope: 'special',
          description: null,
        },
      ],
      default_rules: [],
    }
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('preview-client-c1'))
    const scopesInput = screen.getByTestId('preview-scopes-input')
    fireEvent.change(scopesInput, { target: { value: 'openid special' } })
    const json = await screen.findByTestId('preview-payload-json')
    expect(json.textContent).toContain('https://authglow/claims/roles')
  })
})


// ---------------------------------------------------------------------------
// API key flow (token kind = 'api_key')
// ---------------------------------------------------------------------------


describe("TokenPreviewFlow - API key kind", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.clients = [
      { client_id: 'c1', client_name: 'Test Client', allowed_scopes: ['read'] },
    ]
    mockQueryData.keys = [
      {
        key_id: 'k1',
        user_id: 'u-1',
        user_email: 'u@test.com',
        name: 'Production Key',
        description: null,
        key_prefix: 'ak_ABCDEFGHIJ',
        scopes: ['read', 'write'],
        tier: 'production',
        is_active: true,
        allowed_ips: ['10.0.0.0/24'],
      },
    ]
    mockQueryData.policy = {
      client_id: 'k1',
      is_custom: false,
      rules: [
        {
          claim_name: 'https://authglow.example.com/claims/api_key_name',
          source: 'api_key_field',
          source_config: { api_key_field: 'name' },
          include_in: ['access_token'],
          required_scope: null,
          description: null,
        },
      ],
      default_rules: [],
    }
  })

  it('switches to the API key kind when the picker button is clicked', () => {
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('token-kind-api-key-btn'))
    // The key list is rendered (not the client list)
    expect(screen.getByTestId('token-preview-keys')).toBeInTheDocument()
    expect(screen.queryByTestId('token-preview-clients')).not.toBeInTheDocument()
  })

  it('lists the API keys as clickable cards', () => {
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('token-kind-api-key-btn'))
    expect(screen.getByTestId('preview-key-k1')).toBeInTheDocument()
  })

  it('shows the tier badge on the key card', () => {
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('token-kind-api-key-btn'))
    expect(screen.getByText('tier: production')).toBeInTheDocument()
  })

  it('moves to the preview step when a key is selected', async () => {
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('token-kind-api-key-btn'))
    fireEvent.click(screen.getByTestId('preview-key-k1'))
    await waitFor(() => {
      expect(screen.getByTestId('preview-payload-panel')).toBeInTheDocument()
    })
  })

  it('shows the merge hint badge for the API key kind', async () => {
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('token-kind-api-key-btn'))
    fireEvent.click(screen.getByTestId('preview-key-k1'))
    const hint = await screen.findByTestId('merge-hint')
    expect(hint).toBeInTheDocument()
    expect(hint.textContent).toMatch(/merge with default/i)
  })

  it('shows the default RBAC claims PLUS the saved rule (merge semantic)', async () => {
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('token-kind-api-key-btn'))
    fireEvent.click(screen.getByTestId('preview-key-k1'))
    const json = await screen.findByTestId('preview-payload-json')
    // Default first-party claims (merge always applies them)
    expect(json.textContent).toContain('https://authglow.example.com/claims/roles')
    expect(json.textContent).toContain('https://authglow.example.com/claims/permissions')
    // The saved API key rule
    expect(json.textContent).toContain('https://authglow.example.com/claims/api_key_name')
  })

  it('filters out claims when the required scope is missing (API key flow)', async () => {
    mockQueryData.policy = {
      client_id: 'k1',
      is_custom: true,
      rules: [
        {
          claim_name: 'https://authglow.example.com/claims/api_key_tier',
          source: 'api_key_field',
          source_config: { api_key_field: 'tier' },
          include_in: ['access_token'],
          required_scope: 'special',
          description: null,
        },
      ],
      default_rules: [],
    }
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('token-kind-api-key-btn'))
    fireEvent.click(screen.getByTestId('preview-key-k1'))
    // The default scopes ['read', 'write'] don't include 'special' → tier filtered out
    const json = await screen.findByTestId('preview-payload-json')
    expect(json.textContent).not.toContain('https://authglow.example.com/claims/api_key_tier')
  })

  it('shows an empty-state message when no API keys are configured', () => {
    mockQueryData.keys = []
    render(
      <Wrapper>
        <TokenPreviewFlow />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('token-kind-api-key-btn'))
    expect(screen.getByText(/No API keys configured yet/i)).toBeInTheDocument()
  })
})
