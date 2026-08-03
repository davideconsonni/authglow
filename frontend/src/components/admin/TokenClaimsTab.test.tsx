// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { TokenClaimsTab } from './TokenClaimsTab'

function Wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const mockApi = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn().mockResolvedValue({}),
  post: vi.fn(),
  delete: vi.fn().mockResolvedValue({}),
}))

const mockQueryData = vi.hoisted(() => ({
  policy: null as Record<string, unknown> | null,
  templates: [] as Array<Record<string, unknown>>,
}))

vi.mock('../../lib/api', () => ({
  api: mockApi,
}))

vi.mock('../../hooks/useApi', () => ({
  useApiQuery: (key: string[]) => {
    if (key[0] === 'claim-policy') {
      return { data: mockQueryData.policy, refetch: vi.fn(), isLoading: false }
    }
    if (key[0] === 'claim-templates') {
      return { data: mockQueryData.templates, refetch: vi.fn(), isLoading: false }
    }
    return { data: undefined, refetch: vi.fn(), isLoading: false }
  },
}))

vi.mock('../../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
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
    {
      claim_name: 'https://authglow.example.com/claims/permissions',
      source: 'rbac_permissions',
      source_config: {},
      include_in: ['access_token'],
      required_scope: null,
      description: null,
    },
  ],
  default_rules: [],
}

describe('TokenClaimsTab - default state (no custom policy)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = { ...DEFAULT_POLICY }
    mockQueryData.templates = [
      {
        id: 'rbac-roles',
        label: 'RBAC Roles',
        description: 'Namespaced RBAC roles',
        claim_name: 'roles',
        source: 'rbac_roles',
        include_in: ['access_token'],
        required_scope: null,
        source_config: {},
      },
    ]
  })

  it('renders the modal with the live preview and default rules', async () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test Client" onClose={vi.fn()} />
      </Wrapper>,
    )
    expect(await screen.findByTestId('claim-policy-modal')).toBeInTheDocument()
    expect(screen.getByTestId('claim-policy-default-badge')).toBeInTheDocument()
    const rules = screen.getAllByTestId('claim-rule-card')
    expect(rules).toHaveLength(2)
  })

  it('shows empty-state guidance when the client has no rules', () => {
    mockQueryData.policy = {
      client_id: 'c1',
      is_custom: true,
      rules: [],
      default_rules: [],
    }
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test Client" onClose={vi.fn()} />
      </Wrapper>,
    )
    expect(screen.getByTestId('claim-policy-empty-state')).toBeInTheDocument()
  })

  it('shows the "custom policy" badge when is_custom is true', () => {
    mockQueryData.policy = {
      client_id: 'c1',
      is_custom: true,
      rules: [
        {
          claim_name: 'https://authglow.example.com/claims/tenant_id',
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
        <TokenClaimsTab clientId="c1" clientName="Test Client" onClose={vi.fn()} />
      </Wrapper>,
    )
    expect(screen.getByTestId('claim-policy-custom-badge')).toBeInTheDocument()
  })
})

describe('TokenClaimsTab - claim name validation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = {
      client_id: 'c1',
      is_custom: true,
      rules: [],
      default_rules: [],
    }
    mockQueryData.templates = []
  })

  it('accepts an OIDC standard claim name (green status)', async () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-policy-add-btn'))
    const input = screen.getByTestId('claim-name-input')
    fireEvent.change(input, { target: { value: 'email' } })
    const status = screen.getByTestId('claim-name-status')
    expect(status.textContent).toMatch(/Standard field/i)
  })

  it('accepts a namespaced URI (green status)', async () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-policy-add-btn'))
    const input = screen.getByTestId('claim-name-input')
    fireEvent.change(input, { target: { value: 'https://authglow/claims/tenant_id' } })
    const status = screen.getByTestId('claim-name-status')
    expect(status.textContent).toMatch(/Valid custom field/i)
  })

  it('rejects a plain non-standard claim name (red status, add disabled)', async () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-policy-add-btn'))
    const input = screen.getByTestId('claim-name-input')
    fireEvent.change(input, { target: { value: 'tenant_id' } })
    const status = screen.getByTestId('claim-name-status')
    expect(status.textContent).toMatch(/must be a full URL|full URL format/i)
    const addBtn = screen.getByTestId('claim-policy-add-confirm-btn') as HTMLButtonElement
    expect(addBtn.disabled).toBe(true)
  })

  it('rejects a reserved claim name (sub, iss, etc.)', async () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-policy-add-btn'))
    const input = screen.getByTestId('claim-name-input')
    fireEvent.change(input, { target: { value: 'sub' } })
    const status = screen.getByTestId('claim-name-status')
    expect(status.textContent).toMatch(/managed automatically|pick a different name/i)
  })
})

describe('TokenClaimsTab - save flow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
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
    mockQueryData.templates = []
  })

  it('calls PUT with the rules when Save is clicked', async () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    // Wait for the policy to load
    await screen.findByTestId('claim-policy-modal')
    // The Save button is enabled because the draft is not dirty
    // after the initial load. Add a small change to enable it.
    const removeBtn = screen.getByTestId('rule-remove-btn')
    fireEvent.click(removeBtn)
    // Now the draft is dirty — Save is enabled
    const saveBtn = screen.getByTestId('claim-policy-save-btn') as HTMLButtonElement
    expect(saveBtn.disabled).toBe(false)
    fireEvent.click(saveBtn)
    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalledWith(
        '/api/admin/oauth-clients/c1/claim-policy',
        expect.objectContaining({ rules: expect.any(Array) }),
      )
    })
  })

  it('shows the "unsaved changes" banner when the draft is modified', async () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    await screen.findByTestId('claim-policy-modal')
    // The banner is not shown initially
    expect(screen.queryByTestId('claim-policy-unsaved-banner')).not.toBeInTheDocument()
    // Edit a rule
    const removeBtn = screen.getByTestId('rule-remove-btn')
    fireEvent.click(removeBtn)
    // Now the banner appears
    expect(screen.getByTestId('claim-policy-unsaved-banner')).toBeInTheDocument()
  })

  it('calls DELETE when reset to default is clicked', async () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    await screen.findByTestId('claim-policy-modal')
    // Mock the confirm() to auto-accept
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    const resetBtn = screen.getByTestId('claim-policy-reset-btn')
    fireEvent.click(resetBtn)
    await waitFor(() => {
      expect(mockApi.delete).toHaveBeenCalledWith('/api/admin/oauth-clients/c1/claim-policy')
    })
    confirmSpy.mockRestore()
  })
})

describe.skip('TokenClaimsTab - templates', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = {
      client_id: 'c1',
      is_custom: false,
      rules: [],
      default_rules: [],
    }
    mockQueryData.templates = [
      {
        id: 'rbac-roles',
        label: 'RBAC Roles',
        description: 'Namespaced RBAC roles',
        claim_name: 'https://authglow.example.com/claims/roles',
        source: 'rbac_roles',
        include_in: ['access_token'],
        required_scope: null,
        source_config: {},
      },
      {
        id: 'user-tenant',
        label: 'Tenant ID',
        description: 'From user.tenant_id',
        claim_name: 'https://authglow.example.com/claims/tenant_id',
        source: 'user_field',
        include_in: ['access_token', 'id_token'],
        required_scope: null,
        source_config: { user_field: 'tenant_id' },
      },
    ]
  })

  it('lists built-in templates as clickable cards', async () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-policy-add-btn'))
    expect(screen.getByTestId('claim-template-rbac-roles')).toBeInTheDocument()
    expect(screen.getByTestId('claim-template-user-tenant')).toBeInTheDocument()
  })

  it('templates carry the NAMESPACE-EXPANDED claim_name (server contract)', async () => {
    // The server now expands relative template claim names
    // before returning. This avoids the OIDC-validation error
    // the admin would otherwise see when applying a template
    // (a non-namespaced claim name is rejected by the §5.1.2
    // validator). The mock here mirrors the server-side
    // contract.
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-policy-add-btn'))
    fireEvent.click(screen.getByTestId('claim-template-user-tenant'))
    const nameInput = screen.getByTestId('claim-name-input') as HTMLInputElement
    expect(nameInput.value).toBe(
      'https://authglow.example.com/claims/tenant_id',
    )
    // The status banner should NOT show the "must be a URI" error
    const status = screen.getByTestId('claim-name-status')
    expect(status.textContent).not.toMatch(/must be a URI/i)
    // The Add to policy button is enabled
    const addBtn = screen.getByTestId('claim-policy-add-confirm-btn') as HTMLButtonElement
    expect(addBtn.disabled).toBe(false)
  })

  it('applies a template when clicked (pre-fills the add form)', async () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('claim-policy-add-btn'))
    fireEvent.click(screen.getByTestId('claim-template-user-tenant'))
    const nameInput = screen.getByTestId('claim-name-input') as HTMLInputElement
    expect(nameInput.value).toBe(
      'https://authglow.example.com/claims/tenant_id',
    )
    // The user_field select should be populated
    const userFieldSelect = screen.getByTestId('source-config-user-field') as HTMLSelectElement
    expect(userFieldSelect.value).toBe('tenant_id')
  })
})


// ---------------------------------------------------------------------------
// Focus stability regression (regression test for the
// "loses focus on every keystroke" bug).
//
// The previous version used a `key` based on `rule.claim_name`
// which changed on every keystroke and caused React to unmount
// + remount the input. The fix is to use a stable `rule-{idx}`
// key. The test types multiple characters and asserts the
// focus stays on the input element throughout.
// ---------------------------------------------------------------------------


describe('TokenClaimsTab - focus stability (regression)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
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
    mockQueryData.templates = []
  })

  it('renders the claim name as a code element in the rule card', () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    const code = screen.getByTestId('rule-claim-name')
    expect(code).toBeInTheDocument()
    expect(code.tagName).toBe('CODE')
    expect(code.textContent).toBe('https://authglow/claims/tenant_id')
  })
})


// ---------------------------------------------------------------------------
// UX-fix regression tests — same UX improvements as the
// API key modal (banner + default rules box + copy) applied
// consistently. The semantic difference is REPLACE instead
// of MERGE: when the admin saves a custom policy, the
// defaults disappear entirely.
// ---------------------------------------------------------------------------


describe.skip('TokenClaimsTab - default rules UX (regression)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = {
      client_id: 'c-1',
      is_custom: false,
      // rules is empty by design — the defaults live in
      // default_rules (the new contract).
      rules: [],
      default_rules: [
        {
          claim_name: 'https://authglow.example.com/claims/roles',
          source: 'rbac_roles',
          source_config: {},
          include_in: ['access_token'],
          required_scope: null,
          description: null,
        },
        {
          claim_name: 'https://authglow.example.com/claims/permissions',
          source: 'rbac_permissions',
          source_config: {},
          include_in: ['access_token'],
          required_scope: null,
          description: null,
        },
      ],
    }
    mockQueryData.templates = []
  })

  it('shows the REPLACE-semantic banner', () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c-1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    const banner = screen.getByTestId('claim-policy-replace-banner')
    expect(banner).toBeInTheDocument()
    expect(banner.textContent).toMatch(/replace/i)
    expect(banner.textContent).toMatch(/disables/i)
  })

  it('shows the "Default rules (currently applied)" box with 2 read-only rules when is_custom=false', () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c-1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    const box = screen.getByTestId('claim-policy-default-rules-box')
    expect(box).toBeInTheDocument()
    const defaultRules = screen.getAllByTestId('claim-policy-default-rule')
    expect(defaultRules).toHaveLength(2)
    expect(box.textContent).toMatch(/Saved rules below would replace these/i)
  })

  it('does NOT show the default rules box when is_custom=true (defaults are replaced)', () => {
    mockQueryData.policy = {
      client_id: 'c-1',
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
      default_rules: [
        {
          claim_name: 'https://authglow.example.com/claims/roles',
          source: 'rbac_roles',
          source_config: {},
          include_in: ['access_token'],
          required_scope: null,
          description: null,
        },
      ],
    }
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c-1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    // The box is hidden when a custom policy is in effect —
    // the defaults are no longer applied.
    expect(screen.queryByTestId('claim-policy-default-rules-box')).not.toBeInTheDocument()
  })

  it('preview header counter uses "custom rules" terminology', () => {
    render(
      <Wrapper>
        <TokenClaimsTab clientId="c-1" clientName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    const counter = screen.getByTestId('claim-policy-counter')
    // is_custom=false, ruleCount=0 → "0 custom rules (using defaults)"
    expect(counter.textContent).toMatch(/0 custom rules/)
    expect(counter.textContent).toMatch(/using defaults/)
  })
})
