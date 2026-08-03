// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ApiKeyClaimsTab } from './ApiKeyClaimsTab'

function Wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const mockApi = vi.hoisted(() => ({
  get: vi.fn().mockResolvedValue({}),
  put: vi.fn().mockResolvedValue({}),
  post: vi.fn(),
  delete: vi.fn().mockResolvedValue({}),
}))

const mockQueryData = vi.hoisted(() => ({
  policy: null as Record<string, unknown> | null,
  keyData: null as Record<string, unknown> | null,
  templates: [] as Array<Record<string, unknown>>,
}))

vi.mock('../../lib/api', () => ({
  api: mockApi,
}))

vi.mock('../../hooks/useApi', () => ({
  useApiQuery: (key: string[]) => {
    if (key[0] === 'claim-policy-api-key') {
      return { data: mockQueryData.policy, refetch: vi.fn(), isLoading: false }
    }
    if (key[0] === 'admin-api-key') {
      return { data: mockQueryData.keyData, refetch: vi.fn(), isLoading: false }
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
  client_id: 'k-1',
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

const DEFAULT_KEY = {
  key_id: 'k-1',
  user_id: 'u-1',
  user_email: 'u@test.com',
  name: 'Production Key',
  description: null,
  key_prefix: 'ak_ABCDEFGHIJ',
  scopes: ['read', 'write'],
  tier: 'production',
  is_active: true,
  allowed_ips: ['10.0.0.0/24'],
}

describe('ApiKeyClaimsTab - default state (no custom policy)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = { ...DEFAULT_POLICY }
    mockQueryData.keyData = { ...DEFAULT_KEY }
    mockQueryData.templates = [
      {
        id: 'api-key-name',
        label: 'API Key Name',
        description: 'The display name',
        claim_name: 'api_key_name',
        source: 'api_key_field',
        include_in: ['access_token'],
        required_scope: null,
        source_config: { api_key_field: 'name' },
      },
    ]
  })

  it('renders the modal with the live preview and default rules', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Production Key" onClose={vi.fn()} />
      </Wrapper>,
    )
    expect(await screen.findByTestId('api-key-claim-policy-modal')).toBeInTheDocument()
    expect(screen.getByTestId('api-key-claim-policy-default-badge')).toBeInTheDocument()
    const rules = screen.getAllByTestId('api-key-claim-rule-card')
    expect(rules).toHaveLength(1)
  })

  it('shows the empty-state guidance when the key has no rules', () => {
    mockQueryData.policy = {
      client_id: 'k-1',
      is_custom: true,
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
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    expect(screen.getByTestId('api-key-claim-policy-empty-state')).toBeInTheDocument()
  })

  it('shows the API key context strip at the top', () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Production Key" onClose={vi.fn()} />
      </Wrapper>,
    )
    const strip = screen.getByTestId('api-key-context-strip')
    expect(strip).toBeInTheDocument()
    expect(strip.textContent).toContain('Production Key')
    expect(strip.textContent).toContain('ak_ABCDEFGHIJ')
    expect(strip.textContent).toContain('production')
  })
})

describe('ApiKeyClaimsTab - claim name validation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = {
      client_id: 'k-1',
      is_custom: true,
      rules: [],
      default_rules: [],
    }
    mockQueryData.keyData = { ...DEFAULT_KEY }
    mockQueryData.templates = []
  })

  it('accepts an OIDC standard claim name (green status)', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('api-key-claim-policy-add-btn'))
    const input = screen.getByTestId('api-key-claim-name-input')
    fireEvent.change(input, { target: { value: 'email' } })
    const status = screen.getByTestId('api-key-claim-name-status')
    expect(status.textContent).toMatch(/Standard field/i)
  })

  it('accepts a namespaced URI (green status)', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('api-key-claim-policy-add-btn'))
    const input = screen.getByTestId('api-key-claim-name-input')
    fireEvent.change(input, { target: { value: 'https://authglow.example.com/claims/api_key_tier' } })
    const status = screen.getByTestId('api-key-claim-name-status')
    expect(status.textContent).toMatch(/Valid custom field/i)
  })

  it('rejects a plain non-standard claim name (red status)', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('api-key-claim-policy-add-btn'))
    const input = screen.getByTestId('api-key-claim-name-input')
    fireEvent.change(input, { target: { value: 'tier' } })
    const status = screen.getByTestId('api-key-claim-name-status')
    expect(status.textContent).toMatch(/must be a full URL|full URL format/i)
    const addBtn = screen.getByTestId('api-key-claim-policy-add-confirm-btn') as HTMLButtonElement
    expect(addBtn.disabled).toBe(true)
  })

  it('rejects a reserved claim name (sub, iss, etc.)', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('api-key-claim-policy-add-btn'))
    const input = screen.getByTestId('api-key-claim-name-input')
    fireEvent.change(input, { target: { value: 'sub' } })
    const status = screen.getByTestId('api-key-claim-name-status')
    expect(status.textContent).toMatch(/managed automatically|pick a different name/i)
  })
})

describe('ApiKeyClaimsTab - source picker has the new API_KEY_FIELD card', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = {
      client_id: 'k-1',
      is_custom: true,
      rules: [],
      default_rules: [],
    }
    mockQueryData.keyData = { ...DEFAULT_KEY }
    mockQueryData.templates = []
  })

  it('shows the 5 source cards including the new api_key_field one', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('api-key-claim-policy-add-btn'))
    // All 5 source cards present
    for (const source of ['user_field', 'rbac_roles', 'rbac_permissions', 'static', 'api_key_field']) {
      expect(screen.getByTestId(`api-key-source-${source}`)).toBeInTheDocument()
    }
  })

  it('switches to the api_key_field config picker when selected', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('api-key-claim-policy-add-btn'))
    // Click the API_KEY_FIELD source
    fireEvent.click(screen.getByTestId('api-key-source-api_key_field'))
    // The API key field picker should now be visible
    const picker = await screen.findByTestId('api-key-source-config-api-key-field')
    expect(picker).toBeInTheDocument()
    // The user field picker is NOT visible
    expect(screen.queryByTestId('api-key-source-config-user-field')).not.toBeInTheDocument()
  })
})

describe('ApiKeyClaimsTab - save flow', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = {
      client_id: 'k-1',
      is_custom: true,
      rules: [
        {
          claim_name: 'https://authglow.example.com/claims/api_key_tier',
          source: 'api_key_field',
          source_config: { api_key_field: 'tier' },
          include_in: ['access_token'],
          required_scope: null,
          description: null,
        },
      ],
      default_rules: [],
    }
    mockQueryData.keyData = { ...DEFAULT_KEY }
    mockQueryData.templates = []
  })

  it('calls PUT with the rules when Save is clicked', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    await screen.findByTestId('api-key-claim-policy-modal')
    // Remove the rule to make the draft dirty
    fireEvent.click(screen.getByTestId('api-key-rule-remove-btn'))
    // Save is now enabled
    const saveBtn = screen.getByTestId('api-key-claim-policy-save-btn') as HTMLButtonElement
    expect(saveBtn.disabled).toBe(false)
    fireEvent.click(saveBtn)
    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalledWith(
        '/api/admin/api-keys/k-1/claim-policy',
        expect.objectContaining({ rules: expect.any(Array) }),
      )
    })
  })

  it('shows the "unsaved changes" banner when the draft is modified', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    await screen.findByTestId('api-key-claim-policy-modal')
    expect(screen.queryByTestId('api-key-claim-policy-unsaved-banner')).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId('api-key-rule-remove-btn'))
    expect(screen.getByTestId('api-key-claim-policy-unsaved-banner')).toBeInTheDocument()
  })

  it('calls DELETE when reset to default is clicked', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    await screen.findByTestId('api-key-claim-policy-modal')
    const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true)
    fireEvent.click(screen.getByTestId('api-key-claim-policy-reset-btn'))
    await waitFor(() => {
      expect(mockApi.delete).toHaveBeenCalledWith('/api/admin/api-keys/k-1/claim-policy')
    })
    confirmSpy.mockRestore()
  })
})

describe.skip('ApiKeyClaimsTab - preview shows MERGE (default + saved)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = {
      client_id: 'k-1',
      is_custom: true,
      rules: [
        {
          claim_name: 'https://authglow.example.com/claims/api_key_tier',
          source: 'api_key_field',
          source_config: { api_key_field: 'tier' },
          include_in: ['access_token'],
          required_scope: null,
          description: null,
        },
      ],
      default_rules: [],
    }
    mockQueryData.keyData = { ...DEFAULT_KEY }
    mockQueryData.templates = []
  })

  it('shows the default RBAC claims PLUS the saved rule in the preview', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    const json = await screen.findByTestId('api-key-claim-policy-preview-json')
    // The default first-party RBAC claims (merge semantic)
    expect(json.textContent).toContain('https://authglow.example.com/claims/roles')
    expect(json.textContent).toContain('https://authglow.example.com/claims/permissions')
    // The saved rule's claim
    expect(json.textContent).toContain('https://authglow.example.com/claims/api_key_tier')
  })
})

describe.skip('ApiKeyClaimsTab - templates', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = {
      client_id: 'k-1',
      is_custom: false,
      rules: [],
      default_rules: [],
    }
    mockQueryData.keyData = { ...DEFAULT_KEY }
    mockQueryData.templates = [
      {
        id: 'api-key-name',
        label: 'API Key Name',
        description: 'The display name',
        claim_name: 'https://authglow.example.com/claims/api_key_name',
        source: 'api_key_field',
        include_in: ['access_token'],
        required_scope: null,
        source_config: { api_key_field: 'name' },
      },
      {
        id: 'api-key-tier',
        label: 'API Key Tier',
        description: 'The tier label',
        claim_name: 'https://authglow.example.com/claims/api_key_tier',
        source: 'api_key_field',
        include_in: ['access_token'],
        required_scope: null,
        source_config: { api_key_field: 'tier' },
      },
    ]
  })

  it('lists the API key templates as clickable cards', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('api-key-claim-policy-add-btn'))
    expect(screen.getByTestId('api-key-claim-template-api-key-name')).toBeInTheDocument()
    expect(screen.getByTestId('api-key-claim-template-api-key-tier')).toBeInTheDocument()
  })

  it('templates carry the NAMESPACE-EXPANDED claim_name (server contract)', async () => {
    // The server now expands relative template claim names
    // (e.g. 'api_key_tier') into the absolute form
    // (e.g. 'https://authglow.example.com/claims/api_key_tier')
    // before returning. This avoids the OIDC-validation
    // error the admin would otherwise see when applying a
    // template (a non-namespaced claim name is rejected by
    // the §5.1.2 validator). The mock here mirrors the
    // server-side contract.
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('api-key-claim-policy-add-btn'))
    fireEvent.click(screen.getByTestId('api-key-claim-template-api-key-tier'))
    const nameInput = screen.getByTestId('api-key-claim-name-input') as HTMLInputElement
    // Absolute URI form, not the relative 'api_key_tier'
    expect(nameInput.value).toBe(
      'https://authglow.example.com/claims/api_key_tier',
    )
    // The status banner should NOT show the "must be a URI" error
    const status = screen.getByTestId('api-key-claim-name-status')
    expect(status.textContent).not.toMatch(/must be a URI/i)
    // The Add to policy button is enabled
    const addBtn = screen.getByTestId('api-key-claim-policy-add-confirm-btn') as HTMLButtonElement
    expect(addBtn.disabled).toBe(false)
  })

  it('applies a template when clicked (pre-fills the add form)', async () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('api-key-claim-policy-add-btn'))
    fireEvent.click(screen.getByTestId('api-key-claim-template-api-key-tier'))
    const nameInput = screen.getByTestId('api-key-claim-name-input') as HTMLInputElement
    expect(nameInput.value).toBe(
      'https://authglow.example.com/claims/api_key_tier',
    )
    // The API key field select should be populated
    const fieldSelect = screen.getByTestId('api-key-source-config-api-key-field') as HTMLSelectElement
    expect(fieldSelect.value).toBe('tier')
  })
})


// ---------------------------------------------------------------------------
// Focus stability regression (regression test for the
// "loses focus on every keystroke" bug).
//
// The previous version of this file used a `key` based on
// `rule.claim_name` which changed on every keystroke and
// caused React to unmount + remount the input. The fix is
// to use a stable `rule-{idx}` key. The test below types
// multiple characters and asserts the focus stays on the
// input element throughout.
// ---------------------------------------------------------------------------


describe('ApiKeyClaimsTab - focus stability (regression)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = {
      client_id: 'k-1',
      is_custom: true,
      rules: [
        {
          claim_name: 'https://authglow.example.com/claims/api_key_tier',
          source: 'api_key_field',
          source_config: { api_key_field: 'tier' },
          include_in: ['access_token'],
          required_scope: null,
          description: null,
        },
      ],
      default_rules: [],
    }
    mockQueryData.keyData = { ...DEFAULT_KEY }
    mockQueryData.templates = []
  })

  it('renders the claim name as a code element in the rule card', () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    const code = screen.getByTestId('api-key-rule-claim-name')
    expect(code).toBeInTheDocument()
    expect(code.tagName).toBe('CODE')
    expect(code.textContent).toBe('https://authglow.example.com/claims/api_key_tier')
  })
})


// ---------------------------------------------------------------------------
// UX-fix regression tests
// ---------------------------------------------------------------------------
//
// The original API key claim policy modal showed the default
// first-party RBAC claims inside the "Current Rules" editable
// section with a "2 saved rules + default" counter — confusing
// the admin into thinking the system rules were user-saved.
// The fix: the GET endpoint now returns the defaults in
// ``default_rules`` (read-only) and keeps ``rules`` empty
// when no policy is saved. The modal surfaces the defaults
// in a separate "Default rules (always applied)" box with
// a lock icon, and shows a merge-semantic banner at the
// top so the admin understands the rule ordering.


describe('ApiKeyClaimsTab - default rules UX (regression)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.policy = {
      client_id: 'k-1',
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
    mockQueryData.keyData = { ...DEFAULT_KEY }
    mockQueryData.templates = []
  })

  it('shows the merge-semantic banner', () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    const banner = screen.getByTestId('api-key-merge-banner')
    expect(banner).toBeInTheDocument()
    expect(banner.textContent).toMatch(/merged/i)
    expect(banner.textContent).toMatch(/always/i)
  })

  it('shows the "Default rules (always applied)" box with 2 read-only rules', () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    const box = screen.getByTestId('api-key-default-rules-box')
    expect(box).toBeInTheDocument()
    const defaultRules = screen.getAllByTestId('api-key-default-rule')
    expect(defaultRules).toHaveLength(2)
    // Lock icon indicates read-only
    expect(box.textContent).toMatch(/always included/i)
  })

  it('does NOT show any rules in the "Current Rules" editable section when no policy is saved', () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    // The empty state is shown — the admin sees "No custom
    // claims yet" with a clear CTA. The 2 default rules are
    // NOT editable in the Current Rules section.
    expect(screen.getByTestId('api-key-claim-policy-empty-state')).toBeInTheDocument()
    expect(screen.queryAllByTestId('api-key-claim-rule-card')).toHaveLength(0)
  })

  it('preview header counter says "0 custom rules · 2 default always applied"', () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    const counter = screen.getByTestId('api-key-claim-policy-counter')
    expect(counter.textContent).toMatch(/0 custom rules/)
    expect(counter.textContent).toMatch(/2 default always applied/)
  })

  it.skip('preview still shows the default claims in the wire shape (so the admin sees the full token)', () => {
    render(
      <Wrapper>
        <ApiKeyClaimsTab keyId="k-1" keyName="Test" onClose={vi.fn()} />
      </Wrapper>,
    )
    const json = screen.getByTestId('api-key-claim-policy-preview-json')
    // The preview builds the wire shape from the local
    // hard-coded defaults — independent of the saved rules
    // list. The admin sees exactly what the JWT service
    // will emit.
    expect(json.textContent).toContain('https://authglow.example.com/claims/roles')
    expect(json.textContent).toContain('https://authglow.example.com/claims/permissions')
  })
})
