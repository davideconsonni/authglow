// Token Claims tab - per-API-key claim policy editor.
//
// Information-design principles (mirrored from TokenClaimsTab
// for visual consistency between the two editors):
//
// 1. **Anteprima-prima**: the live JWT-payload preview is the
//    topmost element of the modal, not a side-effect of saving.
//    The admin sees the result of their edits before saving.
//
// 2. **Source picker as visual cards** (5 cards now): User
//    field / RBAC roles / RBAC permissions / Static /
//    **API key field** (the new source specific to this modal).
//
// 3. **Inline OIDC namespacing validation** (green / yellow / red
//    border on the claim-name field, with a one-line
//    explanation of the rule being enforced).
//
// 4. **Show, don't tell for destinations**: tokens the claim can
//    appear in (access / ID / UserInfo) are clickable chips with
//    icons, not a checkbox column.
//
// 5. **Empty state with guidance**: when the key has no
//    custom policy, the modal explains the MERGE semantic
//    (the default first-party rules are always emitted on
//    top of the saved ones) and shows the quick-add templates.
//
// 6. **Live preview on every keystroke**: the payload above
//    the form updates as the admin types (synchronous, since
//    the policy resolution is in-memory).
//
// 7. **"Unsaved changes" banner** with explicit Save / Cancel
//    CTAs (no implicit save).
//
// 8. **Context strip at the top**: the modal shows the API
//    key's name, prefix, scopes, tier so the admin knows
//    what the claim source actually has to read from. This
//    is the API-key counterpart of the "sub = client_id"
//    identifier strip on the OAuth client modal.

import { useEffect, useMemo, useState } from 'react'
import {
  AlertCircle, AlertTriangle, Check, CheckCircle2, ChevronRight,
  Database, KeyRound, Loader2, Lock, Plus, Save, Shield, Sparkles,
  Trash2, User, X, type LucideIcon,
} from 'lucide-react'
import { api } from '../../lib/api'
import { useApiQuery } from '../../hooks/useApi'
import { cn } from '../../lib/utils'
import { Banner } from '../../components/shared/Banner'
import { notify } from '../../stores/toastStore'

// ---------------------------------------------------------------------------
// Types - mirror the backend Pydantic models (with the new
// ``api_key_field`` source for API key policies)
// ---------------------------------------------------------------------------

type ClaimSource =
  | 'user_field'
  | 'rbac_roles'
  | 'rbac_permissions'
  | 'static'
  | 'jwt_meta'
  | 'api_key_field'
type ClaimTarget = 'access_token' | 'id_token' | 'userinfo'

interface ClaimSourceConfig {
  user_field?: string | null
  value?: unknown
  jwt_meta?: string | null
  api_key_field?: string | null
}

interface ClaimRulePayload {
  claim_name: string
  source: ClaimSource
  source_config: ClaimSourceConfig
  include_in: ClaimTarget[]
  required_scope?: string | null
  description?: string | null
}

interface ClaimTemplate {
  id: string
  label: string
  description: string
  claim_name: string
  source: ClaimSource
  include_in: ClaimTarget[]
  required_scope?: string | null
  source_config: ClaimSourceConfig
}

interface ClaimPolicyResponse {
  client_id: string
  is_custom: boolean
  rules: ClaimRulePayload[]
  default_rules: ClaimRulePayload[]
  updated_at?: string | null
}

interface ApiKeyData {
  key_id: string
  user_id: string
  user_email: string
  name: string
  description: string | null
  key_prefix: string
  scopes: string[]
  tier: string | null
  is_active: boolean
  allowed_ips: string[]
}

// OIDC Core §5.1 - claim names that DO NOT require a namespace URI.
const OIDC_STANDARD_CLAIMS = new Set<string>([
  'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'nbf', 'azp', 'cnf',
  'name', 'given_name', 'family_name', 'middle_name', 'nickname',
  'preferred_username', 'profile', 'picture', 'website', 'gender',
  'birthdate', 'zoneinfo', 'locale', 'updated_at',
  'email', 'email_verified', 'phone_number', 'phone_number_verified',
  'address', 'nonce', 'auth_time', 'acr', 'amr', 'sid', 'at_hash', 'c_hash',
  'client_id', 'scope', 'scp', 'token_type',
])

const RESERVED_CLAIMS = new Set<string>([
  'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'nbf', 'azp', 'cnf', 'token_type',
])

// Source picker cards - one per ClaimSource. The icon + label
// teach the data model rather than the operator having to read
// a doc. The API_KEY_FIELD card is only meaningful inside an
// API key claim policy (its data source is the API key model).
const SOURCE_CARDS: { id: ClaimSource; label: string; description: string; icon: LucideIcon }[] = [
  { id: 'user_field', label: 'User attribute', description: 'Read a field off the user record (e.g. tenant_id, organization)', icon: User },
  { id: 'rbac_roles', label: 'RBAC roles', description: 'The list of role names assigned to the user', icon: KeyRound },
  { id: 'rbac_permissions', label: 'RBAC permissions', description: 'The list of permission names aggregated from roles', icon: Lock },
  { id: 'static', label: 'Static value', description: 'A literal value baked into the rule (e.g. environment=production)', icon: Database },
  { id: 'api_key_field', label: 'API key attribute', description: 'Read a field off the API key record (name, prefix, scopes, tier, allowed_ips)', icon: Shield },
]

const TARGET_META: Record<ClaimTarget, { label: string; icon: LucideIcon; bg: string }> = {
  access_token: { label: 'Access Token', icon: KeyRound, bg: 'bg-brand-violet/10 text-brand-violet border-brand-violet/30' },
  id_token: { label: 'ID Token', icon: Sparkles, bg: 'bg-brand-blue/10 text-brand-blue border-brand-blue/30' },
  userinfo: { label: 'UserInfo', icon: User, bg: 'bg-semantic-info/10 text-semantic-info border-semantic-info/30' },
}

const ALL_TARGETS: ClaimTarget[] = ['access_token', 'id_token', 'userinfo']

// API key fields exposed by the API_KEY_FIELD source. The
// list is closed (whitelisted server-side) so typos in the
// admin UI are caught at save time.
const AVAILABLE_API_KEY_FIELDS = [
  { value: 'name', label: 'name', desc: 'The display name set at creation' },
  { value: 'key_prefix', label: 'key_prefix', desc: 'The public prefix (e.g. ak_ABCDEFGHIJ)' },
  { value: 'scopes', label: 'scopes', desc: 'The OAuth scopes the key was granted' },
  { value: 'allowed_ips', label: 'allowed_ips', desc: 'The IP allowlist bound to the key' },
  { value: 'tier', label: 'tier', desc: 'Free-form tier label (production, staging, …)' },
]

// ---------------------------------------------------------------------------
// Validation - claim name -> status
// ---------------------------------------------------------------------------

type ClaimNameStatus =
  | { kind: 'ok'; message: string }
  | { kind: 'standard'; message: string }
  | { kind: 'uri'; message: string }
  | { kind: 'reserved'; message: string }
  | { kind: 'invalid'; message: string }
  | { kind: 'empty'; message: string }

function validateClaimName(name: string): ClaimNameStatus {
  if (!name) return { kind: 'empty', message: 'Claim name is required.' }
  if (RESERVED_CLAIMS.has(name)) {
    return {
      kind: 'reserved',
      message: `${name} is reserved and managed by the JWT service. Your value would be ignored - pick a different name.`,
    }
  }
  if (OIDC_STANDARD_CLAIMS.has(name)) {
    return {
      kind: 'standard',
      message: `Standard OIDC claim - no namespace required.`,
    }
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.\-]*:[^\s]+$/.test(name)) {
    return {
      kind: 'uri',
      message: `Valid namespaced URI per OIDC §5.1.2.`,
    }
  }
  return {
    kind: 'invalid',
    message: `Non-standard claim must be a URI per OIDC §5.1.2 - e.g. https://authglow.example.com/claims/${name || 'tenant_id'}.`,
  }
}

function statusColor(status: ClaimNameStatus): string {
  switch (status.kind) {
    case 'ok':
    case 'uri':
    case 'standard':
      return 'border-semantic-success/40 focus:border-semantic-success'
    case 'reserved':
    case 'invalid':
      return 'border-semantic-error/50 focus:border-semantic-error'
    case 'empty':
      return 'border-surface-2 focus:border-brand-violet'
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface ApiKeyClaimsTabProps {
  keyId: string
  keyName: string
  onClose: () => void
}

export function ApiKeyClaimsTab({ keyId, keyName, onClose }: ApiKeyClaimsTabProps) {
  // ----- Load policy + API key details + templates -----
  const {
    data: policy,
    refetch: refetchPolicy,
    isLoading: policyLoading,
  } = useApiQuery<ClaimPolicyResponse>(
    ['claim-policy-api-key', keyId],
    `/api/admin/api-keys/${encodeURIComponent(keyId)}/claim-policy`,
  )

  // Fetch the API key data for the context strip at the top
  // (name, prefix, scopes, tier). The endpoint is the same
  // one the AdminApiKeysPage uses.
  const { data: keyData } = useApiQuery<ApiKeyData | null>(
    ['admin-api-key', keyId],
    `/api/admin/keys/${encodeURIComponent(keyId)}`,
    { enabled: !!keyId },
  )

  const { data: templates } = useApiQuery<ClaimTemplate[]>(
    ['claim-templates'],
    '/api/admin/claim-templates',
  )

  // ----- Editable copy (the "draft") -----
  const [draft, setDraft] = useState<ClaimRulePayload[]>([])
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (policy) {
      setDraft(policy.rules.map(r => ({ ...r, source_config: { ...r.source_config } })))
      setDirty(false)
    }
  }, [policy?.client_id, policy?.updated_at])

  // ----- Per-rule update helpers -----
  const updateRule = (idx: number, patch: Partial<ClaimRulePayload>) => {
    setDraft(d => d.map((r, i) => (i === idx ? { ...r, ...patch } : r)))
    setDirty(true)
  }
  const updateRuleSourceConfig = (idx: number, patch: Partial<ClaimSourceConfig>) => {
    setDraft(d => d.map((r, i) => (i === idx ? { ...r, source_config: { ...r.source_config, ...patch } } : r)))
    setDirty(true)
  }
  const addRule = (rule: ClaimRulePayload) => {
    setDraft(d => [...d, rule])
    setDirty(true)
  }
  const removeRule = (idx: number) => {
    setDraft(d => d.filter((_, i) => i !== idx))
    setDirty(true)
  }
  const toggleTarget = (idx: number, target: ClaimTarget) => {
    setDraft(d => d.map((r, i) => {
      if (i !== idx) return r
      const has = r.include_in.includes(target)
      return { ...r, include_in: has ? r.include_in.filter(t => t !== target) : [...r.include_in, target] }
    }))
    setDirty(true)
  }

  // ----- Live preview payload (client-side, what the wire would carry).
  //
  // The API key path uses MERGE semantics: the default
  // first-party rules (RBAC roles + permissions) are always
  // emitted, plus any saved rules. The preview mirrors that.
  const previewPayload = useMemo(() => {
    const defaultRoles: string[] = []
    const defaultPermissions: string[] = []
    const ns = 'https://authglow.example.com/claims'
    const out: Record<string, unknown> = {
      [`${ns}/roles`]: defaultRoles,
      [`${ns}/permissions`]: defaultPermissions,
    }
    for (const r of draft) {
      if (!r.include_in.includes('access_token')) continue
      if (RESERVED_CLAIMS.has(r.claim_name)) continue
      if (!r.claim_name) continue
      if (r.source === 'rbac_roles') out[r.claim_name] = defaultRoles
      else if (r.source === 'rbac_permissions') out[r.claim_name] = defaultPermissions
      else if (r.source === 'user_field') out[r.claim_name] = `<user.${r.source_config.user_field ?? '?'}>`
      else if (r.source === 'static') out[r.claim_name] = r.source_config.value ?? null
      else if (r.source === 'api_key_field') {
        out[r.claim_name] = `<api_key.${r.source_config.api_key_field ?? '?'}>`
      } else {
        out[r.claim_name] = '<jwt_meta>'
      }
    }
    return out
  }, [draft])

  // ----- Save / revert -----
  const handleSave = async () => {
    if (!dirty || saving) return
    setSaving(true)
    setError(null)
    try {
      await api.put(
        `/api/admin/api-keys/${encodeURIComponent(keyId)}/claim-policy`,
        { rules: draft },
      )
      notify.success('Token claims saved.')
      setDirty(false)
      await refetchPolicy()
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to save'
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  const handleRevert = () => {
    if (!policy) return
    setDraft(policy.rules.map(r => ({ ...r, source_config: { ...r.source_config } })))
    setDirty(false)
    setError(null)
  }

  const handleDeletePolicy = async () => {
    if (!confirm('Reset to the default claim set? This will remove all custom rules for this API key.')) return
    setSaving(true)
    setError(null)
    try {
      await api.delete(
        `/api/admin/api-keys/${encodeURIComponent(keyId)}/claim-policy`,
      )
      notify.success('Reset to default claim set.')
      setDirty(false)
      await refetchPolicy()
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed'
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  // ----- Add-rule panel state -----
  const [showAddPanel, setShowAddPanel] = useState(false)
  const [newRule, setNewRule] = useState<ClaimRulePayload>(() => emptyRule())
  const newRuleStatus = validateClaimName(newRule.claim_name)

  const applyTemplate = (t: ClaimTemplate) => {
    setNewRule({
      claim_name: t.claim_name,
      source: t.source,
      include_in: [...t.include_in],
      required_scope: t.required_scope ?? null,
      description: t.description,
      source_config: { ...t.source_config },
    })
    setShowAddPanel(true)
  }

  const addNewRule = () => {
    if (newRuleStatus.kind === 'invalid' || newRuleStatus.kind === 'reserved' || newRuleStatus.kind === 'empty') {
      setError('Fix the claim name before adding the rule.')
      return
    }
    if (newRule.include_in.length === 0) {
      setError('Pick at least one token target (Access Token, ID Token, or UserInfo).')
      return
    }
    if (newRule.source === 'user_field' && !newRule.source_config.user_field) {
      setError('Pick a user attribute to read.')
      return
    }
    if (newRule.source === 'api_key_field' && !newRule.source_config.api_key_field) {
      setError('Pick an API key attribute to read.')
      return
    }
    if (newRule.source === 'static' && (newRule.source_config.value === undefined || newRule.source_config.value === null)) {
      setError('Enter a literal value for the static rule.')
      return
    }
    addRule(newRule)
    setNewRule(emptyRule())
    setShowAddPanel(false)
    setError(null)
  }

  const isCustom = policy?.is_custom ?? false
  const ruleCount = draft.length

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-8" data-testid="api-key-claim-policy-modal">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative z-10 flex w-full max-w-5xl flex-col rounded-2xl border border-surface-2 bg-bg-primary shadow-glow-violet max-h-[calc(100vh-4rem)]">

        {/* ----- Header ----- */}
        <div className="flex flex-shrink-0 items-center justify-between border-b border-surface-2 px-6 py-4">
          <div>
            <h2 className="text-lg font-semibold text-text-primary">Token Claims</h2>
            <p className="mt-0.5 text-xs text-text-muted">
              {keyName} · <code className="text-text-secondary">{keyId}</code>
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1 rounded-lg bg-brand-blue/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-brand-blue">
              API Key
            </span>
            {isCustom && (
              <span className="inline-flex items-center gap-1 rounded-lg bg-semantic-info/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-semantic-info" data-testid="api-key-claim-policy-custom-badge">
                Custom Policy
              </span>
            )}
            {!isCustom && (
              <span className="inline-flex items-center gap-1 rounded-lg bg-surface-2 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-text-muted" data-testid="api-key-claim-policy-default-badge">
                Default Rules
              </span>
            )}
            <button onClick={onClose} className="rounded-lg p-1.5 text-text-muted hover:bg-surface-2 hover:text-text-secondary" aria-label="Close">
              <X size={16} />
            </button>
          </div>
        </div>

        {/* ----- ZONE 0: API key context strip -----
            Surface the API key attributes the admin will be
            pulling from. Without this, the API_KEY_FIELD
            source picker is abstract; with this, the admin
            can see at a glance what the key actually has. */}
        {keyData && (
          <div className="flex-shrink-0 border-b border-surface-2 bg-nested-panel px-6 py-3" data-testid="api-key-context-strip">
            <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-text-muted">
              API key
            </p>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px]">
              <span className="font-mono text-text-secondary">
                <span className="text-text-muted">name:</span> {keyData.name}
              </span>
              <span className="font-mono text-text-secondary">
                <span className="text-text-muted">prefix:</span> {keyData.key_prefix}
              </span>
              <span className="font-mono text-text-secondary">
                <span className="text-text-muted">scopes:</span> [{keyData.scopes.join(', ')}]
              </span>
              {keyData.tier && (
                <span className="font-mono text-text-secondary">
                  <span className="text-text-muted">tier:</span> {keyData.tier}
                </span>
              )}
              {keyData.allowed_ips.length > 0 && (
                <span className="font-mono text-text-secondary">
                  <span className="text-text-muted">allowed_ips:</span> [{keyData.allowed_ips.join(', ')}]
                </span>
              )}
            </div>
          </div>
        )}

        {/* ----- ZONE 1: live preview (sticky top) ----- */}
        <div className="flex-shrink-0 border-b border-surface-2 bg-nested-panel px-6 py-4">
          <div className="mb-2 flex items-center justify-between">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                Live preview
              </p>
              <p className="mt-0.5 text-[10px] text-text-muted">
                What the access token will carry. Default + custom rules merged.
              </p>
            </div>
            <span
              className="rounded-lg bg-surface-2 px-2 py-0.5 font-mono text-[10px] text-text-secondary"
              data-testid="api-key-claim-policy-counter"
            >
              {ruleCount === 0
                ? '0 custom rules · 2 default always applied'
                : `${ruleCount} custom ${ruleCount === 1 ? 'rule' : 'rules'} + 2 default`}
            </span>
          </div>
          <PayloadPreview payload={previewPayload} reserved={RESERVED_CLAIMS} />
        </div>

        {/* ----- ZONE 1.5: merge-semantic banner (always visible) ----- */}
        <div className="flex-shrink-0 border-b border-surface-2 bg-brand-blue/5 px-6 py-3" data-testid="api-key-merge-banner">
          <div className="flex items-start gap-2 text-[11px] text-brand-blue">
            <Sparkles size={14} className="mt-0.5 shrink-0" />
            <p>
              API key policies are <strong>merged</strong> with the default
              first-party rules. The default RBAC claims
              (roles + permissions) are <strong>always</strong> emitted on
              top of your custom claims. To override a default value, add
              a custom rule with the same claim name — last-wins.
            </p>
          </div>
        </div>

        {/* ----- Scrollable body (zones 2 + 3) ----- */}
        <div className="flex-1 overflow-y-auto px-6 py-4">

          {error && (
            <div className="mb-4">
              <Banner variant="error" sticky onDismiss={() => setError(null)} data-testid="api-key-claim-policy-error">
                {error}
              </Banner>
            </div>
          )}

          {policyLoading && (
            <div className="flex items-center justify-center py-12 text-text-muted">
              <Loader2 size={20} className="animate-spin" />
            </div>
          )}

          {!policyLoading && (
            <>
              {/* ----- ZONE 1.6: default rules (always applied) -----
                  Read-only reference of the 2 system-emitted claims.
                  The admin can NOT edit or remove these — they are
                  always emitted by the JWT service. */}
              {(policy?.default_rules ?? []).length > 0 && (
                <div
                  className="mb-4 rounded-xl border border-surface-2 bg-nested-panel p-3"
                  data-testid="api-key-default-rules-box"
                >
                  <div className="mb-2 flex items-center gap-1.5">
                    <Lock size={12} className="text-text-muted" />
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">
                      Default rules (always applied)
                    </p>
                    <span className="ml-auto text-[10px] text-text-muted">
                      Cannot be removed
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    {(policy?.default_rules ?? []).map((r, idx) => (
                      <div
                        key={`default-rule-${idx}`}
                        className="rounded-lg border border-surface-2 bg-bg-primary px-2.5 py-1.5"
                        data-testid="api-key-default-rule"
                      >
                        <div className="flex items-center gap-2">
                          <code className="flex-1 font-mono text-[11px] text-text-primary">
                            {r.claim_name}
                          </code>
                          <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] font-mono text-text-secondary">
                            {r.source}
                          </span>
                          <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] font-mono text-text-secondary">
                            {r.include_in.join(', ')}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ----- ZONE 2: current rules ----- */}
              <div className="mb-6">
                <div className="mb-3 flex items-center justify-between">
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">
                    Current Rules
                  </p>
                  {isCustom && (
                    <button
                      onClick={handleDeletePolicy}
                      disabled={saving}
                      data-testid="api-key-claim-policy-reset-btn"
                      className="flex items-center gap-1 text-[11px] text-text-muted hover:text-semantic-error transition-colors"
                    >
                      <Trash2 size={11} /> Reset to default
                    </button>
                  )}
                </div>

                {ruleCount === 0 ? (
                  <EmptyState isCustom={isCustom} onPickTemplate={applyTemplate} templates={templates ?? []} />
                ) : (
                  <div className="space-y-2" data-testid="api-key-claim-rules-list">
                    {draft.map((rule, idx) => (
                      <RuleCard
                        key={`rule-${idx}`}
                        rule={rule}
                        onChange={patch => updateRule(idx, patch)}
                        onSourceConfigChange={patch => updateRuleSourceConfig(idx, patch)}
                        onToggleTarget={t => toggleTarget(idx, t)}
                        onRemove={() => removeRule(idx)}
                      />
                    ))}
                  </div>
                )}
              </div>

              {/* ----- ZONE 3: add panel ----- */}
              <div>
                <button
                  onClick={() => setShowAddPanel(v => !v)}
                  data-testid="api-key-claim-policy-add-btn"
                  className="flex w-full items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-text-muted hover:text-text-secondary transition-colors"
                >
                  <ChevronRight size={12} className={cn('transition-transform', showAddPanel && 'rotate-90')} />
                  Add a claim
                </button>

                {showAddPanel && (
                  <div className="mt-3 space-y-4 rounded-xl border border-surface-2 bg-nested-panel p-4">
                    {/* Quick templates — 5 API key specific ones */}
                    <div>
                      <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-text-muted">
                        Quick templates
                      </p>
                      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                        {(templates ?? [])
                          .filter(t => t.source === 'api_key_field')
                          .map(t => (
                            <button
                              key={t.id}
                              onClick={() => applyTemplate(t)}
                              data-testid={`api-key-claim-template-${t.id}`}
                              className="group flex flex-col items-start rounded-lg border border-surface-2 bg-surface-1 p-2.5 text-left transition-all hover:border-brand-violet hover:shadow-glow-violet/20"
                            >
                              <div className="flex w-full items-center justify-between">
                                <span className="text-[11px] font-semibold text-text-primary">{t.label}</span>
                                <Plus size={11} className="text-text-muted group-hover:text-brand-violet" />
                              </div>
                              <p className="mt-0.5 line-clamp-2 text-[10px] text-text-muted">{t.description}</p>
                            </button>
                          ))}
                      </div>
                    </div>

                    {/* Custom rule form */}
                    <div className="space-y-3 border-t border-surface-2 pt-3">
                      <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">
                        Custom rule
                      </p>

                      <ClaimNameField
                        value={newRule.claim_name}
                        onChange={v => setNewRule(r => ({ ...r, claim_name: v }))}
                        status={newRuleStatus}
                      />

                      <SourcePicker
                        value={newRule.source}
                        onChange={source => setNewRule(r => ({ ...r, source, source_config: {} }))}
                      />

                      <SourceConfigFields
                        source={newRule.source}
                        config={newRule.source_config}
                        onChange={patch => setNewRule(r => ({ ...r, source_config: { ...r.source_config, ...patch } }))}
                      />

                      <TargetChips
                        targets={newRule.include_in}
                        onToggle={t => setNewRule(r => ({
                          ...r,
                          include_in: r.include_in.includes(t) ? r.include_in.filter(x => x !== t) : [...r.include_in, t],
                        }))}
                      />

                      <div>
                        <label className="mb-1 block text-[10px] font-semibold text-text-muted">
                          Required scope (optional)
                        </label>
                        <input
                          value={newRule.required_scope ?? ''}
                          onChange={e => setNewRule(r => ({ ...r, required_scope: e.target.value || null }))}
                          placeholder="e.g. read, write"
                          className="w-full rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
                        />
                        <p className="mt-1 text-[10px] text-text-muted">
                          The claim is only emitted when the API key's scope set includes this scope.
                        </p>
                      </div>

                      <div className="flex items-center justify-end gap-2 border-t border-surface-2 pt-3">
                        <button
                          onClick={() => { setNewRule(emptyRule()); setShowAddPanel(false) }}
                          className="rounded-lg border border-surface-2 px-3 py-1.5 text-[11px] text-text-secondary hover:bg-surface-1"
                        >
                          Cancel
                        </button>
                        <button
                          onClick={addNewRule}
                          disabled={newRuleStatus.kind === 'invalid' || newRuleStatus.kind === 'reserved' || newRuleStatus.kind === 'empty'}
                          data-testid="api-key-claim-policy-add-confirm-btn"
                          className="flex items-center gap-1.5 rounded-lg bg-gradient-cta px-3 py-1.5 text-[11px] font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
                        >
                          <Plus size={11} /> Add to policy
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* ----- Footer with unsaved-state banner + save buttons ----- */}
        <div className="flex-shrink-0 border-t border-surface-2">
          {dirty && (
            <div className="border-b border-semantic-warning/20 bg-semantic-warning/5 px-6 py-2">
              <p className="flex items-center gap-2 text-[11px] text-semantic-warning" data-testid="api-key-claim-policy-unsaved-banner">
                <AlertTriangle size={12} />
                You have unsaved changes.
              </p>
            </div>
          )}
          <div className="flex items-center gap-3 p-4">
            <button onClick={onClose} className="rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2">
              Close
            </button>
            <div className="flex-1" />
            <button
              onClick={handleRevert}
              disabled={!dirty || saving}
              data-testid="api-key-claim-policy-revert-btn"
              className="rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2 disabled:opacity-40"
            >
              Revert
            </button>
            <button
              onClick={handleSave}
              disabled={!dirty || saving}
              data-testid="api-key-claim-policy-save-btn"
              className="flex items-center gap-1.5 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
            >
              {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
              Save policy
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Sub-components (mirrored from TokenClaimsTab with the new
// API_KEY_FIELD source + the dedicated API key context)
// ---------------------------------------------------------------------------

function PayloadPreview({ payload, reserved: _reserved }: { payload: Record<string, unknown>; reserved: Set<string> }) {
  const keys = Object.keys(payload)
  return (
    <div className="rounded-lg border border-surface-2 bg-bg-primary p-3" data-testid="api-key-claim-policy-preview">
      {keys.length === 0 ? (
        <p className="py-2 text-center text-[11px] text-text-muted">
          No custom claims will be emitted. The token will carry only the standard JWT claims.
        </p>
      ) : (
        <>
          <pre className="max-h-40 overflow-y-auto font-mono text-[11px] leading-relaxed text-text-primary">
            <code data-testid="api-key-claim-policy-preview-json">{JSON.stringify(payload, null, 2)}</code>
          </pre>
          <p className="mt-2 text-[10px] text-text-muted">
            The token also carries the standard JWT claims (iss, sub, aud, exp, iat, jti, scopes, email) - managed by the JWT service, not by this policy.
          </p>
        </>
      )}
    </div>
  )
}

function ClaimNameField({ value, onChange, status }: {
  value: string
  onChange: (v: string) => void
  status: ClaimNameStatus
}) {
  const colorClass = statusColor(status)
  return (
    <div>
      <label className="mb-1 block text-[10px] font-semibold text-text-muted">
        Claim name
      </label>
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder="https://authglow.example.com/claims/api_key_tier"
        data-testid="api-key-claim-name-input"
        className={cn(
          'w-full rounded-lg border bg-surface-1 px-2.5 py-1.5 font-mono text-[11px] text-text-primary placeholder:text-text-muted focus:outline-none',
          colorClass,
        )}
      />
      <p
        className={cn(
          'mt-1 flex items-center gap-1 text-[10px]',
          status.kind === 'invalid' || status.kind === 'reserved' ? 'text-semantic-error'
            : status.kind === 'standard' || status.kind === 'uri' ? 'text-semantic-success'
            : 'text-text-muted',
        )}
        role={status.kind === 'invalid' || status.kind === 'reserved' ? 'alert' : 'status'}
        data-testid="api-key-claim-name-status"
      >
        {status.kind === 'uri' || status.kind === 'standard' || status.kind === 'ok' ? (
          <CheckCircle2 size={10} />
        ) : status.kind === 'reserved' || status.kind === 'invalid' ? (
          <AlertCircle size={10} />
        ) : null}
        {status.message}
      </p>
    </div>
  )
}

function SourcePicker({ value, onChange }: { value: ClaimSource; onChange: (s: ClaimSource) => void }) {
  return (
    <div>
      <label className="mb-1 block text-[10px] font-semibold text-text-muted">
        Source
      </label>
      <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3 lg:grid-cols-5">
        {SOURCE_CARDS.map(c => {
          const active = c.id === value
          const Icon = c.icon
          return (
            <button
              key={c.id}
              type="button"
              onClick={() => onChange(c.id)}
              data-testid={`api-key-source-${c.id}`}
              title={c.description}
              className={cn(
                'flex flex-col items-start gap-1 rounded-lg border p-2 text-left transition-all',
                active
                  ? 'border-brand-violet bg-brand-violet/10 text-brand-violet'
                  : 'border-surface-2 bg-surface-1 text-text-secondary hover:border-surface-3',
              )}
            >
              <div className="flex w-full items-center justify-between">
                <Icon size={12} />
                {active && <Check size={10} />}
              </div>
              <span className="text-[10px] font-semibold leading-tight">{c.label}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

function SourceConfigFields({
  source, config, onChange,
}: {
  source: ClaimSource
  config: ClaimSourceConfig
  onChange: (patch: Partial<ClaimSourceConfig>) => void
}) {
  if (source === 'user_field') {
    return (
      <div>
        <label className="mb-1 block text-[10px] font-semibold text-text-muted">
          User attribute
        </label>
        <select
          value={config.user_field ?? ''}
          onChange={e => onChange({ user_field: e.target.value || null })}
          data-testid="api-key-source-config-user-field"
          className="w-full rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] text-text-primary focus:border-brand-violet focus:outline-none"
        >
          <option value="">- Select a user field -</option>
          <option value="tenant_id">tenant_id - Multi-tenant id</option>
          <option value="organization">organization - Org / company name</option>
          <option value="subscription_level">subscription_level - Free / pro / enterprise</option>
          <option value="email">email - The user email</option>
        </select>
      </div>
    )
  }
  if (source === 'static') {
    return (
      <div>
        <label className="mb-1 block text-[10px] font-semibold text-text-muted">
          Literal value
        </label>
        <input
          value={config.value === undefined || config.value === null ? '' : String(config.value)}
          onChange={e => onChange({ value: e.target.value })}
          placeholder='e.g. "production" or 42'
          data-testid="api-key-source-config-static-value"
          className="w-full rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
        />
      </div>
    )
  }
  if (source === 'api_key_field') {
    return (
      <div>
        <label className="mb-1 block text-[10px] font-semibold text-text-muted">
          API key attribute
        </label>
        <select
          value={config.api_key_field ?? ''}
          onChange={e => onChange({ api_key_field: e.target.value || null })}
          data-testid="api-key-source-config-api-key-field"
          className="w-full rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] text-text-primary focus:border-brand-violet focus:outline-none"
        >
          <option value="">- Select an API key attribute -</option>
          {AVAILABLE_API_KEY_FIELDS.map(f => (
            <option key={f.value} value={f.value}>{f.label} - {f.desc}</option>
          ))}
        </select>
      </div>
    )
  }
  return null
}

function TargetChips({ targets, onToggle }: { targets: ClaimTarget[]; onToggle: (t: ClaimTarget) => void }) {
  return (
    <div>
      <label className="mb-1 block text-[10px] font-semibold text-text-muted">
        Include in
      </label>
      <div className="flex flex-wrap gap-1.5">
        {ALL_TARGETS.map(t => {
          const active = targets.includes(t)
          const meta = TARGET_META[t]
          const Icon = meta.icon
          return (
            <button
              key={t}
              type="button"
              onClick={() => onToggle(t)}
              data-testid={`api-key-target-${t}`}
              className={cn(
                'flex items-center gap-1 rounded-lg border px-2.5 py-1 text-[10px] font-semibold transition-all',
                active
                  ? meta.bg
                  : 'border-surface-2 bg-surface-1 text-text-muted hover:border-surface-3',
              )}
            >
              <Icon size={10} />
              {meta.label}
            </button>
          )
        })}
      </div>
    </div>
  )
}

function RuleCard({
  rule, onChange, onSourceConfigChange, onToggleTarget, onRemove,
}: {
  rule: ClaimRulePayload
  onChange: (patch: Partial<ClaimRulePayload>) => void
  onSourceConfigChange: (patch: Partial<ClaimSourceConfig>) => void
  onToggleTarget: (t: ClaimTarget) => void
  onRemove: () => void
}) {
  const status = validateClaimName(rule.claim_name)
  return (
    <div className="rounded-xl border border-surface-2 bg-surface-1 p-3" data-testid="api-key-claim-rule-card">
      <div className="flex items-start gap-2">
        <div className="flex-1 space-y-2">
          <div>
            <div className="flex items-center gap-1.5">
              <input
                value={rule.claim_name}
                onChange={e => onChange({ claim_name: e.target.value })}
                data-testid="api-key-rule-claim-name"
                className={cn(
                  'flex-1 rounded-lg border bg-bg-primary px-2 py-1 font-mono text-[11px] text-text-primary focus:outline-none',
                  statusColor(status),
                )}
              />
              <button
                onClick={onRemove}
                data-testid="api-key-rule-remove-btn"
                className="rounded-lg p-1 text-text-muted hover:text-semantic-error"
                aria-label="Remove rule"
                title="Remove"
              >
                <Trash2 size={11} />
              </button>
            </div>
            <p
              className={cn(
                'mt-1 text-[10px]',
                status.kind === 'invalid' || status.kind === 'reserved' ? 'text-semantic-error'
                  : status.kind === 'standard' || status.kind === 'uri' ? 'text-semantic-success'
                  : 'text-text-muted',
              )}
            >
              {status.message}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <SourcePicker value={rule.source} onChange={src => onChange({ source: src, source_config: {} })} />
          </div>
          <SourceConfigFields
            source={rule.source}
            config={rule.source_config}
            onChange={onSourceConfigChange}
          />

          <TargetChips targets={rule.include_in} onToggle={onToggleTarget} />

          {rule.required_scope && (
            <div className="rounded-lg bg-surface-2 px-2 py-1 text-[10px] text-text-muted">
              Requires scope <code className="font-mono text-text-secondary">{rule.required_scope}</code>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function EmptyState({
  isCustom, onPickTemplate, templates,
}: {
  isCustom: boolean
  onPickTemplate: (t: ClaimTemplate) => void
  templates: ClaimTemplate[]
}) {
  const apiKeyTemplates = templates.filter(t => t.source === 'api_key_field')
  return (
    <div className="rounded-xl border border-dashed border-surface-2 bg-nested-panel p-6 text-center" data-testid="api-key-claim-policy-empty-state">
      <div className="mx-auto mb-3 inline-flex rounded-2xl bg-surface-2 p-3">
        <Shield className="h-5 w-5 text-text-muted" />
      </div>
      <h3 className="text-sm font-semibold text-text-primary">
        {isCustom ? 'No more custom claims needed' : 'No custom claims yet'}
      </h3>
      <p className="mt-1 max-w-md mx-auto text-[11px] text-text-muted">
        {isCustom
          ? 'The default RBAC claims (roles + permissions) are always emitted alongside your saved rules above. Add more rules below, or close this modal — your key is ready to use.'
          : 'The default first-party RBAC claims (roles + permissions) are always emitted. Add a custom rule below if you want to embed additional API key-specific claims (name, tier, scopes, …).'}
      </p>
      {apiKeyTemplates.length > 0 && (
        <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3">
          {apiKeyTemplates.slice(0, 3).map(t => (
            <button
              key={t.id}
              onClick={() => onPickTemplate(t)}
              data-testid={`api-key-empty-template-${t.id}`}
              className="group flex flex-col items-start rounded-lg border border-surface-2 bg-surface-1 p-2.5 text-left transition-all hover:border-brand-violet"
            >
              <span className="text-[11px] font-semibold text-text-primary">{t.label}</span>
              <p className="mt-0.5 line-clamp-2 text-[10px] text-text-muted">{t.description}</p>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

function emptyRule(): ClaimRulePayload {
  return {
    claim_name: '',
    source: 'user_field',
    source_config: {},
    include_in: ['access_token'],
    required_scope: null,
    description: null,
  }
}
