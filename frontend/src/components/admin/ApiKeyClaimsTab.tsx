// Visual Token Builder — per-API-key custom data editor.
//
// Design principles (mirrored from TokenClaimsTab for
// visual consistency):
//
// 1. **Token as a concrete object**: the admin sees the token
//    as a visual card with blocks for each field.
//
// 2. **Standard fields visible**: sub, aud, exp, iat are shown
//    as read-only blocks so the admin understands what's
//    already there.
//
// 3. **Custom fields as blocks**: each custom field is a visual
//    block with name, source icon, value preview, and
//    edit/remove buttons.
//
// 4. **Simple questions**: "What do you want to add?" and
//    "Where does the data come from?" — no jargon.
//
// 5. **Inline form**: adding/editing a field is a simple form
//    that appears inside the token card.
//
// 6. **API key extras**: context strip + merge semantics banner
//    + 5th source (API key attribute).

import { useEffect, useRef, useState } from 'react'
import {
  AlertCircle, AlertTriangle, Check, CheckCircle2,
  Database, HelpCircle, KeyRound, Loader2, Lock, Pencil, Plus,
  Save, Shield, Sparkles, Trash2, User, X,
  type LucideIcon,
} from 'lucide-react'
import { api } from '../../lib/api'
import { useApiQuery } from '../../hooks/useApi'
import { cn } from '../../lib/utils'
import { Banner } from '../../components/shared/Banner'
import { ConfirmDialog } from '../../components/shared/ConfirmDialog'
import { ClaimTemplatePicker, type ClaimTemplate } from './ClaimTemplatePicker'
import { notify } from '../../stores/toastStore'

// ---------------------------------------------------------------------------
// Types
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

// Standard fields always present in the token.
const STANDARD_FIELDS = [
  { name: 'sub', description: 'User ID', example: '"user_abc123"' },
  { name: 'aud', description: 'App ID', example: '"my-app"' },
  { name: 'exp', description: 'Expires', example: '1735689600' },
  { name: 'iat', description: 'Issued at', example: '1735686000' },
  { name: 'iss', description: 'Issuer', example: '"https://auth.example.com"' },
  { name: 'jti', description: 'Token ID', example: '"tok_xyz789"' },
  { name: 'scope', description: 'Scopes', example: '"openid profile email"' },
]

// Reserved claims the JWT service manages automatically.
const RESERVED_CLAIMS = new Set<string>([
  'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'nbf', 'azp', 'cnf', 'token_type',
])

// Standard OIDC claim names.
const OIDC_STANDARD_CLAIMS = new Set<string>([
  'iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'nbf', 'azp', 'cnf',
  'name', 'given_name', 'family_name', 'middle_name', 'nickname',
  'preferred_username', 'profile', 'picture', 'website', 'gender',
  'birthdate', 'zoneinfo', 'locale', 'updated_at',
  'email', 'email_verified', 'phone_number', 'phone_number_verified',
  'address', 'nonce', 'auth_time', 'acr', 'amr', 'sid', 'at_hash', 'c_hash',
  'client_id', 'scope', 'scp', 'token_type',
])

// Source options — plain language, 5 options (API key has an extra).
const SOURCE_OPTIONS: { id: ClaimSource; label: string; description: string; icon: LucideIcon }[] = [
  { id: 'user_field', label: 'From user profile', description: 'Pull from the user\'s profile', icon: User },
  { id: 'rbac_roles', label: 'From user roles', description: 'The user\'s assigned roles', icon: KeyRound },
  { id: 'rbac_permissions', label: 'From user permissions', description: 'Permissions from roles', icon: Lock },
  { id: 'static', label: 'Fixed value', description: 'Always the same value', icon: Database },
  { id: 'api_key_field', label: 'From API key', description: 'Read from this API key record', icon: Shield },
]

// Target options.
const TARGET_OPTIONS: { id: ClaimTarget; label: string; description: string }[] = [
  { id: 'access_token', label: 'Access Token', description: 'Main token for API calls' },
  { id: 'id_token', label: 'ID Token', description: 'Tells the app who the user is' },
  { id: 'userinfo', label: 'UserInfo', description: 'Profile data endpoint' },
]

// User profile fields actually managed by AuthGlow (editable via the
// admin API) — do not list model attributes without a write path.
const AVAILABLE_USER_FIELDS = [
  { value: 'email', label: 'email', desc: 'User email' },
  { value: 'first_name', label: 'first_name', desc: 'First name' },
  { value: 'last_name', label: 'last_name', desc: 'Last name' },
  { value: 'phone', label: 'phone', desc: 'Phone number' },
  { value: 'avatar_url', label: 'avatar_url', desc: 'Avatar image URL' },
]

// Available API key fields.
const AVAILABLE_API_KEY_FIELDS = [
  { value: 'name', label: 'name', desc: 'The display name set at creation' },
  { value: 'key_prefix', label: 'key_prefix', desc: 'The public prefix (e.g. ak_ABCDEFGHIJ)' },
  { value: 'scopes', label: 'scopes', desc: 'The OAuth scopes the key was granted' },
  { value: 'tier', label: 'tier', desc: 'Free-form tier label (production, staging, …)' },
  { value: 'allowed_ips', label: 'allowed_ips', desc: 'The IP allowlist bound to the key' },
]

// ---------------------------------------------------------------------------
// Inline help tooltip
// ---------------------------------------------------------------------------

function HelpTooltip({ text }: { text: string }) {
  return (
    <span className="group relative inline-flex">
      <HelpCircle
        size={12}
        className="cursor-help text-text-muted transition-colors hover:text-text-secondary"
      />
      <span className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-1.5 -translate-x-1/2 whitespace-normal rounded-lg border border-surface-2 bg-bg-primary p-2 text-[10px] text-text-secondary shadow-lg opacity-0 transition-opacity group-hover:opacity-100 w-52 text-left leading-relaxed">
        {text}
      </span>
    </span>
  )
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

type FieldNameStatus =
  | { kind: 'ok'; message: string }
  | { kind: 'standard'; message: string }
  | { kind: 'uri'; message: string }
  | { kind: 'reserved'; message: string }
  | { kind: 'invalid'; message: string }
  | { kind: 'empty'; message: string }

function validateFieldName(name: string): FieldNameStatus {
  if (!name) return { kind: 'empty', message: 'Give this field a name.' }
  if (RESERVED_CLAIMS.has(name)) {
    return { kind: 'reserved', message: `"${name}" is managed automatically — pick a different name.` }
  }
  if (OIDC_STANDARD_CLAIMS.has(name)) {
    return { kind: 'standard', message: 'Standard field — recognized by all OAuth apps.' }
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.\\-]*:[^\s]+$/.test(name)) {
    return { kind: 'uri', message: 'Valid custom field name (full URL format).' }
  }
  return {
    kind: 'invalid',
    message: `Custom names must be a full URL — try https://yourapp.com/claims/${name || 'field_name'}.`,
  }
}

function statusColor(status: FieldNameStatus): string {
  switch (status.kind) {
    case 'ok': case 'uri': case 'standard':
      return 'border-semantic-success/40 focus:border-semantic-success'
    case 'reserved': case 'invalid':
      return 'border-semantic-error/50 focus:border-semantic-error'
    case 'empty':
      return 'border-surface-2 focus:border-brand-accent'
  }
}

function sourceIcon(source: ClaimSource): LucideIcon {
  return SOURCE_OPTIONS.find(s => s.id === source)?.icon ?? Database
}

function sourceLabel(source: ClaimSource): string {
  return SOURCE_OPTIONS.find(s => s.id === source)?.label ?? source
}

// ---------------------------------------------------------------------------
// Empty rule factory
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Mock preview value
// ---------------------------------------------------------------------------

function mockValue(rule: ClaimRulePayload): string {
  if (rule.source === 'rbac_roles') return '["admin", "editor"]'
  if (rule.source === 'rbac_permissions') return '["users.read", "users.write"]'
  if (rule.source === 'user_field') return `<user.${rule.source_config.user_field ?? '?'}>`
  if (rule.source === 'api_key_field') return `<api_key.${rule.source_config.api_key_field ?? '?'}>`
  if (rule.source === 'static') return JSON.stringify(rule.source_config.value ?? null)
  return '<jwt_meta>'
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface ApiKeyClaimsTabProps {
  keyId: string
  keyName: string
  onClose: () => void
}

export function ApiKeyClaimsTab({ keyId, keyName, onClose }: ApiKeyClaimsTabProps) {
  // ----- Load policy + API key details -----
  const {
    data: policy,
    refetch: refetchPolicy,
    isLoading: policyLoading,
  } = useApiQuery<ClaimPolicyResponse>(
    ['claim-policy-api-key', keyId],
    `/api/admin/api-keys/${encodeURIComponent(keyId)}/claim-policy`,
  )

  const { data: keyData } = useApiQuery<ApiKeyData | null>(
    ['admin-api-key', keyId],
    `/api/admin/keys/${encodeURIComponent(keyId)}`,
    { enabled: !!keyId },
  )

  // ----- Editable draft -----
  const [draft, setDraft] = useState<ClaimRulePayload[]>([])
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (policy) {
      setDraft(policy.rules.map(r => ({ ...r, source_config: { ...r.source_config } })))
      setDirty(false)
    }
  }, [policy])

  // ----- Edit helpers -----
  const updateRule = (idx: number, patch: Partial<ClaimRulePayload>) => {
    setDraft(d => d.map((r, i) => (i === idx ? { ...r, ...patch } : r)))
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

  // ----- Add/Edit form state -----
  const [formMode, setFormMode] = useState<'closed' | 'add' | 'edit'>('closed')
  const [editIdx, setEditIdx] = useState<number | null>(null)
  const [formDraft, setFormDraft] = useState<ClaimRulePayload>(() => emptyRule())
  const formStatus = validateFieldName(formDraft.claim_name)

  const openAddForm = () => {
    setFormDraft(emptyRule())
    setEditIdx(null)
    setFormMode('add')
    setError(null)
  }
  const openEditForm = (idx: number) => {
    const r = draft[idx]
    setFormDraft({ ...r, source_config: { ...r.source_config } })
    setEditIdx(idx)
    setFormMode('edit')
    setError(null)
  }
  const closeForm = () => {
    setFormMode('closed')
    setEditIdx(null)
    setFormDraft(emptyRule())
    setError(null)
  }
  const submitForm = () => {
    if (formStatus.kind === 'invalid' || formStatus.kind === 'reserved' || formStatus.kind === 'empty') {
      setError('Fix the field name before saving.')
      return
    }
    if (formDraft.include_in.length === 0) {
      setError('Pick at least one token to send this data to.')
      return
    }
    if (formDraft.source === 'user_field' && !formDraft.source_config.user_field) {
      setError('Pick which user profile field to use.')
      return
    }
    if (formDraft.source === 'api_key_field' && !formDraft.source_config.api_key_field) {
      setError('Pick which API key attribute to use.')
      return
    }
    if (formDraft.source === 'static' && (formDraft.source_config.value === undefined || formDraft.source_config.value === null)) {
      setError('Enter the fixed value.')
      return
    }
    if (formMode === 'edit' && editIdx !== null) {
      updateRule(editIdx, formDraft)
    } else {
      addRule(formDraft)
    }
    closeForm()
  }

  // ----- Save / revert -----
  const handleSave = async () => {
    if (!dirty || saving) return
    setSaving(true)
    setError(null)
    try {
      await api.put(`/api/admin/api-keys/${encodeURIComponent(keyId)}/claim-policy`, { rules: draft })
      notify.success('Custom data saved.')
      setDirty(false)
      await refetchPolicy()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save')
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
  const handleDeleteAll = async () => {
    if (!confirm('Remove all custom rules? The token will go back to including only standard fields.')) return
    setSaving(true)
    setError(null)
    try {
      await api.delete(`/api/admin/api-keys/${encodeURIComponent(keyId)}/claim-policy`)
      notify.success('Removed custom rules.')
      setDirty(false)
      await refetchPolicy()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed')
    } finally {
      setSaving(false)
    }
  }

  // ----- Template gallery -----
  const applyTemplate = (t: ClaimTemplate) => {
    // The server already resolved the namespaced claim_name, so the
    // template maps straight onto a rule — no form round-trip needed.
    addRule({
      claim_name: t.claim_name,
      source: t.source as ClaimSource,
      source_config: { ...t.source_config } as ClaimSourceConfig,
      include_in: [...t.include_in] as ClaimTarget[],
      required_scope: t.required_scope ?? null,
      description: null,
    })
    notify.success(`Added "${t.label}" from the template gallery.`)
  }

  // ----- beforeunload + dirty close -----
  useEffect(() => {
    if (!dirty) return
    const h = (e: BeforeUnloadEvent) => { e.preventDefault() }
    window.addEventListener('beforeunload', h)
    return () => window.removeEventListener('beforeunload', h)
  }, [dirty])

  const [showDirtyConfirm, setShowDirtyConfirm] = useState(false)
  const pendingCloseRef = useRef<(() => void) | null>(null)
  const requestClose = () => {
    if (dirty) {
      pendingCloseRef.current = onClose
      setShowDirtyConfirm(true)
    } else {
      onClose()
    }
  }

  const isCustom = policy?.is_custom ?? false
  const ruleCount = draft.length

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-8" data-testid="api-key-claim-policy-modal">
      <div className="absolute inset-0 bg-black/50" onClick={requestClose} />
      <div className="relative z-10 flex w-full max-w-3xl flex-col rounded-2xl border border-surface-2 bg-bg-primary shadow-glow-accent max-h-[calc(100vh-4rem)]">

        {/* ----- Header ----- */}
        <div className="flex flex-shrink-0 items-center justify-between border-b border-surface-2 px-6 py-4">
          <div>
            <h2 className="text-lg font-semibold text-text-primary">Custom Token Data</h2>
            <p className="mt-0.5 text-xs text-text-muted">
              {keyName} · <code className="text-text-secondary">{keyId}</code>
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1 rounded-lg bg-brand-cool/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-brand-cool">
              API Key
            </span>
            {isCustom && (
              <span className="inline-flex items-center gap-1 rounded-lg bg-semantic-info/10 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-semantic-info" data-testid="api-key-claim-policy-custom-badge">
                Custom
              </span>
            )}
            {!isCustom && (
              <span className="inline-flex items-center gap-1 rounded-lg bg-surface-2 px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-text-muted" data-testid="api-key-claim-policy-default-badge">
                Default
              </span>
            )}
            <button onClick={requestClose} className="rounded-lg p-1.5 text-text-muted hover:bg-surface-2 hover:text-text-secondary" aria-label="Close">
              <X size={16} />
            </button>
          </div>
        </div>

        {/* ----- API key context strip ----- */}
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
            </div>
          </div>
        )}

        {/* ----- Merge semantics banner ----- */}
        <div className="flex-shrink-0 border-b border-surface-2 bg-brand-cool/5 px-6 py-3" data-testid="api-key-merge-banner">
          <div className="flex items-start gap-2 text-[11px] text-brand-cool">
            <Sparkles size={14} className="mt-0.5 shrink-0" />
            <p>
              API key policies are <strong>merged</strong> with default rules. The system
              always emits roles + permissions alongside your custom claims. To override
              a default, add a custom rule with the same name — last one wins.
            </p>
          </div>
        </div>

        {/* ----- Scrollable body ----- */}
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
            <div className="rounded-2xl border border-surface-2 bg-nested-panel p-5">

              {/* ----- Token title ----- */}
              <div className="mb-4 flex items-center gap-2">
                <span className="text-lg">🎫</span>
                <h3 className="text-sm font-semibold text-text-primary">Your Token</h3>
              </div>

              {/* ----- Default rules (read-only, always applied) ----- */}
              {(policy?.default_rules ?? []).length > 0 && (
                <div className="mb-5" data-testid="api-key-default-rules-box">
                  <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-text-muted">
                    Default rules (always included)
                  </p>
                  <div className="space-y-1.5">
                    {(policy?.default_rules ?? []).map((r, idx) => (
                      <div
                        key={`default-rule-${idx}`}
                        className="flex items-center gap-2 rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5"
                        data-testid="api-key-default-rule"
                      >
                        <Lock size={10} className="shrink-0 text-text-muted" />
                        <code className="flex-1 font-mono text-[11px] text-text-primary">
                          {r.claim_name}
                        </code>
                        <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[9px] font-mono text-text-secondary">
                          {r.source}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ----- Standard fields section ----- */}
              <div className="mb-5">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-text-muted">
                  Standard fields (always included)
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {STANDARD_FIELDS.map(f => (
                    <div
                      key={f.name}
                      className="group flex flex-col rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5"
                      title={f.description}
                    >
                      <span className="font-mono text-[11px] font-semibold text-text-primary">{f.name}</span>
                      <span className="text-[9px] text-text-muted">{f.example}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* ----- Custom fields section ----- */}
              <div className="mb-4">
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">
                      Your custom fields
                    </p>
                    <span className="text-[10px] font-semibold text-text-muted" data-testid="api-key-claim-policy-counter">
                      {ruleCount} custom rule{ruleCount !== 1 ? 's' : ''}{' · '}
                      {(policy?.default_rules ?? []).length} default always applied
                    </span>
                  </div>
                  {isCustom && ruleCount > 0 && (
                    <button
                      onClick={handleDeleteAll}
                      disabled={saving}
                      data-testid="api-key-claim-policy-reset-btn"
                      className="flex items-center gap-1 text-[10px] text-text-muted hover:text-semantic-error transition-colors"
                    >
                      <Trash2 size={10} /> Remove all
                    </button>
                  )}
                </div>

                {ruleCount === 0 && formMode === 'closed' ? (
                  <div className="rounded-xl border border-dashed border-surface-2 bg-bg-primary p-6 text-center" data-testid="api-key-claim-policy-empty-state">
                    <div className="mx-auto mb-2 inline-flex rounded-xl bg-surface-2 p-2">
                      <Sparkles className="h-4 w-4 text-text-muted" />
                    </div>
                    <p className="text-xs font-semibold text-text-primary">No custom fields yet</p>
                    <p className="mt-0.5 text-[10px] text-text-muted">
                      The token only has the standard fields above. Add custom data like API key tier or scopes.
                    </p>
                    <button
                      onClick={openAddForm}
                      data-testid="api-key-claim-policy-add-btn"
                      className="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-gradient-cta px-3 py-1.5 text-[11px] font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02]"
                    >
                      <Plus size={12} /> Add first field
                    </button>
                  </div>
                ) : (
                  <div className="space-y-2" data-testid="api-key-claim-rules-list">
                    {draft.map((rule, idx) => {
                      const Icon = sourceIcon(rule.source)
                      return (
                        <div
                          key={`rule-${idx}`}
                          className="group rounded-xl border border-surface-2 bg-bg-primary p-3 transition-colors hover:border-surface-3"
                          data-testid="api-key-claim-rule-card"
                        >
                          <div className="flex items-start gap-3">
                            {/* Icon */}
                            <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-brand-wash text-brand-accent">
                              <Icon size={14} />
                            </div>
                            {/* Content */}
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <code className="font-mono text-[12px] font-semibold text-text-primary" data-testid="api-key-rule-claim-name">
                                  {rule.claim_name}
                                </code>
                                <span className="text-[9px] text-text-muted">
                                  {sourceLabel(rule.source)}
                                </span>
                              </div>
                              <p className="mt-0.5 font-mono text-[10px] text-text-secondary truncate">
                                {mockValue(rule)}
                              </p>
                              <div className="mt-1 flex flex-wrap gap-1">
                                {rule.include_in.map(t => (
                                  <span key={t} className="rounded bg-surface-2 px-1.5 py-0.5 text-[9px] font-semibold text-text-secondary">
                                    {TARGET_OPTIONS.find(o => o.id === t)?.label ?? t}
                                  </span>
                                ))}
                                {rule.required_scope && (
                                  <span className="rounded bg-semantic-warning/10 px-1.5 py-0.5 text-[9px] font-semibold text-semantic-warning">
                                    scope: {rule.required_scope}
                                  </span>
                                )}
                              </div>
                            </div>
                            {/* Actions */}
                            <div className="flex shrink-0 gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                              <button
                                onClick={() => openEditForm(idx)}
                                className="rounded-lg p-1.5 text-text-muted hover:bg-surface-2 hover:text-text-secondary"
                                aria-label="Edit field"
                                title="Edit"
                              >
                                <Pencil size={12} />
                              </button>
                              <button
                                onClick={() => removeRule(idx)}
                                data-testid="api-key-rule-remove-btn"
                                className="rounded-lg p-1.5 text-text-muted hover:bg-surface-2 hover:text-semantic-error"
                                aria-label="Remove field"
                                title="Remove"
                              >
                                <Trash2 size={12} />
                              </button>
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>

              {/* ----- Add field button (when rules exist) ----- */}
              {ruleCount > 0 && formMode === 'closed' && (
                <button
                  onClick={openAddForm}
                  data-testid="api-key-claim-policy-add-btn"
                  className="flex w-full items-center justify-center gap-1.5 rounded-xl border border-dashed border-surface-2 py-2 text-[11px] font-semibold text-text-muted transition-all hover:border-brand-accent/30 hover:text-brand-accent hover:bg-brand-wash-faint"
                >
                  <Plus size={12} /> Add custom field
                </button>
              )}

              {/* ----- Template gallery (manual build alternative) ----- */}
              {formMode === 'closed' && (
                <div className="mt-2">
                  <ClaimTemplatePicker
                    onSelect={applyTemplate}
                    testPrefix="api-key-claim-template"
                  />
                </div>
              )}

              {/* ----- Add/Edit form ----- */}
              {formMode !== 'closed' && (
                <div className="mt-3 rounded-xl border border-brand-accent/30 bg-bg-primary p-4 space-y-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-brand-accent">
                    {formMode === 'edit' ? 'Edit field' : 'Add custom field'}
                  </p>

                  {/* Field name */}
                  <div>
                    <div className="mb-1 flex items-center gap-1.5">
                      <label className="text-[10px] font-semibold text-text-muted">What do you want to add?</label>
                      <HelpTooltip text="This is the name that will appear in the token. Use a standard name like 'email' or a full URL for custom fields." />
                    </div>
                    <input
                      value={formDraft.claim_name}
                      onChange={e => setFormDraft(r => ({ ...r, claim_name: e.target.value }))}
                      placeholder="e.g. tenant_id, api_key_tier, or https://yourapp.com/claims/field_name"
                      data-testid="api-key-claim-name-input"
                      className={cn(
                        'w-full rounded-lg border bg-surface-1 px-2.5 py-1.5 font-mono text-[11px] text-text-primary placeholder:text-text-muted focus:outline-none',
                        statusColor(formStatus),
                      )}
                    />
                    <p className={cn(
                      'mt-1 flex items-center gap-1 text-[10px]',
                      formStatus.kind === 'invalid' || formStatus.kind === 'reserved' ? 'text-semantic-error'
                        : formStatus.kind === 'standard' || formStatus.kind === 'uri' ? 'text-semantic-success'
                        : 'text-text-muted',
                    )} data-testid="api-key-claim-name-status">
                      {formStatus.kind === 'uri' || formStatus.kind === 'standard' || formStatus.kind === 'ok' ? (
                        <CheckCircle2 size={10} />
                      ) : formStatus.kind === 'reserved' || formStatus.kind === 'invalid' ? (
                        <AlertCircle size={10} />
                      ) : null}
                      {formStatus.message}
                    </p>
                  </div>

                  {/* Source */}
                  <div>
                    <div className="mb-1.5 flex items-center gap-1.5">
                      <label className="text-[10px] font-semibold text-text-muted">Where does the data come from?</label>
                      <HelpTooltip text="Choose where the system should look to find this data. 'From API key' reads from this key's record (name, tier, scopes)." />
                    </div>
                    <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3 lg:grid-cols-5">
                      {SOURCE_OPTIONS.map(s => {
                        const active = formDraft.source === s.id
                        const Icon = s.icon
                        return (
                          <button
                            key={s.id}
                            type="button"
                            onClick={() => setFormDraft(r => ({ ...r, source: s.id, source_config: {} }))}
                            data-testid={`api-key-source-${s.id}`}
                            className={cn(
                              'flex flex-col items-start gap-1 rounded-lg border p-2 text-left transition-all',
                              active
                                ? 'border-brand-accent bg-brand-wash text-brand-accent'
                                : 'border-surface-2 bg-surface-1 text-text-muted hover:border-surface-3',
                            )}
                          >
                            <Icon size={12} />
                            <span className="text-[10px] font-semibold leading-tight">{s.label}</span>
                          </button>
                        )
                      })}
                    </div>
                  </div>

                  {/* Source config — conditional */}
                  {formDraft.source === 'user_field' && (
                    <div>
                      <label className="mb-1 block text-[10px] font-semibold text-text-muted">Which profile field?</label>
                      <select
                        value={formDraft.source_config.user_field ?? ''}
                        onChange={e => setFormDraft(r => ({ ...r, source_config: { ...r.source_config, user_field: e.target.value || null } }))}
                        data-testid="api-key-source-config-user-field"
                        className="w-full rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] text-text-primary focus:border-brand-accent focus:outline-none"
                      >
                        <option value="">— Select a field —</option>
                        {AVAILABLE_USER_FIELDS.map(f => (
                          <option key={f.value} value={f.value}>{f.label} — {f.desc}</option>
                        ))}
                      </select>
                    </div>
                  )}
                  {formDraft.source === 'api_key_field' && (
                    <div>
                      <label className="mb-1 block text-[10px] font-semibold text-text-muted">Which API key attribute?</label>
                      <select
                        value={formDraft.source_config.api_key_field ?? ''}
                        onChange={e => setFormDraft(r => ({ ...r, source_config: { ...r.source_config, api_key_field: e.target.value || null } }))}
                        data-testid="api-key-source-config-api-key-field"
                        className="w-full rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] text-text-primary focus:border-brand-accent focus:outline-none"
                      >
                        <option value="">— Select an attribute —</option>
                        {AVAILABLE_API_KEY_FIELDS.map(f => (
                          <option key={f.value} value={f.value}>{f.label} — {f.desc}</option>
                        ))}
                      </select>
                    </div>
                  )}
                  {formDraft.source === 'static' && (
                    <div>
                      <label className="mb-1 block text-[10px] font-semibold text-text-muted">What value?</label>
                      <input
                        value={formDraft.source_config.value === undefined || formDraft.source_config.value === null ? '' : String(formDraft.source_config.value)}
                        onChange={e => setFormDraft(r => ({ ...r, source_config: { ...r.source_config, value: e.target.value } }))}
                        placeholder='e.g. "production" or 42'
                        data-testid="api-key-source-config-static-value"
                        className="w-full rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
                      />
                    </div>
                  )}

                  {/* Send to */}
                  <div>
                    <div className="mb-1.5 flex items-center gap-1.5">
                      <label className="text-[10px] font-semibold text-text-muted">Send to</label>
                      <HelpTooltip text="Which tokens should include this data? Access Token is for API calls, ID Token is for the app, UserInfo is for profile requests." />
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {TARGET_OPTIONS.map(t => {
                        const active = formDraft.include_in.includes(t.id)
                        return (
                          <button
                            key={t.id}
                            type="button"
                            onClick={() => {
                              setFormDraft(r => ({
                                ...r,
                                include_in: r.include_in.includes(t.id)
                                  ? r.include_in.filter(x => x !== t.id)
                                  : [...r.include_in, t.id],
                              }))
                            }}
                            data-testid={`api-key-target-${t.id}`}
                            title={t.description}
                            className={cn(
                              'flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-[10px] font-semibold transition-all',
                              active
                                ? 'border-brand-accent bg-brand-wash text-brand-accent'
                                : 'border-surface-2 bg-surface-1 text-text-muted hover:border-surface-3',
                            )}
                          >
                            {active && <Check size={10} />}
                            {t.label}
                          </button>
                        )
                      })}
                    </div>
                  </div>

                  {/* Scope */}
                  <div>
                    <div className="mb-1 flex items-center gap-1.5">
                      <label className="text-[10px] font-semibold text-text-muted">Only if scope is approved</label>
                      <HelpTooltip text="Leave empty to always include this data. Type a scope name to only include it when the API key has that scope." />
                    </div>
                    <input
                      value={formDraft.required_scope ?? ''}
                      onChange={e => setFormDraft(r => ({ ...r, required_scope: e.target.value || null }))}
                      placeholder="e.g. read, write (optional)"
                      className="w-full rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
                    />
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-end gap-2 border-t border-surface-2 pt-3">
                    <button
                      onClick={closeForm}
                      className="rounded-lg border border-surface-2 px-3 py-1.5 text-[11px] text-text-secondary hover:bg-surface-1"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={submitForm}
                      disabled={formStatus.kind === 'invalid' || formStatus.kind === 'reserved' || formStatus.kind === 'empty'}
                      data-testid="api-key-claim-policy-add-confirm-btn"
                      className="flex items-center gap-1.5 rounded-lg bg-gradient-cta px-3 py-1.5 text-[11px] font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
                    >
                      {formMode === 'edit' ? <><Check size={11} /> Save changes</> : <><Plus size={11} /> Add field</>}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* ----- Footer ----- */}
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
            <button onClick={requestClose} className="rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2">
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
              className="flex items-center gap-1.5 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
            >
              {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
              Save changes
            </button>
          </div>
        </div>
      </div>

      <ConfirmDialog
        open={showDirtyConfirm}
        title="Unsaved changes"
        message="You have unsaved custom data. Discard them?"
        confirmLabel="Discard"
        cancelLabel="Keep editing"
        variant="danger"
        onConfirm={() => { setShowDirtyConfirm(false); pendingCloseRef.current?.(); pendingCloseRef.current = null }}
        onCancel={() => { setShowDirtyConfirm(false); pendingCloseRef.current = null }}
      />
    </div>
  )
}
