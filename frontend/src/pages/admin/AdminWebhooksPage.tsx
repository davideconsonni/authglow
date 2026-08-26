import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  Webhook as WebhookIcon,
  Plus,
  Loader2,
  Trash2,
  RotateCcw,
  ScrollText,
  X,
  Check,
  Pencil,
} from 'lucide-react'
import { api } from '../../lib/api'
import { useApiQuery } from '../../hooks/useApi'
import { ConfirmDialog } from '../../components/shared/ConfirmDialog'
import { PageHeader } from '../../components/layout/PageHeader'
import { CopyButton } from '../../components/shared/CopyButton'
import { formatDateTime } from '../../lib/utils'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { notify } from '../../stores/toastStore'

// Mirror of the backend Event Catalog (authglow/models/webhook_events.py).
const WEBHOOK_EVENT_TYPES = [
  'user.created',
  'user.updated',
  'user.deleted',
  'login.success',
  'login.failed',
  'password.changed',
  'mfa.enrolled',
  'session.revoked',
  'webhook.test',
] as const

// Mirror of the backend URL policy (authglow/api/webhooks.py:
// _validate_registration_url). Returns an error message or null.
function validateWebhookUrl(url: string, insecure: boolean): string | null {
  let parsed: URL
  try {
    parsed = new URL(url.trim())
  } catch {
    return "Invalid URL (e.g. 'http://' with no hostname)."
  }
  if (!parsed.hostname) return 'URL is missing a hostname.'
  if (parsed.protocol === 'https:') return null
  if (parsed.protocol === 'http:') {
    return insecure
      ? null
      : 'HTTP requires the "Allow insecure HTTP" flag for this endpoint.'
  }
  return `Unsupported scheme: ${parsed.protocol.replace(':', '')}.`
}

interface WebhookEndpointRow {
  id: string
  url: string
  events: string[]
  active: boolean
  insecure: boolean
  masked_secret: string
  created_at: string
  updated_at: string
}

interface Delivery {
  id: string
  event_type: string
  attempt: number
  ok: boolean
  status_code: number | null
  error: string | null
  duration_ms: number
  delivered_at: string
}

export function AdminWebhooksPage() {
  useDocumentTitle('Webhooks')
  const queryClient = useQueryClient()

  const { data: webhooks, isLoading } = useApiQuery<WebhookEndpointRow[]>(
    ['admin-webhooks'],
    '/api/admin/webhooks',
  )

  const [showCreate, setShowCreate] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [createUrl, setCreateUrl] = useState('https://')
  const [createEvents, setCreateEvents] = useState<string[]>([])
  const [createInsecure, setCreateInsecure] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [urlTouched, setUrlTouched] = useState(false)
  const [creating, setCreating] = useState(false)

  const [secretReveal, setSecretReveal] = useState<string | null>(null)
  const [rotateId, setRotateId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [testingId, setTestingId] = useState<string | null>(null)
  const [logOpenId, setLogOpenId] = useState<string | null>(null)

  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ['admin-webhooks'] }),
      queryClient.invalidateQueries({ queryKey: ['webhook-deliveries'] }),
    ])

  // Live validation drives the Save button; the inline alert appears only
  // once the field has been touched (or a save was attempted) so the form
  // doesn't open shouting about its own default placeholder value.
  const urlError = validateWebhookUrl(createUrl, createInsecure)

  const resetFormState = () => {
    setCreateInsecure(false)
    setFormError(null)
    setUrlTouched(false)
  }

  // ----- Create -----
  const toggleEvent = (t: string) =>
    setCreateEvents((prev) =>
      prev.includes(t) ? prev.filter((e) => e !== t) : [...prev, t],
    )

  const openCreateForm = () => {
    setEditingId(null)
    setCreateUrl('https://')
    setCreateEvents([])
    resetFormState()
    setShowCreate(true)
  }

  const openEditForm = (wh: WebhookEndpointRow) => {
    setEditingId(wh.id)
    setCreateUrl(wh.url)
    setCreateEvents([...wh.events])
    setCreateInsecure(wh.insecure)
    setFormError(null)
    setUrlTouched(false)
    setShowCreate(true)
  }

  const closeForm = () => {
    setShowCreate(false)
    setEditingId(null)
    resetFormState()
  }

  const handleCreate = async () => {
    if (creating) return
    const validationError = validateWebhookUrl(createUrl, createInsecure)
    if (validationError || createEvents.length === 0) {
      setFormError(validationError ?? 'Seleziona almeno un evento.')
      return
    }
    setCreating(true)
    try {
      let res: WebhookEndpointRow & { secret?: string }
      if (editingId) {
        // PATCH: url + events + insecure; il flag `active` si gestisce dal toggle di riga.
        res = await api.patch<WebhookEndpointRow>(
          `/api/admin/webhooks/${editingId}`,
          { url: createUrl.trim(), events: createEvents, insecure: createInsecure },
        ) as WebhookEndpointRow & { secret?: string }
      } else {
        res = await api.post<WebhookEndpointRow & { secret: string }>(
          '/api/admin/webhooks',
          { url: createUrl.trim(), events: createEvents, insecure: createInsecure },
        )
      }
      if (!editingId && res.secret) {
        setSecretReveal(res.secret)
      } else {
        notify.success(editingId ? 'Webhook updated.' : 'Webhook created.')
      }
      closeForm()
      await refresh()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to save webhook')
    } finally {
      setCreating(false)
    }
  }

  // ----- Row actions -----
  const handleToggleActive = async (wh: WebhookEndpointRow) => {
    try {
      await api.patch(`/api/admin/webhooks/${wh.id}`, { active: !wh.active })
      notify.success(wh.active ? 'Webhook disabled.' : 'Webhook enabled.')
      await refresh()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed')
    }
  }

  const handleRotate = async () => {
    if (!rotateId) return
    try {
      const res = await api.post<{ secret: string }>(
        `/api/admin/webhooks/${rotateId}/rotate-secret`,
      )
      setRotateId(null)
      setSecretReveal(res.secret)
      await refresh()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to rotate secret')
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.delete(`/api/admin/webhooks/${deleteId}`)
      setDeleteId(null)
      if (logOpenId === deleteId) setLogOpenId(null)
      notify.success('Webhook deleted.')
      await refresh()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to delete webhook')
    }
  }

  const handleTest = async (id: string) => {
    setTestingId(id)
    try {
      const res = await api.post<{ delivered: boolean; attempts: { status_code: number | null; error: string | null }[] }>(
        `/api/admin/webhooks/${id}/test`,
      )
      if (res.delivered) {
        notify.success('Test event delivered.')
      } else {
        const last = res.attempts[res.attempts.length - 1]
        notify.error(`Not delivered — ${last?.error ?? last?.status_code ?? 'unknown error'}`)
      }
      setLogOpenId(id)
      await refresh()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Test failed')
    } finally {
      setTestingId(null)
    }
  }

  return (
    <div>
      <PageHeader
        title="Webhooks"
        description="Receive signed IdP events on your own endpoints."
        actions={
          <button
            onClick={openCreateForm}
            data-testid="webhooks-create-btn"
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02]"
          >
            <Plus size={16} /> New webhook
          </button>
        }
      />

      {/* ----- Create form ----- */}
      {showCreate && (
        <div className="mb-6 rounded-2xl border border-surface-2 bg-surface-1 p-5 space-y-4" data-testid="webhooks-create-form">
          <div className="space-y-2">
            <label htmlFor="wh-url" className="block text-xs font-medium text-text-secondary">
              Endpoint URL <span className="text-text-muted">(HTTPS; HTTP only with the insecure flag)</span>
            </label>
            <input
              id="wh-url"
              type="url"
              value={createUrl}
              onChange={(e) => {
                setCreateUrl(e.target.value)
                setUrlTouched(true)
                setFormError(null)
              }}
              placeholder="https://mio-sito.it/hooks/authglow"
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-3 py-2 text-sm font-mono text-text-primary focus:border-brand-violet focus:outline-none"
            />
            {formError && (
              <p role="alert" data-testid="webhooks-form-error" className="text-xs text-semantic-error">
                {formError}
              </p>
            )}
            {!formError && urlError && urlTouched && (
              <p role="alert" data-testid="webhooks-form-error" className="text-xs text-semantic-error">
                {urlError}
              </p>
            )}
            <label className="flex cursor-pointer items-center gap-2 pt-1 text-xs text-text-secondary">
              <input
                type="checkbox"
                checked={createInsecure}
                onChange={(e) => {
                  setCreateInsecure(e.target.checked)
                  setFormError(null)
                }}
                data-testid="webhooks-insecure-toggle"
                className="accent-brand-violet"
              />
              Allow insecure HTTP <span className="text-text-muted">(extreme cases only: internal receivers without TLS)</span>
            </label>
            {createInsecure && (
              <p className="text-[11px] text-semantic-warning">
                Warning: events will be delivered in plaintext and the SSRF guard will be disabled for this endpoint.
              </p>
            )}
          </div>
          <div className="space-y-2">
            <p className="text-xs font-medium text-text-secondary">Events</p>
            <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
              {WEBHOOK_EVENT_TYPES.map((t) => (
                <label key={t} className="flex cursor-pointer items-center gap-2 rounded-lg border border-surface-2 bg-surface-1 px-2.5 py-1.5 text-[11px] text-text-secondary hover:border-brand-violet/40">
                  <input
                    type="checkbox"
                    checked={createEvents.includes(t)}
                    onChange={() => toggleEvent(t)}
                    className="accent-brand-violet"
                  />
                  <code>{t}</code>
                </label>
              ))}
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleCreate}
              disabled={creating || !!urlError || createEvents.length === 0}
              data-testid="webhooks-create-confirm"
              className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet disabled:opacity-50"
            >
              {creating && <Loader2 size={14} className="animate-spin" />}
              {editingId ? 'Save changes' : 'Create webhook'}
            </button>
            <button onClick={closeForm} className="rounded-xl px-3 py-2 text-xs text-text-muted hover:text-text-secondary">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* ----- List ----- */}
      {isLoading ? (
        <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div>
      ) : !webhooks || webhooks.length === 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-12 text-center">
          <WebhookIcon className="mx-auto h-8 w-8 text-text-muted" />
          <h3 className="mt-3 text-sm font-semibold text-text-primary">No webhooks yet</h3>
          <p className="mt-1 text-xs text-text-muted">Register an endpoint to start receiving signed events.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {webhooks.map((wh) => (
            <div key={wh.id} className="rounded-2xl border border-surface-2 bg-surface-1">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-4">
                <span
                  className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${
                    wh.active
                      ? 'bg-semantic-success/10 text-semantic-success'
                      : 'bg-surface-2 text-text-muted'
                  }`}
                >
                  {wh.active ? 'active' : 'disabled'}
                </span>
                {wh.insecure && (
                  <span
                    data-testid={`webhook-insecure-${wh.id}`}
                    title="Insecure HTTP endpoint: plaintext deliveries, SSRF guard disabled"
                    className="inline-flex rounded-lg bg-semantic-warning/10 px-2 py-0.5 text-xs font-medium text-semantic-warning"
                  >
                    HTTP
                  </span>
                )}
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-xs text-text-primary">{wh.url}</p>
                  <p className="mt-0.5 flex flex-wrap gap-1">
                    {wh.events.map((e) => (
                      <span key={e} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[9px] text-text-secondary">{e}</span>
                    ))}
                  </p>
                  <p className="mt-1 font-mono text-[10px] text-text-muted">
                    {wh.id} · secret {wh.masked_secret} · creato {formatDateTime(wh.created_at)}
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <button
                    onClick={() => handleTest(wh.id)}
                    disabled={testingId === wh.id}
                    title="Send test event"
                    data-testid={`webhook-test-${wh.id}`}
                    className="rounded-lg p-1.5 text-text-muted hover:bg-brand-violet/10 hover:text-brand-violet disabled:opacity-50"
                  >
                    {testingId === wh.id ? <Loader2 size={14} className="animate-spin" /> : <WebhookIcon size={14} />}
                  </button>
                  <button
                    onClick={() => openEditForm(wh)}
                    title="Edit URL & events"
                    aria-label={`Edit webhook ${wh.id}`}
                    data-testid={`webhook-edit-${wh.id}`}
                    className="rounded-lg p-1.5 text-text-muted hover:text-brand-violet transition-colors"
                  >
                    <Pencil size={14} />
                  </button>
                  <button
                    onClick={() => setLogOpenId(logOpenId === wh.id ? null : wh.id)}
                    title="Delivery log"
                    aria-label="Delivery log"
                    className={`rounded-lg p-1.5 transition-colors ${
                      logOpenId === wh.id ? 'text-brand-violet' : 'text-text-muted hover:text-text-secondary'
                    }`}
                  >
                    <ScrollText size={14} />
                  </button>
                  <button
                    onClick={() => setRotateId(wh.id)}
                    title="Rotate signing secret"
                    className="rounded-lg p-1.5 text-text-muted hover:text-brand-blue transition-colors"
                  >
                    <RotateCcw size={14} />
                  </button>
                  <button
                    onClick={() => handleToggleActive(wh)}
                    title={wh.active ? 'Disable' : 'Enable'}
                    className="rounded-lg px-2 py-1 text-[11px] font-semibold text-text-secondary hover:text-text-primary"
                  >
                    {wh.active ? 'Disable' : 'Enable'}
                  </button>
                  <button
                    onClick={() => setDeleteId(wh.id)}
                    title="Delete webhook"
                    className="rounded-lg p-1.5 text-text-muted hover:text-semantic-error transition-colors"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>

              {/* ----- Deliveries panel ----- */}
              {logOpenId === wh.id && (
                <DeliveriesPanel webhookId={wh.id} />
              )}
            </div>
          ))}
        </div>
      )}

      {/* ----- Secret reveal-once modal ----- */}
      {secretReveal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" data-testid="secret-reveal-modal">
          <div className="absolute inset-0 bg-black/50" onClick={() => setSecretReveal(null)} />
          <div className="relative z-10 w-full max-w-lg rounded-2xl border border-surface-2 bg-bg-primary p-6 shadow-glow-violet">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-text-primary">Signing Secret</h3>
              <button onClick={() => setSecretReveal(null)} aria-label="Close" className="rounded-lg p-1 text-text-muted hover:text-text-secondary">
                <X size={16} />
              </button>
            </div>
            <p className="mt-2 text-xs text-semantic-warning">
              Copy it now: it is shown <strong>only once</strong>. Losing it means rotating the secret.
            </p>
            <div className="mt-3 flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-2/50 p-3">
              <code className="min-w-0 flex-1 break-all font-mono text-xs text-text-primary" data-testid="secret-reveal-value">{secretReveal}</code>
              <CopyButton text={secretReveal} label="Copy" />
            </div>
            <button
              onClick={() => setSecretReveal(null)}
              className="mt-4 w-full rounded-xl bg-gradient-cta py-2 text-sm font-semibold text-white"
            >
              I've copied the secret
            </button>
          </div>
        </div>
      )}

      <ConfirmDialog
        open={!!rotateId}
        title="Rotate Signing Secret"
        message="The old secret stops working IMMEDIATELY: update your endpoint's verification at the same time."
        confirmLabel="Rotate now"
        variant="danger"
        onConfirm={handleRotate}
        onCancel={() => setRotateId(null)}
      />

      <ConfirmDialog
        open={!!deleteId}
        title="Delete Webhook"
        message="The endpoint will stop receiving events and its delivery log will be removed."
        confirmLabel="Delete"
        variant="danger"
        onConfirm={handleDelete}
        onCancel={() => setDeleteId(null)}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Deliveries log panel (fetches on mount, newest first)
// ---------------------------------------------------------------------------

function DeliveriesPanel({ webhookId }: { webhookId: string }) {
  const { data: deliveries, isLoading } = useApiQuery<Delivery[]>(
    ['webhook-deliveries', webhookId],
    `/api/admin/webhooks/${webhookId}/deliveries`,
  )

  if (isLoading) {
    return <div className="border-t border-surface-2 px-5 py-3"><Loader2 size={14} className="animate-spin text-text-muted" /></div>
  }
  if (!deliveries || deliveries.length === 0) {
    return (
      <div className="border-t border-surface-2 px-5 py-3" data-testid="deliveries-panel-empty">
        <p className="text-xs text-text-muted">No deliveries recorded yet.</p>
      </div>
    )
  }
  return (
    <div className="border-t border-surface-2 px-5 py-3" data-testid="deliveries-panel">
      <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-text-muted">
        Recent deliveries (newest → oldest, max 20)
      </p>
      <div className="space-y-1">
        {deliveries.map((d) => (
          <div key={d.id} className="flex items-center gap-2 rounded-lg bg-surface-2/40 px-2.5 py-1.5 text-[11px]">
            {d.ok ? (
              <Check size={12} className="shrink-0 text-semantic-success" />
            ) : (
              <X size={12} className="shrink-0 text-semantic-error" />
            )}
            <code className="font-mono text-text-secondary">{d.event_type}</code>
            <span className="text-text-muted">· attempt {d.attempt}</span>
            {d.status_code !== null && <span className="text-text-muted">· HTTP {d.status_code}</span>}
            {d.error && <span className="truncate text-semantic-error">{d.error}</span>}
            <span className="ml-auto shrink-0 text-text-muted">{formatDateTime(d.delivered_at)}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
