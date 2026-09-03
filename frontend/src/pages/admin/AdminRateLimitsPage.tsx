import { useState } from 'react'
import { Gauge, Loader2, RotateCcw, Route, Shield } from 'lucide-react'
import { useApiMutation, useApiQuery } from '../../hooks/useApi'
import { PageHeader } from '../../components/layout/PageHeader'
import { RateLimitInput } from '../../components/admin/RateLimitInput'
import { normalizeRateLimit } from '../../lib/rateLimit'
import { ConfirmDialog } from '../../components/shared/ConfirmDialog'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { notify } from '../../stores/toastStore'
import { cn } from '../../lib/utils'

interface RateLimitEntry {
  route: string
  method: string
  limit: string
  source: string
  path: string | null
  override: string | null
}

interface RateLimitsData {
  total_routes: number
  rate_limits: RateLimitEntry[]
}

interface RateLimitsStatus {
  total_routes_limited: number
  default_limits_count: number
  exempt_routes_count: number
  storage_type: string
  enabled: boolean
}

interface RateLimitConfigUpdate {
  enabled?: boolean
  overrides?: Record<string, string | null>
}

const METHOD_COLORS: Record<string, string> = {
  GET: 'bg-semantic-success/10 text-semantic-success',
  POST: 'bg-brand-cool/10 text-brand-cool',
  PUT: 'bg-semantic-warning/10 text-semantic-warning',
  PATCH: 'bg-semantic-warning/10 text-semantic-warning',
  DELETE: 'bg-semantic-error/10 text-semantic-error',
}

export function AdminRateLimitsPage() {
  useDocumentTitle('Rate Limits')

  const [edited, setEdited] = useState<Record<string, string>>({})
  const [showResetAllConfirm, setShowResetAllConfirm] = useState(false)

  const { data, isLoading, refetch } = useApiQuery<RateLimitsData>(
    ['admin-rate-limits'],
    '/api/admin/rate-limits',
  )

  const { data: statusData, refetch: refetchStatus } = useApiQuery<RateLimitsStatus>(
    ['admin-rate-limits-status'],
    '/api/admin/rate-limits/status',
  )

  const configMutation = useApiMutation<
    { enabled: boolean },
    RateLimitConfigUpdate
  >('put', '/api/admin/rate-limits/config')

  const limits = data?.rate_limits ?? []
  const status = statusData

  const handleToggle = async () => {
    const next = !status?.enabled
    try {
      await configMutation.mutateAsync({ enabled: next })
      notify.success(next ? 'Rate limiting enabled.' : 'Rate limiting disabled.')
      await Promise.all([refetch(), refetchStatus()])
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to update rate limiting')
    }
  }

  const handleChangeRow = (route: string, original: string, value: string) => {
    // Treat "10 per 1 minute" and "10/minute" as the same value so
    // touching the controls without a real change clears the dirty mark.
    if (normalizeRateLimit(value) === normalizeRateLimit(original)) {
      setEdited((prev) => {
        const next = { ...prev }
        delete next[route]
        return next
      })
      return
    }
    setEdited((prev) => ({ ...prev, [route]: value }))
  }

  const handleSaveRow = async (path: string) => {
    const value = edited[path]?.trim()
    if (!value) return
    try {
      await configMutation.mutateAsync({ overrides: { [path]: value } })
      notify.success('Limit updated.')
      setEdited((prev) => {
        const next = { ...prev }
        delete next[path]
        return next
      })
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to update limit')
    }
  }

  const handleResetRow = async (path: string) => {
    try {
      await configMutation.mutateAsync({ overrides: { [path]: null } })
      notify.success('Limit reset to default.')
      setEdited((prev) => {
        const next = { ...prev }
        delete next[path]
        return next
      })
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to reset limit')
    }
  }

  const editingDisabled = configMutation.isPending
  const overridePaths = [
    ...new Set(
      limits
        .filter((l) => l.override !== null && l.path !== null)
        .map((l) => l.path as string),
    ),
  ]
  const hasOverrides = overridePaths.length > 0

  const handleResetAll = async () => {
    setShowResetAllConfirm(false)
    const overrides = Object.fromEntries(overridePaths.map((path) => [path, null]))
    try {
      await configMutation.mutateAsync({ overrides })
      notify.success('All limits reset to defaults.')
      setEdited({})
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to reset limits')
    }
  }

  return (
    <div>
      <PageHeader
        title="Rate Limits"
        description="Configure and review rate-limited API routes."
      />

      {/* Status cards */}
      {status && (
        <div className="mb-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="rounded-xl border border-surface-2 bg-surface-1 p-4">
            <div className="flex items-center gap-2 text-sm text-text-muted">
              <Route size={16} />
              Limited routes
            </div>
            <p className="mt-1 text-2xl font-bold text-text-primary">
              {status.total_routes_limited}
            </p>
          </div>
          <div className="rounded-xl border border-surface-2 bg-surface-1 p-4">
            <div className="flex items-center gap-2 text-sm text-text-muted">
              <Shield size={16} />
              Rate limiting
            </div>
            <div className="mt-2 flex items-center justify-between gap-3">
              <p
                className={cn(
                  'text-lg font-bold',
                  status.enabled ? 'text-semantic-success' : 'text-semantic-error',
                )}
              >
                {status.enabled ? 'Active' : 'Disabled'}
              </p>
              <button
                type="button"
                role="switch"
                aria-checked={status.enabled}
                aria-label="Toggle rate limiting globally"
                disabled={editingDisabled}
                onClick={handleToggle}
                className={cn(
                  'relative inline-flex h-6 w-10 items-center rounded-full transition-colors',
                  status.enabled ? 'bg-brand-accent' : 'bg-surface-3',
                  editingDisabled && 'cursor-not-allowed opacity-50',
                )}
              >
                <span
                  className={cn(
                    'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                    status.enabled ? 'translate-x-5' : 'translate-x-1',
                  )}
                />
              </button>
            </div>
          </div>
          <div className="rounded-xl border border-surface-2 bg-surface-1 p-4">
            <div className="flex items-center gap-2 text-sm text-text-muted">
              <Gauge size={16} />
              Storage
            </div>
            <p className="mt-1 text-lg font-bold text-text-primary">
              {status.storage_type}
            </p>
          </div>
        </div>
      )}

      {/* Reset all toolbar */}
      {hasOverrides && (
        <div className="mb-3 flex justify-end">
          <button
            type="button"
            data-testid="rate-limits-reset-all"
            disabled={editingDisabled}
            onClick={() => setShowResetAllConfirm(true)}
            className="flex items-center gap-2 rounded-xl border border-surface-2 px-3 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:bg-surface-2 hover:text-text-primary btn-cta"
          >
            {editingDisabled ? (
              <Loader2 size={13} className="animate-spin" />
            ) : (
              <RotateCcw size={13} />
            )}
            Reset all to defaults
          </button>
        </div>
      )}

      {/* Rate limits table */}
      <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
        <table className="w-full">
          <thead className="border-b border-surface-2">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">
                Method
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">
                Route
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">
                Limit
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">
                Source
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-2">
            {isLoading ? (
              <tr>
                <td colSpan={4} className="px-6 py-12 text-center text-sm text-text-muted">
                  Loading...
                </td>
              </tr>
            ) : limits.length === 0 ? (
              <tr>
                <td colSpan={4} className="px-6 py-12 text-center">
                  <Gauge className="mx-auto h-8 w-8 text-text-muted" />
                  <p className="mt-3 text-sm font-semibold text-text-primary">
                    No rate-limited routes
                  </p>
                  <p className="mt-1 text-xs text-text-muted">
                    Add @limiter.limit decorators to API endpoints.
                  </p>
                </td>
              </tr>
            ) : (
              limits.map((l, i) => {
                const isEditable = l.path !== null
                const effective = edited[l.route] ?? l.override ?? l.limit
                const isDirty = isEditable && edited[l.route] !== undefined

                return (
                  <tr key={`${l.method}-${l.route}-${i}`} className="hover:bg-surface-2/50">
                    <td className="px-6 py-3">
                      <span
                        className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-mono font-semibold ${
                          METHOD_COLORS[l.method] ?? 'bg-surface-2 text-text-muted'
                        }`}
                      >
                        {l.method}
                      </span>
                    </td>
                    <td className="px-6 py-3">
                      <code className="text-xs text-text-secondary">{l.route}</code>
                    </td>
                    <td className="px-6 py-3">
                      {isEditable ? (
                        <RateLimitInput
                          route={l.route}
                          value={effective}
                          override={l.override}
                          dirty={isDirty}
                          disabled={editingDisabled}
                          saving={editingDisabled}
                          onChange={(value) =>
                            handleChangeRow(l.route, l.override ?? l.limit, value)
                          }
                          onSave={() => l.path && handleSaveRow(l.route)}
                          onReset={() => l.path && handleResetRow(l.route)}
                        />
                      ) : (
                        <span className="inline-flex rounded-lg bg-brand-wash px-2 py-0.5 text-xs font-medium text-brand-accent">
                          {normalizeRateLimit(l.limit)}
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-3 text-xs text-text-muted">
                      <span
                        className={cn(
                          l.source === 'override' && 'font-semibold text-brand-accent',
                        )}
                      >
                        {l.source}
                      </span>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <ConfirmDialog
        open={showResetAllConfirm}
        title="Reset all rate limits"
        message={`This restores the decorator default for all ${overridePaths.length} overridden routes. Continue?`}
        confirmLabel="Reset all"
        variant="danger"
        onConfirm={handleResetAll}
        onCancel={() => setShowResetAllConfirm(false)}
      />
    </div>
  )
}
