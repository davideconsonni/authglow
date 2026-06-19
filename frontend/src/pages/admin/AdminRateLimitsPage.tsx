import { Gauge, Route, Shield } from 'lucide-react'
import { useApiQuery } from '@/hooks/useApi'
import { PageHeader } from '@/components/layout/PageHeader'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

interface RateLimitEntry {
  route: string
  method: string
  limit: string
  source: string
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

const METHOD_COLORS: Record<string, string> = {
  GET: 'bg-semantic-success/10 text-semantic-success',
  POST: 'bg-brand-blue/10 text-brand-blue',
  PUT: 'bg-semantic-warning/10 text-semantic-warning',
  PATCH: 'bg-semantic-warning/10 text-semantic-warning',
  DELETE: 'bg-semantic-error/10 text-semantic-error',
}

export function AdminRateLimitsPage() {
  useDocumentTitle('Rate Limits')

  const { data, isLoading } = useApiQuery<RateLimitsData>(
    ['admin-rate-limits'],
    '/api/admin/rate-limits',
  )

  const { data: statusData } = useApiQuery<RateLimitsStatus>(
    ['admin-rate-limits-status'],
    '/api/admin/rate-limits/status',
  )

  const limits = data?.rate_limits ?? []
  const status = statusData

  return (
    <div>
      <PageHeader
        title="Rate Limits"
        description="Overview of rate-limited API routes."
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
              Status
            </div>
            <p className="mt-1 text-2xl font-bold text-text-primary">
              <span
                className={
                  status.enabled ? 'text-semantic-success' : 'text-semantic-error'
                }
              >
                {status.enabled ? 'Active' : 'Disabled'}
              </span>
            </p>
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
              limits.map((l, i) => (
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
                    <span className="inline-flex rounded-lg bg-brand-violet/10 px-2 py-0.5 text-xs font-medium text-brand-violet">
                      {l.limit}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-xs text-text-muted">{l.source}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
