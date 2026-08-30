import { useNavigate } from 'react-router-dom'
import { Users, Shield, Loader2, Monitor, Key, TrendingUp, Activity } from 'lucide-react'
import { useApiQuery } from '../../hooks/useApi'
import { ROUTES } from '../../lib/constants'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { formatRelativeTime } from '../../lib/utils'

interface AdminStats {
  total_users: number
  active_users: number
  inactive_users: number
  users_with_mfa: number
  mfa_percentage: number
  new_users_today: number
  new_users_this_week: number
  new_users_this_month: number
}

interface RecentUser {
  id: string
  email: string
  first_name?: string
  last_name?: string
  created_at: string
}

export function AdminDashboardPage() {
  useDocumentTitle('Admin Dashboard')
  const navigate = useNavigate()
  const { data, isLoading } = useApiQuery<AdminStats>(['admin-stats-v2'], '/api/admin/stats')
  const { data: recentUsers } = useApiQuery<{ items?: RecentUser[] } | RecentUser[]>(['admin-recent-users'], '/api/admin/users?limit=5&sort=created_at:desc')

  const usersList = Array.isArray(recentUsers) ? recentUsers : (recentUsers as { items?: RecentUser[] } | undefined)?.items ?? []

  if (isLoading) return <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-accent" /></div>

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Administration</h1>
        <p className="mt-1 text-sm text-text-muted">System overview and user management.</p>
      </div>

      {/* Hero stat cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <button onClick={() => navigate(ROUTES.ADMIN.USERS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-6 text-left transition-all hover:shadow-glow-accent hover:border-brand-accent/30 group">
          <div className="flex items-center justify-between mb-3">
            <Users size={24} className="text-brand-accent" />
            <span className="flex items-center gap-1 text-xs font-medium text-semantic-success">
              <TrendingUp size={12} />
              +{data?.new_users_today ?? 0} today
            </span>
          </div>
          <p className="text-3xl font-bold text-text-primary">{data?.total_users ?? 0}</p>
          <p className="text-sm text-text-muted mt-1">Total Users</p>
          <p className="mt-3 text-xs font-medium text-brand-accent opacity-0 group-hover:opacity-100 transition-opacity">Manage users &rarr;</p>
        </button>

        <button onClick={() => navigate(ROUTES.ADMIN.USERS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-6 text-left transition-all hover:shadow-glow-accent hover:border-brand-alt/30 group">
          <div className="flex items-center justify-between mb-3">
            <Shield size={24} className="text-brand-alt" />
            <span className="text-xs font-medium text-text-muted">of total users</span>
          </div>
          <p className="text-3xl font-bold text-text-primary">{data?.mfa_percentage ?? 0}%</p>
          <p className="text-sm text-text-muted mt-1">MFA Adoption</p>
          <p className="mt-3 text-xs font-medium text-brand-alt opacity-0 group-hover:opacity-100 transition-opacity">View users &rarr;</p>
        </button>

        <button onClick={() => navigate(ROUTES.ADMIN.SESSIONS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-6 text-left transition-all hover:shadow-glow-accent hover:border-brand-cool/30 group">
          <div className="flex items-center justify-between mb-3">
            <Activity size={24} className="text-brand-cool" />
            <span className="text-xs font-medium text-text-muted">this month</span>
          </div>
          <p className="text-3xl font-bold text-text-primary">{data?.new_users_this_month ?? 0}</p>
          <p className="text-sm text-text-muted mt-1">New Users (30d)</p>
          <p className="mt-3 text-xs font-medium text-brand-cool opacity-0 group-hover:opacity-100 transition-opacity">View sessions &rarr;</p>
        </button>
      </div>

      {/* Quick stats row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatBadge label="Active" value={data?.active_users ?? 0} color="text-semantic-success" trend={data?.new_users_today ? `+${data.new_users_today}` : undefined} />
        <StatBadge label="Inactive" value={data?.inactive_users ?? 0} color="text-text-muted" />
        <StatBadge label="New this week" value={data?.new_users_this_week ?? 0} color="brand-accent" />
        <StatBadge label="MFA enabled" value={data?.users_with_mfa ?? 0} color="brand-alt" />
      </div>

      {/* Quick links + Recent Activity */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Quick links */}
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wider">Quick Access</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <button onClick={() => navigate(ROUTES.ADMIN.USERS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-5 text-left transition-all hover:border-brand-accent/30">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-wash text-brand-accent"><Users size={18} /></div>
                <div><p className="text-sm font-semibold text-text-primary">Users</p><p className="text-xs text-text-muted">Manage accounts</p></div>
              </div>
            </button>
            <button onClick={() => navigate(ROUTES.ADMIN.OAUTH_CLIENTS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-5 text-left transition-all hover:border-brand-alt/30">
              <div className="flex items-center gap-3">
                <div className="icon-chip flex h-9 w-9 items-center justify-center rounded-xl"><Key size={18} /></div>
                <div><p className="text-sm font-semibold text-text-primary">OAuth Apps</p><p className="text-xs text-text-muted">Registered clients</p></div>
              </div>
            </button>
            <button onClick={() => navigate(ROUTES.ADMIN.SESSIONS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-5 text-left transition-all hover:border-brand-cool/30">
              <div className="flex items-center gap-3">
                <div className="icon-chip flex h-9 w-9 items-center justify-center rounded-xl"><Monitor size={18} /></div>
                <div><p className="text-sm font-semibold text-text-primary">Sessions</p><p className="text-xs text-text-muted">Active tokens</p></div>
              </div>
            </button>
            <button onClick={() => navigate(ROUTES.ADMIN.RBAC)} className="rounded-2xl border border-surface-2 bg-surface-1 p-5 text-left transition-all hover:border-semantic-info/30">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-semantic-info/10 text-semantic-info"><Shield size={18} /></div>
                <div><p className="text-sm font-semibold text-text-primary">RBAC</p><p className="text-xs text-text-muted">Roles &amp; permissions</p></div>
              </div>
            </button>
          </div>
        </div>

        {/* Recent users */}
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wider">Recent Users</h2>
          <div className="rounded-2xl border border-surface-2 bg-surface-1">
            {usersList.length === 0 ? (
              <div className="p-6 text-center text-sm text-text-muted">No recent users</div>
            ) : (
              <div className="divide-y divide-surface-2">
                {usersList.slice(0, 5).map((u) => (
                  <div key={u.id} className="flex items-center gap-3 px-5 py-3">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-brand-wash text-xs font-bold text-brand-accent">
                      {(u.first_name || u.email || '?')[0].toUpperCase()}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-text-primary truncate">
                        {u.first_name && u.last_name ? `${u.first_name} ${u.last_name}` : u.email}
                      </p>
                      <p className="text-xs text-text-muted">{u.email}</p>
                    </div>
                    <span className="shrink-0 text-[11px] text-text-muted">
                      {formatRelativeTime(u.created_at)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function StatBadge({ label, value, color, trend }: { label: string; value: number; color: string; trend?: string }) {
  return (
    <div className="rounded-xl bg-surface-1 border border-surface-2 px-3 py-2.5">
      <div className="flex items-center justify-between">
        <p className={`text-base font-bold ${color.startsWith('text-') ? color : `text-${color}`}`}>{value}</p>
        {trend && (
          <span className="flex items-center gap-0.5 text-[10px] font-medium text-semantic-success">
            <TrendingUp size={10} />
            {trend}
          </span>
        )}
      </div>
      <p className="text-xs text-text-muted">{label}</p>
    </div>
  )
}
