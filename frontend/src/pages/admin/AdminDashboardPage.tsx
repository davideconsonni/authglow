import { useNavigate } from 'react-router-dom'
import { Users, Shield, Loader2, Monitor, Key } from 'lucide-react'
import { useApiQuery } from '../../hooks/useApi'
import { ROUTES } from '../../lib/constants'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'

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

export function AdminDashboardPage() {
  useDocumentTitle('Admin Dashboard')
  const navigate = useNavigate()
  const { data, isLoading } = useApiQuery<AdminStats>(['admin-stats-v2'], '/api/admin/stats')

  if (isLoading) return <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div>

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Administration</h1>
        <p className="mt-1 text-sm text-text-muted">System overview and user management.</p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <button onClick={() => navigate(ROUTES.ADMIN.USERS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-6 text-left transition-all hover:shadow-glow-violet hover:border-brand-violet/30">
          <Users size={24} className="text-brand-violet mb-3" />
          <p className="text-2xl font-bold text-text-primary">{data?.total_users ?? 0}</p>
          <p className="text-sm text-text-muted">Total Users</p>
          <p className="mt-2 text-xs text-brand-violet">Manage users &rarr;</p>
        </button>

        <button onClick={() => navigate(ROUTES.ADMIN.USERS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-6 text-left transition-all hover:shadow-glow-violet hover:border-brand-violet/30">
          <Shield size={24} className="text-brand-magenta mb-3" />
          <p className="text-2xl font-bold text-text-primary">{data?.mfa_percentage ?? 0}%</p>
          <p className="text-sm text-text-muted">MFA Adoption</p>
          <p className="mt-2 text-xs text-brand-magenta">View users &rarr;</p>
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatBadge label="Active" value={data?.active_users ?? 0} color="text-semantic-success" />
        <StatBadge label="Inactive" value={data?.inactive_users ?? 0} color="text-text-muted" />
        <StatBadge label="New today" value={data?.new_users_today ?? 0} color="text-brand-violet" />
        <StatBadge label="New this week" value={data?.new_users_this_week ?? 0} color="text-brand-blue" />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <button onClick={() => navigate(ROUTES.ADMIN.USERS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-5 text-left transition-all hover:border-brand-violet/30">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-violet/10 text-brand-violet"><Users size={18} /></div>
            <div><p className="text-sm font-semibold text-text-primary">Users</p><p className="text-xs text-text-muted">Manage user accounts</p></div>
          </div>
        </button>
        <button onClick={() => navigate(ROUTES.ADMIN.SESSIONS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-5 text-left transition-all hover:border-brand-violet/30">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue"><Monitor size={18} /></div>
            <div><p className="text-sm font-semibold text-text-primary">Sessions</p><p className="text-xs text-text-muted">Active token management</p></div>
          </div>
        </button>
        <button onClick={() => navigate(ROUTES.ADMIN.OAUTH_CLIENTS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-5 text-left transition-all hover:border-brand-violet/30">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-brand-magenta/10 text-brand-magenta"><Key size={18} /></div>
            <div><p className="text-sm font-semibold text-text-primary">OAuth Clients</p><p className="text-xs text-text-muted">Registered applications</p></div>
          </div>
        </button>
      </div>
    </div>
  )
}

function StatBadge({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-xl bg-surface-1 border border-surface-2 px-3 py-2.5">
      <p className={`text-base font-bold ${color}`}>{value}</p>
      <p className="text-xs text-text-muted">{label}</p>
    </div>
  )
}
