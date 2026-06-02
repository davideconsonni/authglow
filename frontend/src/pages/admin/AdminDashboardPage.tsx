import { useNavigate } from 'react-router-dom'
import { Users, Activity, Shield, Loader2 } from 'lucide-react'
import { useApiQuery } from '@/hooks/useApi'
import { ROUTES } from '@/lib/constants'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

interface AdminStats {
  total_users: number
  active_users: number
  inactive_users: number
  users_with_mfa: number
  mfa_percentage: number
  new_users_today: number
  new_users_this_week: number
  new_users_this_month: number
  total_logins_today: number
  failed_logins_today: number
}

interface TimeseriesPoint {
  date: string
  count: number
}

export function AdminDashboardPage() {
  const navigate = useNavigate()
  const { data, isLoading } = useApiQuery<AdminStats>(['admin-stats-v2'], '/api/admin/stats')
  const { data: timeseries, isLoading: tsLoading } = useApiQuery<TimeseriesPoint[]>(['admin-timeseries'], '/api/admin/stats/timeseries')

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

        <button onClick={() => navigate(ROUTES.ADMIN.SESSIONS)} className="rounded-2xl border border-surface-2 bg-surface-1 p-6 text-left transition-all hover:shadow-glow-violet hover:border-brand-violet/30">
          <Activity size={24} className="text-brand-blue mb-3" />
          <p className="text-2xl font-bold text-text-primary">{data?.total_logins_today ?? 0}</p>
          <p className="text-sm text-text-muted">Logins Today</p>
          <p className="mt-2 text-xs text-brand-blue">View sessions &rarr;</p>
        </button>

        <button onClick={() => navigate(ROUTES.ADMIN.RBAC)} className="rounded-2xl border border-surface-2 bg-surface-1 p-6 text-left transition-all hover:shadow-glow-violet hover:border-brand-violet/30">
          <Shield size={24} className="text-brand-magenta mb-3" />
          <p className="text-2xl font-bold text-text-primary">{data?.mfa_percentage ?? 0}%</p>
          <p className="text-sm text-text-muted">MFA Adoption</p>
          <p className="mt-2 text-xs text-brand-magenta">Manage RBAC &rarr;</p>
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatBadge label="Active" value={data?.active_users ?? 0} color="text-semantic-success" />
        <StatBadge label="Inactive" value={data?.inactive_users ?? 0} color="text-text-muted" />
        <StatBadge label="New today" value={data?.new_users_today ?? 0} color="text-brand-violet" />
        <StatBadge label="Failed logins" value={data?.failed_logins_today ?? 0} color="text-semantic-error" />
      </div>

      {/* Timeseries Chart */}
      {tsLoading ? (
        <div className="py-4 text-center"><Loader2 className="mx-auto h-5 w-5 animate-spin text-brand-violet" /></div>
      ) : timeseries && timeseries.length > 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
          <h3 className="text-sm font-semibold text-text-primary mb-4">New Users (Last 30 Days)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={timeseries}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(32,45,86,0.5)" />
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: '#94A3B8' }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#121A32', border: '1px solid #202D56', borderRadius: '12px', color: '#FFFFFF', fontSize: '12px' }}
                labelStyle={{ color: '#CBD5E1' }}
              />
              <Line type="monotone" dataKey="count" stroke="#8B5CF6" strokeWidth={2} dot={false} activeDot={{ r: 4, fill: '#8B5CF6' }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      ) : null}
    </div>
  )
}

function StatBadge({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="rounded-xl bg-surface-1 border border-surface-2 px-4 py-3">
      <p className={`text-lg font-bold ${color}`}>{value}</p>
      <p className="text-xs text-text-muted">{label}</p>
    </div>
  )
}
