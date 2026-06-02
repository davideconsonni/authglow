import { Shield, Monitor, Key, Mail, Users, Activity, Settings, ArrowRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/hooks/useAuth'
import { useApiQuery } from '@/hooks/useApi'
import { ROUTES } from '@/lib/constants'
import { Section } from '@/components/shared/Section'

interface AdminStats {
  total_users: number
  active_users: number
  users_with_mfa: number
  new_users_today: number
  total_logins_today: number
  failed_logins_today: number
}

export function DashboardPage() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const isAdmin = user?.scopes?.includes('admin')

  const { data: stats } = useApiQuery<AdminStats>(['dash-stats-v2'], '/api/admin/stats', { enabled: isAdmin })

  return (
    <div className="space-y-10">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">
          Welcome back, {user?.first_name || 'User'}
        </h1>
        <p className="mt-1 text-sm text-text-muted">
          Here's what's happening with your account.
        </p>
      </div>

      {/* Account Overview */}
      <Section title="Your Account" description="Quick overview and shortcuts to manage your identity.">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <DashCard
            icon={Mail} label="Email" value={user?.email || '-'}
            color="brand-blue" onClick={() => navigate(ROUTES.PROFILE)}
          />
          <DashCard
            icon={Shield} label="MFA Status"
            value={user?.mfa_enabled ? 'Enabled' : 'Not enabled'}
            color={user?.mfa_enabled ? 'semantic-success' : 'brand-violet'}
            onClick={() => navigate(ROUTES.SECURITY)}
            action="Set up MFA"
          />
          <DashCard
            icon={Monitor} label="Sessions"
            value="Manage" color="brand-violet"
            onClick={() => navigate(ROUTES.SESSIONS)} action="View all"
          />
          <DashCard
            icon={Key} label="API Keys"
            value="Manage" color="brand-magenta"
            onClick={() => navigate(ROUTES.API_KEYS)} action="View all"
          />
        </div>
      </Section>

      {/* System Overview (admin only) */}
      {isAdmin && stats && (
        <Section title="System Overview" description="Platform metrics at a glance.">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <DashCard icon={Users} label="Total Users" value={String(stats.total_users)} color="brand-violet" onClick={() => navigate(ROUTES.ADMIN.USERS)} action="Manage users" />
            <DashCard icon={Activity} label="Logins Today" value={String(stats.total_logins_today)} color="brand-blue" onClick={() => navigate(ROUTES.ADMIN.SESSIONS)} action="View sessions" />
            <DashCard icon={Settings} label="Administration" value="Open panel" color="brand-violet" onClick={() => navigate(ROUTES.ADMIN.DASHBOARD)} action="Admin panel" />
          </div>
        </Section>
      )}

      {/* Quick Actions */}
      <Section title="Quick Actions" description="Common tasks you might want to do.">
        <div className="flex flex-wrap gap-3">
          <QuickAction label="Security settings" onClick={() => navigate(ROUTES.SECURITY)} />
          <QuickAction label="Create API Key" onClick={() => navigate(ROUTES.API_KEYS)} />
          <QuickAction label="View Sessions" onClick={() => navigate(ROUTES.SESSIONS)} />
          <QuickAction label="Edit Profile" onClick={() => navigate(ROUTES.PROFILE)} />
          {isAdmin && <QuickAction label="Manage Users" onClick={() => navigate(ROUTES.ADMIN.USERS)} />}
        </div>
      </Section>
    </div>
  )
}

function DashCard({ icon: Icon, label, value, color, onClick, action }: {
  icon: typeof Shield; label: string; value: string; color: string; onClick?: () => void; action?: string
}) {
  const colors: Record<string, string> = {
    'brand-violet': 'text-brand-violet bg-brand-violet/10',
    'brand-blue': 'text-brand-blue bg-brand-blue/10',
    'brand-magenta': 'text-brand-magenta bg-brand-magenta/10',
    'semantic-success': 'text-semantic-success bg-semantic-success/10',
  }
  return (
    <div className="rounded-2xl border border-surface-2 bg-surface-1 p-5 transition-all duration-300 hover:shadow-glow-violet group cursor-pointer" onClick={onClick}>
      <div className="flex items-center gap-4">
        <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${colors[color] || colors['brand-violet']}`}>
          <Icon size={20} />
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-xs text-text-muted">{label}</p>
          <p className="text-lg font-bold text-text-primary">{value}</p>
        </div>
        {action && (
          <ArrowRight size={16} className="text-text-muted opacity-0 group-hover:opacity-100 transition-opacity" />
        )}
      </div>
      {action && (
        <p className="mt-3 text-xs font-medium text-brand-violet">{action} &rarr;</p>
      )}
    </div>
  )
}

function QuickAction({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button onClick={onClick} className="rounded-xl border border-surface-2 bg-surface-1 px-5 py-2.5 text-sm font-medium text-text-secondary hover:border-brand-violet/30 hover:text-brand-violet transition-all duration-150">
      {label} &rarr;
    </button>
  )
}
