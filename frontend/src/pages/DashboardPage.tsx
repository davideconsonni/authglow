import { useNavigate } from 'react-router-dom'
import { Shield, Monitor, Key, Users, CheckCircle2, Mail, Plus } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'
import { useApiQuery } from '../hooks/useApi'
import { ROUTES } from '../lib/constants'
import { useDocumentTitle } from '../hooks/useDocumentTitle'
import { Section } from '../components/shared/Section'
import { StatusBadge } from '../components/shared/StatusBadge'
import { formatDate, formatRelativeTime, cn } from '../lib/utils'

interface ProfileMe {
  id: string
  email: string
  email_verified: boolean
  first_name?: string
  last_name?: string
  avatar_url?: string
  mfa_enabled: boolean
  created_at: string
  last_login?: string
  roles: string[]
  scopes: string[]
}

interface SessionsResponse {
  sessions: unknown[]
  total: number
}

interface AdminStats {
  total_users: number
}

export function DashboardPage() {
  useDocumentTitle('Dashboard')
  const { user } = useAuth()
  const navigate = useNavigate()
  const isAdmin = user?.scopes?.includes('admin')

  const { data: profile } = useApiQuery<ProfileMe>(['profile-me'], '/api/profile/me')
  const { data: sessionsData } = useApiQuery<SessionsResponse>(['my-dash-sessions'], '/api/tokens/refresh/list')
  const { data: keysData } = useApiQuery<unknown[]>(['my-dash-keys'], '/api/keys')
  const { data: stats } = useApiQuery<AdminStats>(['dash-stats-v2'], '/api/admin/stats', { enabled: isAdmin })

  const sessionCount = sessionsData?.total ?? 0
  const keyCount = keysData?.length ?? 0

  const isFederated = user?.is_federated ?? false
  const emailVerified = user?.email_verified ?? profile?.email_verified ?? false
  const mfaEnabled = user?.mfa_enabled ?? profile?.mfa_enabled ?? false
  const missingChecks = isFederated ? 0 : ((!emailVerified ? 1 : 0) + (!mfaEnabled ? 1 : 0))
  const allSecure = isFederated || missingChecks === 0

  const isInitialLoading = !profile && !sessionsData && !keysData

  if (isInitialLoading) {
    return (
      <div className="space-y-8 animate-pulse">
        <div>
          <div className="h-7 w-48 rounded-lg bg-surface-2" />
          <div className="mt-2 h-4 w-64 rounded-lg bg-surface-2" />
        </div>
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
          <div className="flex items-start gap-5">
            <div className="h-14 w-14 shrink-0 rounded-2xl bg-surface-2" />
            <div className="flex-1 space-y-3">
              <div className="h-5 w-40 rounded-lg bg-surface-2" />
              <div className="h-4 w-56 rounded-lg bg-surface-2" />
              <div className="flex gap-2">
                <div className="h-5 w-20 rounded-lg bg-surface-2" />
                <div className="h-5 w-24 rounded-lg bg-surface-2" />
              </div>
            </div>
          </div>
        </div>
        <div className="flex gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="flex-1 rounded-2xl border border-surface-2 bg-surface-1 p-4">
              <div className="flex items-center gap-3">
                <div className="h-9 w-9 rounded-xl bg-surface-2" />
                <div className="space-y-1.5">
                  <div className="h-3 w-16 rounded bg-surface-2" />
                  <div className="h-5 w-8 rounded bg-surface-2" />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">
          Welcome back, {user?.first_name || profile?.first_name || 'User'}
        </h1>
        <p className="mt-1 text-sm text-text-muted">
          Here's a snapshot of your account.
        </p>
      </div>

      <Section title="Identity">
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
          <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex items-start gap-4">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-brand-violet/15 text-lg font-bold text-brand-violet">
                {(user?.first_name || profile?.first_name || '?').charAt(0).toUpperCase()}
                {(user?.last_name || profile?.last_name || '').charAt(0).toUpperCase()}
              </div>
              <div className="min-w-0">
                <p className="text-xl font-bold text-text-primary">
                  {user?.first_name || profile?.first_name || 'User'}{' '}
                  {user?.last_name || profile?.last_name || ''}
                </p>
                <p className="mt-0.5 break-all text-sm text-text-muted">
                  {user?.email || profile?.email || '-'}
                </p>
                <div className="mt-2 flex flex-wrap gap-2">
                  {isFederated ? (
                    <StatusBadge
                      status={null}
                      trueLabel=""
                      falseLabel="Provider managed"
                      falseClass="bg-surface-2 text-text-muted"
                    />
                  ) : (
                    <>
                      <StatusBadge
                        status={emailVerified}
                        trueLabel="Email verified"
                        falseLabel="Email unverified"
                        trueClass="bg-semantic-success/10 text-semantic-success"
                        falseClass="bg-semantic-warning/10 text-semantic-warning"
                      />
                      <StatusBadge
                        status={mfaEnabled}
                        trueLabel="MFA enabled"
                        falseLabel="MFA not enabled"
                        trueClass="bg-semantic-success/10 text-semantic-success"
                        falseClass="bg-semantic-warning/10 text-semantic-warning"
                      />
                    </>
                  )}
                </div>
              </div>
            </div>
            <div className="shrink-0 text-left sm:text-right">
              <p className="text-xs text-text-muted">Member since</p>
              <p className="text-sm font-medium text-text-primary">
                {formatDate(profile?.created_at)}
              </p>
              <p className="mt-2 text-xs text-text-muted">Last sign-in</p>
              <p className="text-sm font-medium text-text-primary">
                {formatRelativeTime(profile?.last_login)}
              </p>
            </div>
          </div>
        </div>
      </Section>

      {allSecure ? (
        <Section title="Security">
          <div className="flex items-center gap-3 rounded-2xl border border-semantic-success/20 bg-semantic-success/5 px-5 py-4">
            <CheckCircle2 size={20} className="shrink-0 text-semantic-success" />
            <p className="text-sm font-medium text-text-primary">
              {isFederated
                ? 'Email and MFA are managed by your identity provider.'
                : 'All security recommendations completed.'}
            </p>
          </div>
        </Section>
      ) : (
        <Section title="Security checklist" description="Complete these steps to secure your account.">
          <div className="space-y-3 max-w-xl">
            {!emailVerified && (
              <button
                onClick={() => navigate(ROUTES.PROFILE)}
                className="flex items-center gap-3 rounded-2xl border border-surface-2 bg-surface-1 px-5 py-4 text-left transition-all hover:border-semantic-warning/30"
              >
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-semantic-warning/10 text-semantic-warning">
                  <Mail size={18} />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-text-primary">Verify your email</p>
                  <p className="text-xs text-text-muted">Confirm your email address to enable account recovery.</p>
                </div>
              </button>
            )}
            {!mfaEnabled && (
              <button
                onClick={() => navigate(ROUTES.SECURITY)}
                className="flex items-center gap-3 rounded-2xl border border-surface-2 bg-surface-1 px-5 py-4 text-left transition-all hover:border-semantic-warning/30"
              >
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-semantic-warning/10 text-semantic-warning">
                  <Shield size={18} />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-text-primary">Enable two-factor authentication</p>
                  <p className="text-xs text-text-muted">Add an extra layer of security to your account.</p>
                </div>
              </button>
            )}
          </div>
        </Section>
      )}

      {!isFederated && (
        <Section title="Quick Actions" description="Common tasks for your account.">
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => navigate(ROUTES.SECURITY)}
              className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm font-medium text-text-primary hover:border-brand-violet/30 transition-all"
            >
              <Key size={16} className="text-brand-violet" />
              Change Password
            </button>
            <button
              onClick={() => navigate(ROUTES.SECURITY)}
              className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm font-medium text-text-primary hover:border-brand-violet/30 transition-all"
            >
              <Shield size={16} className="text-brand-violet" />
              Setup MFA
            </button>
            <button
              onClick={() => navigate(ROUTES.API_KEYS)}
              className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm font-medium text-text-primary hover:border-brand-violet/30 transition-all"
            >
              <Plus size={16} className="text-brand-violet" />
              Create API Key
            </button>
          </div>
        </Section>
      )}

      <Section title="At a glance" description="Live counts based on your account activity.">
        <div className="flex flex-wrap gap-4">
          <StatCard
            icon={Monitor} label="Active sessions"
            value={String(sessionCount)} color="brand-violet"
            onClick={() => navigate(ROUTES.SESSIONS)}
            detail={sessionCount === 1 ? '1 device' : `${sessionCount} devices`}
          />
          <StatCard
            icon={Key} label="API keys"
            value={String(keyCount)} color="brand-magenta"
            onClick={() => navigate(ROUTES.API_KEYS)}
            detail={keyCount === 1 ? '1 key' : `${keyCount} keys active`}
          />
          {isAdmin && (
            <StatCard
              icon={Users} label="Total users"
              value={String(stats?.total_users ?? 0)} color="brand-blue"
              onClick={() => navigate(ROUTES.ADMIN.USERS)}
              detail="total users"
            />
          )}
        </div>
      </Section>

      {isAdmin && (
        <Section title="Administration">
          <button
            onClick={() => navigate(ROUTES.ADMIN.DASHBOARD)}
            className="flex w-full items-center justify-between rounded-2xl border border-surface-2 bg-surface-1 px-6 py-4 text-left transition-all hover:border-brand-violet/30 hover:shadow-glow-violet"
          >
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-violet/10 text-brand-violet">
                <Users size={20} />
              </div>
              <div>
                <p className="text-sm font-semibold text-text-primary">Open admin overview</p>
                <p className="text-xs text-text-muted">Manage users, sessions, OAuth clients and more.</p>
              </div>
            </div>
            <span className="text-xs font-medium text-brand-violet">&rarr;</span>
          </button>
        </Section>
      )}
    </div>
  )
}

function StatCard({ icon: Icon, label, value, color, onClick, hint, detail }: {
  icon: typeof Shield; label: string; value: string; color: string; onClick?: () => void; hint?: string; detail?: string
}) {
  const colors: Record<string, string> = {
    'brand-violet': 'text-brand-violet bg-brand-violet/10',
    'brand-blue': 'text-brand-blue bg-brand-blue/10',
    'brand-magenta': 'text-brand-magenta bg-brand-magenta/10',
  }
  return (
    <div
      className="rounded-2xl border border-surface-2 bg-surface-1 p-4 transition-all duration-300 hover:shadow-glow-violet cursor-pointer min-w-[200px] flex-1"
      onClick={onClick}
    >
      <div className="flex items-center gap-3">
        <div className={cn('flex h-9 w-9 items-center justify-center rounded-xl', colors[color] || colors['brand-violet'])}>
          <Icon size={18} />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-xs text-text-muted">{label}</p>
          <p className="text-base font-bold text-text-primary">{value}</p>
          {detail && <p className="text-xs text-text-muted">{detail}</p>}
          {!detail && hint && <p className="text-xs text-text-muted">{hint}</p>}
        </div>
      </div>
    </div>
  )
}
