import { useState, useEffect } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useNavigate } from 'react-router-dom'
import { Loader2, Save, Mail, Calendar, Shield, Key, Check, ArrowRight } from 'lucide-react'
import { api } from '@/lib/api'
import { useAuth } from '@/hooks/useAuth'
import { useApiQuery } from '@/hooks/useApi'
import { useTheme, type Theme } from '@/hooks/useTheme'
import { PageHeader } from '@/components/layout/PageHeader'
import { CopyButton } from '@/components/shared/CopyButton'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { Section } from '@/components/shared/Section'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { formatDateTime } from '@/lib/utils'
import { ROUTES } from '@/lib/constants'

function PreferencesSection() {
  const { data: prefs } = useApiQuery<{ theme?: string; language?: string }>(['user-prefs'], '/api/profile/me/preferences')
  const { theme, setTheme } = useTheme()
  const [saving, setSaving] = useState(false)
  const [language, setLanguage] = useState('en')
  const [prefSuccess, setPrefSuccess] = useState(false)

  useEffect(() => {
    if (prefs?.language) {
      setLanguage(prefs.language)
    }
  }, [prefs?.language])

  const handleThemeChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    await setTheme(e.target.value as Theme)
  }

  const savePrefs = async () => {
    setSaving(true)
    try {
      await api.patch('/api/profile/me/preferences', { language })
      setPrefSuccess(true)
      setTimeout(() => setPrefSuccess(false), 2000)
    } catch {} finally { setSaving(false) }
  }

  return (
    <Section title="Preferences" description="Customize your AuthGlow experience.">
      <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
        {prefSuccess && <div className="mb-4 rounded-xl bg-semantic-success/10 px-4 py-2 text-xs text-semantic-success">Preferences saved.</div>}
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1">Theme</label>
            <select
              value={theme}
              onChange={handleThemeChange}
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary focus:border-brand-violet focus:outline-none"
            >
              <option value="auto">Auto (system)</option>
              <option value="dark">Dark</option>
              <option value="light">Light</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-text-secondary mb-1">Language</label>
            <select
              value={language}
              onChange={e => setLanguage(e.target.value)}
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary focus:border-brand-violet focus:outline-none"
            >
              <option value="en">English</option>
              <option value="it">Italiano</option>
              <option value="fr">Français</option>
              <option value="de">Deutsch</option>
              <option value="es">Español</option>
            </select>
          </div>
        </div>
        <button
          onClick={savePrefs}
          disabled={saving}
          className="mt-4 rounded-xl bg-gradient-cta px-5 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50"
        >
          {saving ? 'Saving...' : 'Save language'}
        </button>
      </div>
    </Section>
  )
}

const profileSchema = z.object({
  first_name: z.string().min(1, 'Required'),
  last_name: z.string().min(1, 'Required'),
})

interface UserProfile {
  id: string
  email: string
  is_active: boolean
  created_at: string
  first_name: string
  last_name: string
  scopes: string[]
  mfa_enabled: boolean
  mfa_verified: boolean
  email_verified: boolean
}

export function ProfilePage() {
  const { user, fetchCurrentUser } = useAuth()
  const navigate = useNavigate()
  const [success, setSuccess] = useState(false)
  const [error, setError] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [deactivateDialog, setDeactivateDialog] = useState(false)
  const [deleteDialog, setDeleteDialog] = useState(false)
  const [reactivating, setReactivating] = useState(false)

  const { data: profile } = useApiQuery<UserProfile>(['profile-full-v2'], '/api/users/me')

  const { register, handleSubmit, formState: { isSubmitting } } = useForm<{
    first_name: string
    last_name: string
  }>({
    resolver: zodResolver(profileSchema),
    values: { first_name: user?.first_name || '', last_name: user?.last_name || '' },
  })

  const onSubmit = async (data: { first_name: string; last_name: string }) => {
    setError('')
    setSuccess(false)
    try {
      await api.patch('/api/profile/me', data)
      await fetchCurrentUser()
      setSuccess(true)
      setShowForm(false)
      setTimeout(() => setSuccess(false), 3000)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update')
    }
  }

  const p = profile || user

  const handleDeactivate = async () => {
    try {
      await api.post('/api/profile/me/deactivate')
      setDeactivateDialog(false)
      await fetchCurrentUser()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed')
    }
  }

  const handleReactivate = async () => {
    setReactivating(true)
    try {
      await api.post('/api/profile/me/reactivate')
      await fetchCurrentUser()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed')
    } finally { setReactivating(false) }
  }

  const handleDelete = async () => {
    try {
      await api.delete('/api/profile/me')
      setDeleteDialog(false)
      // Auth store will handle redirect on next API call
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed')
    }
  }

  return (
    <div className="space-y-10">
      <PageHeader title="Your Profile" description="Manage your personal information and account details." />

      {success && (
        <div className="flex items-center gap-2 rounded-xl bg-semantic-success/10 px-4 py-3 text-sm text-semantic-success">
          <Check size={16} /> Profile updated successfully
        </div>
      )}

      {/* SECTION: Identity */}
      <Section title="Identity" description="Your personal information and account status.">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Avatar & Name card */}
          <div className="lg:col-span-2 rounded-2xl border border-surface-2 bg-surface-1 p-8">
            <div className="flex items-start gap-5">
              <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-2xl bg-brand-violet/20 text-2xl font-bold text-brand-violet">
                {(p?.first_name || 'U')[0].toUpperCase()}
              </div>
              <div className="min-w-0">
                <h2 className="text-xl font-bold text-text-primary">{p?.first_name} {p?.last_name}</h2>
                <div className="mt-1 flex items-center gap-2">
                  <Mail size={14} className="text-text-muted" />
                  <span className="text-sm text-text-secondary">{p?.email}</span>
                </div>
                <div className="mt-1 flex items-center gap-1 text-xs text-text-muted">
                  <Calendar size={12} />
                  <span>Member since {p?.created_at ? formatDateTime(p.created_at) : '-'}</span>
                </div>
                <div className="mt-4 flex items-center gap-3">
                  <StatusBadge status={p?.is_active ?? true} trueLabel="Active" falseLabel="Inactive" />
                  {p?.email_verified !== undefined && (
                    <StatusBadge
                      status={p.email_verified}
                      trueLabel="Email verified"
                      falseLabel="Email not verified"
                      trueClass="bg-semantic-success/10 text-semantic-success"
                      falseClass="bg-semantic-warning/10 text-semantic-warning"
                    />
                  )}
                </div>
              </div>
              <button
                onClick={() => setShowForm(!showForm)}
                className="ml-auto shrink-0 rounded-xl border border-surface-2 px-4 py-2 text-sm font-medium text-text-secondary hover:bg-surface-2 transition-colors"
              >
                {showForm ? 'Cancel' : 'Edit'}
              </button>
            </div>

            {showForm && (
              <form onSubmit={handleSubmit(onSubmit)} className="mt-6 space-y-4 border-t border-surface-2 pt-6">
                {error && <div className="rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">{error}</div>}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-text-muted mb-1.5">First name</label>
                    <input {...register('first_name')} className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20" />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-text-muted mb-1.5">Last name</label>
                    <input {...register('last_name')} className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20" />
                  </div>
                </div>
                <button type="submit" disabled={isSubmitting} className="inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-5 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50">
                  {isSubmitting ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                  Save changes
                </button>
              </form>
            )}
          </div>

          {/* Security quick card */}
          <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
            <h3 className="text-sm font-semibold text-text-primary">Security Status</h3>

            <div className="space-y-3">
              <div className="flex items-center justify-between rounded-xl bg-surface-2 px-4 py-3">
                <div className="flex items-center gap-2">
                  <Shield size={16} className="text-text-muted" />
                  <span className="text-sm text-text-secondary">MFA</span>
                </div>
                <StatusBadge
                  status={!!p?.mfa_enabled}
                  trueLabel="Enabled"
                  falseLabel="Disabled"
                  trueClass="bg-semantic-success/10 text-semantic-success"
                  falseClass="bg-surface-3 text-text-muted"
                />
              </div>

              <div className="flex items-center justify-between rounded-xl bg-surface-2 px-4 py-3">
                <div className="flex items-center gap-2">
                  <Mail size={16} className="text-text-muted" />
                  <span className="text-sm text-text-secondary">Email</span>
                </div>
                <StatusBadge
                  status={!!p?.email_verified}
                  trueLabel="Verified"
                  falseLabel="Not verified"
                  trueClass="bg-semantic-success/10 text-semantic-success"
                  falseClass="bg-semantic-warning/10 text-semantic-warning"
                />
              </div>
            </div>

            <button
              onClick={() => navigate(ROUTES.SECURITY)}
              className="flex w-full items-center justify-center gap-1.5 rounded-xl bg-surface-2 py-2.5 text-xs font-medium text-brand-violet hover:bg-surface-3 transition-colors"
            >
              Manage security
              <ArrowRight size={12} />
            </button>
          </div>
        </div>
      </Section>

      {/* SECTION: Technical Details */}
      <Section title="Technical Details" description="Your account identifiers and permissions.">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
            <h3 className="text-sm font-semibold text-text-primary">User ID</h3>
            <div className="flex items-center gap-3 rounded-xl bg-surface-2 p-4">
              <Key size={16} className="text-text-muted shrink-0" />
              <code className="flex-1 break-all text-sm font-mono text-text-secondary">
                {p?.id || '-'}
              </code>
              {p?.id && <CopyButton text={p.id} label="Copy" />}
            </div>
            <p className="text-xs text-text-muted">This is your unique identifier. Use it when contacting support.</p>
          </div>

          <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
            <h3 className="text-sm font-semibold text-text-primary">Permissions</h3>
            {p?.scopes && p.scopes.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {p.scopes.map((scope) => (
                  <span
                    key={scope}
                    className={`rounded-lg px-3 py-1.5 text-sm font-medium ${
                      scope === 'admin'
                        ? 'bg-brand-violet/15 text-brand-violet ring-1 ring-brand-violet/30'
                        : 'bg-surface-2 text-text-secondary'
                    }`}
                  >
                    {scope}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-text-muted">No permissions assigned.</p>
            )}
            <p className="text-xs text-text-muted">
              Permissions determine what actions you can perform in the system.
            </p>
          </div>
        </div>
      </Section>

      {/* Preferences */}
      <PreferencesSection />

      {/* Danger Zone */}
      <Section title="Danger Zone" description="Irreversible account actions. Please be careful.">
        <div className="rounded-2xl border border-semantic-error/20 bg-surface-1 p-6 space-y-4">
          {p?.is_active ? (
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-text-primary">Deactivate Account</p>
                <p className="text-xs text-text-muted">Temporarily disable your account. You can reactivate it later.</p>
              </div>
              <button
                onClick={() => setDeactivateDialog(true)}
                className="rounded-xl border border-semantic-warning/30 px-4 py-2 text-xs font-medium text-semantic-warning hover:bg-semantic-warning/10 transition-colors"
              >
                Deactivate
              </button>
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-text-primary">Account Inactive</p>
                <p className="text-xs text-text-muted">Your account is currently deactivated.</p>
              </div>
              <button
                onClick={handleReactivate}
                disabled={reactivating}
                className="rounded-xl bg-gradient-cta px-4 py-2 text-xs font-semibold text-white shadow-glow-violet disabled:opacity-50"
              >
                {reactivating ? 'Reactivating...' : 'Reactivate'}
              </button>
            </div>
          )}

          <div className="border-t border-surface-2 pt-4 flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-semantic-error">Delete Account</p>
              <p className="text-xs text-text-muted">Permanently delete your account and all associated data. This cannot be undone.</p>
            </div>
            <button
              onClick={() => setDeleteDialog(true)}
              className="rounded-xl border border-semantic-error/30 px-4 py-2 text-xs font-medium text-semantic-error hover:bg-semantic-error/10 transition-colors"
            >
              Delete Account
            </button>
          </div>
        </div>
      </Section>

      <ConfirmDialog open={deactivateDialog} title="Deactivate Account" message="You will be logged out and your account will be inaccessible until reactivated by an administrator." confirmLabel="Deactivate" variant="danger" onConfirm={handleDeactivate} onCancel={() => setDeactivateDialog(false)} />
      <ConfirmDialog open={deleteDialog} title="Delete Account" message="This will permanently delete your account, data, API keys, and all associated information. This action CANNOT be undone." confirmLabel="Delete Forever" variant="danger" onConfirm={handleDelete} onCancel={() => setDeleteDialog(false)} />
    </div>
  )
}
