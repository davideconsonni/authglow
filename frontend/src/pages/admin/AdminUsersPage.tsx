import { useState, useEffect } from 'react'
import { Search, Loader2, ShieldOff, UserX, UserPlus, Mail, Save } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'

interface AdminUser {
  id: string
  email: string
  first_name: string
  last_name: string
  is_active: boolean
  mfa_enabled: boolean
  created_at: string
  login_count: number
}

interface InviteForm {
  email: string
  first_name: string
  last_name: string
  scopes: string
}

function UserAvatar({ first, last }: { first?: string; last?: string }) {
  const a = first?.[0] ?? ''
  const b = last?.[0] ?? ''
  const initials = (a + b).toUpperCase() || '?'
  return (
    <span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-brand-violet/20 text-xs font-semibold text-brand-violet">
      {initials}
    </span>
  )
}

export function AdminUsersPage() {
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [resetMfaId, setResetMfaId] = useState<string | null>(null)
  const [showInvite, setShowInvite] = useState(false)
  const [inviteForm, setInviteForm] = useState<InviteForm>({ email: '', first_name: '', last_name: '', scopes: '' })
  const [inviting, setInviting] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const limit = 15
  const { data, refetch, isLoading } = useApiQuery<{
    items: AdminUser[]
    total: number
    limit: number
    offset: number
  }>(
    ['admin-users', search, String(page)],
    `/api/admin/users/search?q=${encodeURIComponent(search)}&limit=${limit}&offset=${(page - 1) * limit}`,
  )

  const users = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.ceil(total / limit)

  useEffect(() => {
    if (success) {
      const t = setTimeout(() => setSuccess(''), 3000)
      return () => clearTimeout(t)
    }
  }, [success])

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      setError('')
      await api.delete(`/api/admin/users/${deleteId}`)
      setDeleteId(null)
      setSuccess('User deleted successfully.')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete user')
    }
  }

  const handleResetMfa = async () => {
    if (!resetMfaId) return
    try {
      setError('')
      await api.post(`/api/admin/users/${resetMfaId}/reset-mfa`)
      setResetMfaId(null)
      setSuccess('MFA reset successfully.')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to reset MFA')
    }
  }

  const handleToggleActive = async (id: string, isActive: boolean) => {
    try {
      setError('')
      await api.put(`/api/admin/users/${id}`, { is_active: !isActive })
      await refetch()
    } catch {
      /* ignore toggle errors */
    }
  }

  const handleInvite = async () => {
    if (!inviteForm.email) return
    setInviting(true)
    setError('')
    try {
      const scopes = inviteForm.scopes
        ? inviteForm.scopes.split(',').map((s) => s.trim()).filter(Boolean)
        : []
      await api.post('/api/admin/users', {
        email: inviteForm.email,
        first_name: inviteForm.first_name,
        last_name: inviteForm.last_name,
        scopes,
      })
      setShowInvite(false)
      setInviteForm({ email: '', first_name: '', last_name: '', scopes: '' })
      setSuccess('User created successfully.')
      await refetch()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to create user')
    } finally {
      setInviting(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="Users"
        description="Manage registered users."
        actions={
          <button
            onClick={() => setShowInvite(true)}
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <UserPlus size={16} />
            Invite User
          </button>
        }
      />

      {error && (
        <div className="mb-4 rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">
          {error}
        </div>
      )}
      {success && (
        <div className="mb-4 rounded-xl bg-semantic-success/10 px-4 py-2 text-xs text-semantic-success">
          {success}
        </div>
      )}

      <div className="mb-4">
        <div className="relative max-w-sm">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
            placeholder="Search by email or name..."
            className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 pl-10 pr-4 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
          />
        </div>
      </div>

      {isLoading ? (
        <div className="py-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" />
        </div>
      ) : users.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="rounded-2xl bg-surface-2 p-4">
            <Mail className="h-8 w-8 text-text-muted" />
          </div>
          <h3 className="mt-4 text-lg font-semibold text-text-primary">No users found</h3>
          <p className="mt-2 max-w-sm text-sm text-text-muted">
            {search ? 'No users match your search. Try different keywords.' : 'Get started by inviting your first user.'}
          </p>
          {!search && (
            <button
              onClick={() => setShowInvite(true)}
              className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              <UserPlus size={16} />
              Invite User
            </button>
          )}
        </div>
      ) : (
        <>
          <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-surface-2">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">User</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Email</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">MFA</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Active</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Logins</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
                  <th className="px-6 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-2">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-surface-2/50">
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-3">
                        <UserAvatar first={u.first_name} last={u.last_name} />
                        <span className="text-sm font-medium text-text-primary">
                          {u.first_name} {u.last_name}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-3 text-sm text-text-secondary">{u.email}</td>
                    <td className="px-6 py-3">
                      <span
                        className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${
                          u.mfa_enabled
                            ? 'bg-semantic-success/10 text-semantic-success'
                            : 'bg-surface-2 text-text-muted'
                        }`}
                      >
                        {u.mfa_enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="px-6 py-3">
                      <button
                        onClick={() => handleToggleActive(u.id, u.is_active)}
                        className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium transition-colors ${
                          u.is_active
                            ? 'bg-semantic-success/10 text-semantic-success hover:bg-semantic-success/20'
                            : 'bg-semantic-error/10 text-semantic-error hover:bg-semantic-error/20'
                        }`}
                      >
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            u.is_active ? 'bg-semantic-success' : 'bg-semantic-error'
                          }`}
                        />
                        {u.is_active ? 'Active' : 'Inactive'}
                      </button>
                    </td>
                    <td className="px-6 py-3 text-sm text-text-muted">{u.login_count ?? 0}</td>
                    <td className="px-6 py-3 text-sm text-text-muted">{formatDateTime(u.created_at)}</td>
                    <td className="px-6 py-3">
                      <div className="flex gap-2">
                        <button
                          onClick={() => setResetMfaId(u.id)}
                          className="text-text-muted hover:text-text-secondary transition-colors"
                          title="Reset MFA"
                        >
                          <ShieldOff size={14} />
                        </button>
                        <button
                          onClick={() => setDeleteId(u.id)}
                          className="text-text-muted hover:text-semantic-error transition-colors"
                          title="Delete user"
                        >
                          <UserX size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="mt-4 flex items-center justify-between">
              <span className="text-xs text-text-muted">
                {total} user{total !== 1 ? 's' : ''} total
              </span>
              <div className="flex gap-2">
                {Array.from({ length: totalPages }, (_, i) => (
                  <button
                    key={i}
                    onClick={() => setPage(i + 1)}
                    className={`rounded-lg px-3 py-1 text-sm transition-colors ${
                      page === i + 1
                        ? 'bg-brand-violet text-white'
                        : 'bg-surface-2 text-text-secondary hover:bg-surface-3'
                    }`}
                  >
                    {i + 1}
                  </button>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      <ConfirmDialog
        open={!!deleteId}
        title="Delete User"
        message="This action cannot be undone. The user and all associated data will be permanently deleted."
        confirmLabel="Delete"
        variant="danger"
        onConfirm={handleDelete}
        onCancel={() => setDeleteId(null)}
      />

      <ConfirmDialog
        open={!!resetMfaId}
        title="Reset MFA"
        message="This will disable MFA for this user. They will need to set it up again on next login."
        confirmLabel="Reset MFA"
        variant="danger"
        onConfirm={handleResetMfa}
        onCancel={() => setResetMfaId(null)}
      />

      {showInvite && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowInvite(false)} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet">
            <h3 className="text-lg font-semibold text-text-primary">Create User</h3>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Email</label>
              <input
                value={inviteForm.email}
                onChange={(e) => setInviteForm({ ...inviteForm, email: e.target.value })}
                placeholder="user@example.com"
                type="email"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="mb-1 block text-xs font-medium text-text-muted">First name</label>
                <input
                  value={inviteForm.first_name}
                  onChange={(e) => setInviteForm({ ...inviteForm, first_name: e.target.value })}
                  placeholder="First name"
                  className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-text-muted">Last name</label>
                <input
                  value={inviteForm.last_name}
                  onChange={(e) => setInviteForm({ ...inviteForm, last_name: e.target.value })}
                  placeholder="Last name"
                  className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
                />
              </div>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Initial scopes (comma-separated)</label>
              <input
                value={inviteForm.scopes}
                onChange={(e) => setInviteForm({ ...inviteForm, scopes: e.target.value })}
                placeholder="openid, profile, email"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>
            <div className="flex gap-3 pt-2">
              <button
                onClick={() => setShowInvite(false)}
                className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleInvite}
                disabled={inviting || !inviteForm.email}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
              >
                {inviting ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Create User
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
