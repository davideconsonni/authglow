import { useState, useEffect, useReducer } from 'react'
import { Search, Loader2, ShieldOff, UserX, UserPlus, Mail, Save, Plus, X } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

interface AdminUser {
  id: string; email: string; first_name: string; last_name: string
  is_active: boolean; mfa_enabled: boolean; created_at: string; login_count: number
}

interface AdminUserDetail {
  id: string; email: string; first_name: string | null; last_name: string | null
  is_active: boolean; mfa_enabled: boolean; email_verified: boolean
  login_count: number; created_at: string; updated_at: string
  last_login: string | null; is_invited: boolean; mfa_verified: boolean
  scopes: string[]; failed_login_count: number
}

function UserAvatar({ first, last }: { first?: string; last?: string }) {
  const initials = ((first?.[0] ?? '') + (last?.[0] ?? '')).toUpperCase() || '?'
  return <span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-brand-violet/20 text-xs font-semibold text-brand-violet">{initials}</span>
}

export function AdminUsersPage() {
  useDocumentTitle('Admin Users')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [resetMfaId, setResetMfaId] = useState<string | null>(null)
  const [showInvite, setShowInvite] = useState(false)
  const [inviteForm, setInviteForm] = useState({ email: '', first_name: '', last_name: '', scopes: '' })
  const [inviting, setInviting] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [bulkAction, setBulkAction] = useState<'activate' | 'deactivate' | 'delete' | null>(null)
  const [bulking, setBulking] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [detailUserId, setDetailUserId] = useState<string | null>(null)

  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [mfaFilter, setMfaFilter] = useState<string>('all')
  const [verifiedFilter, setVerifiedFilter] = useState<string>('all')

  const limit = 15

  const queryParams = new URLSearchParams()
  queryParams.set('q', search)
  queryParams.set('limit', String(limit))
  queryParams.set('offset', String((page - 1) * limit))
  if (statusFilter !== 'all') queryParams.set('is_active', statusFilter === 'active' ? 'true' : 'false')
  if (mfaFilter !== 'all') queryParams.set('mfa_enabled', mfaFilter === 'enabled' ? 'true' : 'false')
  if (verifiedFilter !== 'all') queryParams.set('email_verified', verifiedFilter === 'verified' ? 'true' : 'false')

  const queryKey = ['admin-users', search, String(page), statusFilter, mfaFilter, verifiedFilter]
  const queryUrl = `/api/admin/users/search?${queryParams.toString()}`
  const { data, refetch, isLoading } = useApiQuery<{ items: AdminUser[]; total: number; limit: number; offset: number }>(
    queryKey, queryUrl, { enabled: true },
  )

  const users = data?.items ?? []
  const total = data?.total ?? 0
  const totalPages = Math.ceil(total / limit)

  useEffect(() => { if (success) { const t = setTimeout(() => setSuccess(''), 3000); return () => clearTimeout(t) } }, [success])

  const handleDelete = async () => { if (!deleteId) return; try { await api.delete(`/api/admin/users/${deleteId}`); setDeleteId(null); setSuccess('User deleted.'); await refetch() } catch (e) { setError(e instanceof Error ? e.message : 'Failed') } }
  const handleResetMfa = async () => { if (!resetMfaId) return; try { await api.post(`/api/admin/users/${resetMfaId}/reset-mfa`); setResetMfaId(null); setSuccess('MFA reset.'); await refetch() } catch (e) { setError(e instanceof Error ? e.message : 'Failed') } }

  const handleToggleActive = async (id: string, isActive: boolean) => {
    setError('')
    try { await api.put(`/api/admin/users/${id}`, { is_active: !isActive }); await refetch() } catch { /* ignore */ }
  }

  const handleInvite = async () => {
    if (!inviteForm.email) return; setInviting(true); setError('')
    try {
      const scopes = inviteForm.scopes ? inviteForm.scopes.split(',').map(s => s.trim()).filter(Boolean) : []
      await api.post('/api/users/invite', { email: inviteForm.email, first_name: inviteForm.first_name, last_name: inviteForm.last_name, scopes })
      setShowInvite(false); setInviteForm({ email: '', first_name: '', last_name: '', scopes: '' }); setSuccess('User created.'); await refetch()
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed') } finally { setInviting(false) }
  }

  const toggleSelect = (id: string) => { const n = new Set(selected); if (n.has(id)) n.delete(id); else n.add(id); setSelected(n) }
  const toggleSelectAll = () => setSelected(selected.size === users.length ? new Set() : new Set(users.map(u => u.id)))

  const handleBulkAction = async () => {
    if (selected.size === 0 || !bulkAction) return; setBulking(true); setError('')
    try {
      const ids = Array.from(selected)
      if (bulkAction === 'delete') { for (const id of ids) await api.delete(`/api/admin/users/${id}`) }
      else await api.post('/api/admin/users/bulk', { user_ids: ids, action: bulkAction === 'activate' ? 'activate' : 'deactivate' })
      setSelected(new Set()); setBulkAction(null)
      setSuccess(`${bulkAction === 'delete' ? 'Deleted' : bulkAction === 'activate' ? 'Activated' : 'Deactivated'} ${ids.length} user${ids.length !== 1 ? 's' : ''}.`)
      await refetch()
    } catch (e) { setError(e instanceof Error ? e.message : 'Bulk action failed') } finally { setBulking(false) }
  }

  const handleFilterChange = (setter: (v: string) => void) => (val: string) => { setter(val); setPage(1) }

  return (
    <div>
      <PageHeader title="Users" description="Manage registered users."
        actions={<button onClick={() => setShowInvite(true)} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"><UserPlus size={16} />Invite User</button>}
      />
      {error && <div className="mb-4 rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">{error}</div>}
      {success && <div className="mb-4 rounded-xl bg-semantic-success/10 px-4 py-2 text-xs text-semantic-success">{success}</div>}

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative max-w-sm flex-1">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
          <input value={search} onChange={e => { setSearch(e.target.value); setPage(1) }} placeholder="Search by email or name..." data-testid="user-search-input" className="w-full rounded-xl border border-surface-2 bg-surface-1 py-2.5 pl-10 pr-4 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
        </div>
        <select value={statusFilter} onChange={e => handleFilterChange(setStatusFilter)(e.target.value)} data-testid="filter-status" className="rounded-xl border border-surface-2 bg-surface-1 px-3 py-2.5 text-sm text-text-primary focus:border-brand-violet focus:outline-none">
          <option value="all">All Status</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
        </select>
        <select value={mfaFilter} onChange={e => handleFilterChange(setMfaFilter)(e.target.value)} data-testid="filter-mfa" className="rounded-xl border border-surface-2 bg-surface-1 px-3 py-2.5 text-sm text-text-primary focus:border-brand-violet focus:outline-none">
          <option value="all">All MFA</option>
          <option value="enabled">MFA Enabled</option>
          <option value="disabled">MFA Disabled</option>
        </select>
        <select value={verifiedFilter} onChange={e => handleFilterChange(setVerifiedFilter)(e.target.value)} data-testid="filter-verified" className="rounded-xl border border-surface-2 bg-surface-1 px-3 py-2.5 text-sm text-text-primary focus:border-brand-violet focus:outline-none">
          <option value="all">All Verified</option>
          <option value="verified">Email Verified</option>
          <option value="unverified">Email Unverified</option>
        </select>
      </div>

      {isLoading ? <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div>
      : users.length === 0 ? <div className="flex flex-col items-center justify-center py-16 text-center"><div className="rounded-2xl bg-surface-2 p-4"><Mail className="h-8 w-8 text-text-muted" /></div><h3 className="mt-4 text-lg font-semibold text-text-primary">No users found</h3><p className="mt-2 max-w-sm text-sm text-text-muted">{search || statusFilter !== 'all' || mfaFilter !== 'all' || verifiedFilter !== 'all' ? 'No matches. Try different filters.' : 'Get started by inviting your first user.'}</p>{!search && statusFilter === 'all' && mfaFilter === 'all' && verifiedFilter === 'all' && <button onClick={() => setShowInvite(true)} className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet hover:scale-[1.02]"><UserPlus size={16} />Invite User</button>}</div>
      : <>
        {selected.size > 0 && <div className="mb-3 flex items-center gap-3 rounded-xl bg-brand-violet/10 border border-brand-violet/20 px-4 py-3" data-testid="bulk-action-bar"><span className="text-sm text-brand-violet font-medium">{selected.size} selected</span><div className="flex gap-2 ml-auto"><button onClick={() => setBulkAction('activate')} disabled={bulking} className="rounded-lg bg-semantic-success/10 px-3 py-1 text-xs font-medium text-semantic-success hover:bg-semantic-success/20 disabled:opacity-50">Activate</button><button onClick={() => setBulkAction('deactivate')} disabled={bulking} data-testid="bulk-deactivate-btn" className="rounded-lg bg-semantic-warning/10 px-3 py-1 text-xs font-medium text-semantic-warning hover:bg-semantic-warning/20 disabled:opacity-50">Deactivate</button><button onClick={() => setBulkAction('delete')} disabled={bulking} className="rounded-lg bg-semantic-error/10 px-3 py-1 text-xs font-medium text-semantic-error hover:bg-semantic-error/20 disabled:opacity-50">Delete</button><button onClick={() => { setSelected(new Set()); setBulkAction(null) }} className="rounded-lg bg-surface-2 px-3 py-1 text-xs text-text-secondary hover:bg-surface-3">Clear</button></div></div>}

        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full"><thead className="border-b border-surface-2"><tr>
            <th className="px-4 py-3 w-10"><button onClick={toggleSelectAll} data-testid="bulk-select-all" className="rounded p-0.5 text-text-muted hover:text-text-primary">{selected.size === users.length && users.length > 0 ? '✓' : '☐'}</button></th>
            <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">User</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Email</th>
            <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">MFA</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Active</th>
            <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Logins</th>
            <th className="hidden md:table-cell px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Created</th>
            <th className="hidden md:table-cell px-6 py-3" />
          </tr></thead>
          <tbody className="divide-y divide-surface-2">
            {users.map(u => <tr key={u.id} className={`hover:bg-surface-2/50 cursor-pointer ${selected.has(u.id) ? 'bg-brand-violet/5' : ''}`} onClick={() => setDetailUserId(u.id)} data-testid="user-table-row">
              <td className="px-4 py-3" onClick={e => e.stopPropagation()}><button onClick={() => toggleSelect(u.id)} data-testid="user-select-checkbox" className="rounded p-0.5 text-text-muted hover:text-text-primary">{selected.has(u.id) ? '✓' : '☐'}</button></td>
              <td className="px-6 py-3"><div className="flex items-center gap-3"><UserAvatar first={u.first_name} last={u.last_name} /><span className="text-sm font-medium text-text-primary">{u.first_name} {u.last_name}</span></div></td>
              <td className="px-6 py-3 text-sm text-text-secondary">{u.email}</td>
              <td className="hidden md:table-cell px-6 py-3"><span className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${u.mfa_enabled ? 'bg-semantic-success/10 text-semantic-success' : 'bg-surface-2 text-text-muted'}`}>{u.mfa_enabled ? 'Enabled' : 'Disabled'}</span></td>
              <td className="px-6 py-3" onClick={e => e.stopPropagation()}><button onClick={() => handleToggleActive(u.id, u.is_active)} data-testid="toggle-active-btn" className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 min-h-[44px] py-1 text-xs font-medium ${u.is_active ? 'bg-semantic-success/10 text-semantic-success' : 'bg-semantic-error/10 text-semantic-error'}`}><span className={`h-1.5 w-1.5 rounded-full ${u.is_active ? 'bg-semantic-success' : 'bg-semantic-error'}`} />{u.is_active ? 'Active' : 'Inactive'}</button></td>
              <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">{u.login_count ?? 0}</td>
              <td className="hidden md:table-cell px-6 py-3 text-sm text-text-muted">{formatDateTime(u.created_at)}</td>
              <td className="hidden md:table-cell px-6 py-3" onClick={e => e.stopPropagation()}><div className="flex gap-2"><button onClick={() => setResetMfaId(u.id)} className="text-text-muted hover:text-text-secondary" title="Reset MFA"><ShieldOff size={14} /></button><button onClick={() => setDeleteId(u.id)} className="text-text-muted hover:text-semantic-error" title="Delete"><UserX size={14} /></button></div></td>
            </tr>)}
          </tbody></table>
        </div>

        {totalPages > 1 && <div className="mt-4 flex items-center justify-between"><span className="text-xs text-text-muted">{total} user{total !== 1 ? 's' : ''} total</span><div className="flex gap-2">{Array.from({ length: totalPages }, (_, i) => <button key={i} onClick={() => setPage(i + 1)} className={`rounded-lg px-3 py-1 text-sm ${page === i + 1 ? 'bg-brand-violet text-white' : 'bg-surface-2 text-text-secondary hover:bg-surface-3'}`}>{i + 1}</button>)}</div></div>}
      </>}

      <ConfirmDialog open={!!deleteId} title="Delete User" message="This action cannot be undone." confirmLabel="Delete" variant="danger" onConfirm={handleDelete} onCancel={() => setDeleteId(null)} />
      <ConfirmDialog open={!!resetMfaId} title="Reset MFA" message="This will disable MFA for this user." confirmLabel="Reset MFA" variant="danger" onConfirm={handleResetMfa} onCancel={() => setResetMfaId(null)} />
      <ConfirmDialog open={!!bulkAction} title={`${bulkAction} ${selected.size} Users`} message={`${bulkAction === 'delete' ? 'Permanently delete' : bulkAction === 'activate' ? 'Activate' : 'Deactivate'} ${selected.size} selected user${selected.size !== 1 ? 's' : ''}.`} confirmLabel="Confirm" variant="danger" onConfirm={handleBulkAction} onCancel={() => setBulkAction(null)} />

      {showInvite && <div className="fixed inset-0 z-50 flex items-center justify-center"><div className="absolute inset-0 bg-black/50" onClick={() => setShowInvite(false)} /><div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet">
        <h3 className="text-lg font-semibold text-text-primary">Invite User</h3>
        <div><label className="mb-1 block text-xs font-medium text-text-muted">Email</label><input value={inviteForm.email} onChange={e => setInviteForm({...inviteForm, email: e.target.value})} placeholder="user@example.com" type="email" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div>
        <div className="grid grid-cols-2 gap-3"><div><label className="mb-1 block text-xs font-medium text-text-muted">First name</label><input value={inviteForm.first_name} onChange={e => setInviteForm({...inviteForm, first_name: e.target.value})} placeholder="First name" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div><div><label className="mb-1 block text-xs font-medium text-text-muted">Last name</label><input value={inviteForm.last_name} onChange={e => setInviteForm({...inviteForm, last_name: e.target.value})} placeholder="Last name" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div></div>
        <div><label className="mb-1 block text-xs font-medium text-text-muted">Initial scopes (comma-separated)</label><input value={inviteForm.scopes} onChange={e => setInviteForm({...inviteForm, scopes: e.target.value})} placeholder="openid, profile, email" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div>
        <div className="flex gap-3 pt-2"><button onClick={() => setShowInvite(false)} className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2">Cancel</button><button onClick={handleInvite} disabled={inviting || !inviteForm.email} className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet disabled:opacity-50">{inviting ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}Create User</button></div>
      </div></div>}

      {detailUserId && <UserDrawer userId={detailUserId} onClose={() => setDetailUserId(null)} onUserUpdated={refetch} />}
    </div>
  )
}

function UserDrawer({ userId, onClose, onUserUpdated }: { userId: string; onClose: () => void; onUserUpdated: () => void }) {
  const queryClient = useQueryClient()
  const { data: user, isLoading } = useApiQuery<AdminUserDetail>(['user-detail', userId], `/api/admin/users/${userId}`)
  const { data: keys } = useApiQuery<unknown[]>(['user-keys', userId], `/api/admin/users/${userId}/keys`)
  const { data: passkeys } = useApiQuery<unknown[]>(['user-passkeys', userId], `/api/admin/users/${userId}/passkeys`)

  type EditState = { first: string; last: string; verified: boolean; scopes: string[] }
  const reducer = (state: EditState, action: { type: string; value?: unknown; user?: AdminUserDetail }): EditState => {
    switch (action.type) {
      case 'SET_FIRST': return { ...state, first: action.value as string }
      case 'SET_LAST': return { ...state, last: action.value as string }
      case 'SET_VERIFIED': return { ...state, verified: action.value as boolean }
      case 'ADD_SCOPE': return { ...state, scopes: [...state.scopes, action.value as string] }
      case 'REMOVE_SCOPE': return { ...state, scopes: state.scopes.filter(s => s !== action.value) }
      case 'INIT': {
        const u = action.user
        return {
          first: u?.first_name ?? '',
          last: u?.last_name ?? '',
          verified: u?.email_verified ?? false,
          scopes: u?.scopes ? [...u.scopes] : [],
        }
      }
      default: return state
    }
  }

  const [edit, dispatch] = useReducer(reducer, { first: '', last: '', verified: false, scopes: [] })
  const [newScope, setNewScope] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => { if (user) dispatch({ type: 'INIT', user }) }, [user])

  useEffect(() => { if (success) { const t = setTimeout(() => setSuccess(''), 2000); return () => clearTimeout(t) } }, [success])

  const addScope = () => {
    const trimmed = newScope.trim()
    if (trimmed && !edit.scopes.includes(trimmed)) {
      dispatch({ type: 'ADD_SCOPE', value: trimmed })
    }
    setNewScope('')
  }

  const removeScope = (scope: string) => {
    dispatch({ type: 'REMOVE_SCOPE', value: scope })
  }

  const handleSave = async () => {
    setSaving(true); setError('')
    try {
      await api.put(`/api/admin/users/${userId}`, {
        first_name: edit.first || null,
        last_name: edit.last || null,
        email_verified: edit.verified,
        scopes: edit.scopes,
      })
      setSuccess('User updated.')
      queryClient.invalidateQueries({ queryKey: ['user-detail', userId] })
      queryClient.invalidateQueries({ queryKey: ['admin-users'] })
      onUserUpdated()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative z-10 w-full max-w-md bg-surface-1 border-l border-surface-2 overflow-y-auto p-6 space-y-5 shadow-glow-violet" data-testid="user-detail-drawer">
        <div className="flex items-center justify-between"><h3 className="text-lg font-semibold text-text-primary">User Detail</h3><button onClick={onClose} className="rounded-lg p-1 text-text-muted hover:text-text-secondary">✕</button></div>

        {isLoading ? <div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div>
        : user ? <>
          <div className="rounded-xl border border-surface-2 bg-surface-1 p-4 space-y-3">
            <div className="flex items-center gap-3">
              <span className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-brand-violet/20 text-sm font-bold text-brand-violet">{(user.first_name?.[0]||'')+(user.last_name?.[0]||'')||'?'}</span>
              <div><p className="text-sm font-semibold text-text-primary">{user.first_name} {user.last_name}</p><p className="text-xs text-text-muted">{user.email}</p></div>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-lg bg-surface-2 p-2"><p className="text-text-muted">Status</p><p className="text-text-primary font-medium">{user.is_active?'Active':'Inactive'}</p></div>
              <div className="rounded-lg bg-surface-2 p-2"><p className="text-text-muted">MFA</p><p className="text-text-primary font-medium">{user.mfa_enabled?'Enabled':'Disabled'}</p></div>
              <div className="rounded-lg bg-surface-2 p-2"><p className="text-text-muted">Logins</p><p className="text-text-primary font-medium">{user.login_count??0}</p></div>
              <div className="rounded-lg bg-surface-2 p-2"><p className="text-text-muted">Created</p><p className="text-text-primary font-medium">{user.created_at?formatDateTime(user.created_at):'-'}</p></div>
            </div>

            <div className="border-t border-surface-2 pt-3 space-y-3">
              <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Edit Profile</h4>
              <div className="grid grid-cols-2 gap-3">
                <div><label className="mb-1 block text-xs text-text-muted">First name</label><input value={edit.first} onChange={e => dispatch({ type: 'SET_FIRST', value: e.target.value })} className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary focus:border-brand-violet focus:outline-none" /></div>
                <div><label className="mb-1 block text-xs text-text-muted">Last name</label><input value={edit.last} onChange={e => dispatch({ type: 'SET_LAST', value: e.target.value })} className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary focus:border-brand-violet focus:outline-none" /></div>
              </div>
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={edit.verified} onChange={e => dispatch({ type: 'SET_VERIFIED', value: e.target.checked })} className="rounded border-surface-2 text-brand-violet focus:ring-brand-violet" /><span className="text-text-primary">Email verified</span></label>
            </div>

            <div className="border-t border-surface-2 pt-3 space-y-2">
              <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Scopes</h4>
              <div className="flex flex-wrap gap-1.5 min-h-[28px]">
                {edit.scopes.map(s => (
                  <span key={s} className="inline-flex items-center gap-1 rounded-lg bg-surface-2 px-2 py-0.5 text-[11px] text-text-secondary">
                    {s}
                    <button onClick={() => removeScope(s)} className="text-text-muted hover:text-semantic-error"><X size={12} /></button>
                  </span>
                ))}
                {edit.scopes.length === 0 && <span className="text-[11px] text-text-muted italic">No scopes</span>}
              </div>
              <div className="flex gap-2">
                <input value={newScope} onChange={e => setNewScope(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addScope() } }} placeholder="Add scope..." className="flex-1 rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-xs text-text-primary focus:border-brand-violet focus:outline-none" />
                <button onClick={addScope} disabled={!newScope.trim()} className="rounded-lg bg-brand-violet/10 px-2.5 py-1.5 text-xs font-medium text-brand-violet hover:bg-brand-violet/20 disabled:opacity-40"><Plus size={14} /></button>
              </div>
            </div>
          </div>

          {error && <div className="rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">{error}</div>}
          {success && <div className="rounded-xl bg-semantic-success/10 px-4 py-2 text-xs text-semantic-success">{success}</div>}

          <button onClick={handleSave} disabled={saving} className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50">
            {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
            Save Changes
          </button>

          {keys && keys.length > 0 && <div><h4 className="text-sm font-semibold text-text-primary mb-2">API Keys ({keys.length})</h4><div className="space-y-1.5">{(keys as Array<Record<string, unknown>>).map(k => <div key={k.id as string} className="rounded-lg bg-surface-2 px-3 py-2 text-xs"><span className="text-text-primary font-medium">{k.name as string}</span><code className="ml-2 text-text-muted">{((k.key_prefix ?? (k.id as string)?.slice(0,8)) as string)}...</code></div>)}</div></div>}
          {passkeys && passkeys.length > 0 && <div><h4 className="text-sm font-semibold text-text-primary mb-2">Passkeys ({passkeys.length})</h4><div className="space-y-1.5">{(passkeys as Array<Record<string, unknown>>).map(pk => <div key={(pk.id ?? pk.credential_id) as string} className="rounded-lg bg-surface-2 px-3 py-2 text-xs"><span className="text-text-primary">{(pk.name ?? pk.device_type ?? 'Passkey') as string}</span><span className="ml-2 text-text-muted">{pk.created_at ? formatDateTime(pk.created_at as string) : ''}</span></div>)}</div></div>}
        </> : <p className="text-sm text-text-muted text-center py-8">Could not load user details.</p>}
      </div>
    </div>
  )
}
