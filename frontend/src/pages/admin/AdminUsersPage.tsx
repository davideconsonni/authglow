import { useState, useEffect, useReducer, useRef } from 'react'
import { Search, Loader2, ShieldOff, Shield, UserX, UserPlus, Mail, Save, Plus, X, Trash2, LogOut, RefreshCw, Smartphone, KeyRound, Monitor, Fingerprint, History, AlertTriangle, Globe, Download, Ban, Clock, Check } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '../../lib/api'
import { useApiQuery } from '../../hooks/useApi'
import { useDemoMeta } from '../../hooks/useDemoMeta'
import { ConfirmDialog } from '../../components/shared/ConfirmDialog'
import { Banner } from '../../components/shared/Banner'
import { DemoInbox } from '../../components/shared/DemoInbox'
import { PageHeader } from '../../components/layout/PageHeader'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../../components/ui/tabs'
import { formatDateTime } from '../../lib/utils'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { useAuthStore } from '../../stores/authStore'
import { notify } from '../../stores/toastStore'

interface AdminUser {
  id: string; email: string; first_name: string; last_name: string
  is_active: boolean; mfa_enabled: boolean; created_at: string; login_count: number
  is_federated: boolean
}

// Mirror of backend defaults (backend/.env.example: PASSWORD_MIN_LENGTH=8,
// PASSWORD_REQUIRE_UPPERCASE / LOWERCASE / DIGITS / SPECIAL=true).
// If the operator disables a rule, the server will still enforce it; this
// client-side check is purely UX.
const PASSWORD_RULES: { label: string; test: (v: string) => boolean }[] = [
  { label: 'At least 8 characters', test: (v) => v.length >= 8 },
  { label: 'One uppercase letter', test: (v) => /[A-Z]/.test(v) },
  { label: 'One lowercase letter', test: (v) => /[a-z]/.test(v) },
  { label: 'One digit', test: (v) => /\d/.test(v) },
  { label: 'One special character', test: (v) => /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(v) },
]

function passwordIsValid(value: string): boolean {
  return PASSWORD_RULES.every((rule) => rule.test(value))
}

interface AdminUserDetail {
  id: string; email: string; first_name: string | null; last_name: string | null
  is_active: boolean; mfa_enabled: boolean; email_verified: boolean
  login_count: number; created_at: string; updated_at: string
  last_login: string | null; is_invited: boolean; mfa_verified: boolean
  scopes: string[]; failed_login_count: number
  password_expired: boolean; locked_until: string | null
  suspended_until: string | null
  phone: string | null; avatar_url: string | null
  is_federated: boolean
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
  const [revokeSessionsId, setRevokeSessionsId] = useState<string | null>(null)
  const [showInvite, setShowInvite] = useState(false)
  const [inviteForm, setInviteForm] = useState({ email: '', first_name: '', last_name: '', scopes: '' })
  const [inviting, setInviting] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState({ email: '', password: '', first_name: '', last_name: '', scopes: '', phone: '', avatar_url: '' })
  const [creating, setCreating] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [bulkAction, setBulkAction] = useState<'activate' | 'deactivate' | 'delete' | null>(null)
  const [bulking, setBulking] = useState(false)
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

  const handleDelete = async () => { if (!deleteId) return; try { await api.delete(`/api/admin/users/${deleteId}`); setDeleteId(null); notify.success('User deleted.'); await refetch() } catch (e) { notify.error(e instanceof Error ? e.message : 'Failed') } }
  const handleResetMfa = async () => { if (!resetMfaId) return; try { await api.post(`/api/admin/users/${resetMfaId}/reset-mfa`); setResetMfaId(null); notify.success('MFA reset.'); await refetch() } catch (e) { notify.error(e instanceof Error ? e.message : 'Failed') } }
  const handleRevokeSessions = async () => { if (!revokeSessionsId) return; try { await api.post(`/api/admin/users/${revokeSessionsId}/sessions/revoke-all`); setRevokeSessionsId(null); notify.success('All sessions revoked.'); await refetch() } catch (e) { notify.error(e instanceof Error ? e.message : 'Failed') } }

  const handleToggleActive = async (id: string, isActive: boolean) => {
    try { await api.put(`/api/admin/users/${id}`, { is_active: !isActive }); await refetch() } catch { /* ignore */ }
  }

  const handleInvite = async () => {
    if (!inviteForm.email) return; setInviting(true)
    try {
      const scopes = inviteForm.scopes ? inviteForm.scopes.split(',').map(s => s.trim()).filter(Boolean) : []
      await api.post('/api/users/invite', { email: inviteForm.email, first_name: inviteForm.first_name, last_name: inviteForm.last_name, scopes })
      setShowInvite(false); setInviteForm({ email: '', first_name: '', last_name: '', scopes: '' }); notify.success('User invited.'); await refetch()
    } catch (e) { notify.error(e instanceof Error ? e.message : 'Failed') } finally { setInviting(false) }
  }

  const handleCreate = async () => {
    if (!createForm.email || !createForm.password) return; setCreating(true)
    try {
      const scopes = createForm.scopes ? createForm.scopes.split(',').map(s => s.trim()).filter(Boolean) : []
      await api.post('/api/admin/users/create', {
        email: createForm.email,
        password: createForm.password,
        first_name: createForm.first_name || null,
        last_name: createForm.last_name || null,
        phone: createForm.phone || null,
        avatar_url: createForm.avatar_url || null,
        scopes,
      })
      setShowCreate(false); setCreateForm({ email: '', password: '', first_name: '', last_name: '', scopes: '', phone: '', avatar_url: '' }); notify.success('User created.'); await refetch()
    } catch (e) { notify.error(e instanceof Error ? e.message : 'Failed') } finally { setCreating(false) }
  }

  const toggleSelect = (id: string) => { const n = new Set(selected); if (n.has(id)) n.delete(id); else n.add(id); setSelected(n) }
  const toggleSelectAll = () => setSelected(selected.size === users.length ? new Set() : new Set(users.map(u => u.id)))

  const handleBulkAction = async () => {
    if (selected.size === 0 || !bulkAction) return; setBulking(true)
    try {
      const ids = Array.from(selected)
      if (bulkAction === 'delete') { for (const id of ids) await api.delete(`/api/admin/users/${id}`) }
      else await api.post('/api/admin/users/bulk', { user_ids: ids, action: bulkAction === 'activate' ? 'activate' : 'deactivate' })
      setSelected(new Set()); setBulkAction(null)
      notify.success(`${bulkAction === 'delete' ? 'Deleted' : bulkAction === 'activate' ? 'Activated' : 'Deactivated'} ${ids.length} user${ids.length !== 1 ? 's' : ''}.`)
      await refetch()
    } catch (e) { notify.error(e instanceof Error ? e.message : 'Bulk action failed') } finally { setBulking(false) }
  }

  const handleFilterChange = (setter: (v: string) => void) => (val: string) => { setter(val); setPage(1) }

  return (
    <div>
      <PageHeader title="Users" description="Manage registered users."
        actions={<div className="flex gap-2"><button onClick={() => setShowCreate(true)} data-testid="create-user-btn" className="flex items-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-4 py-2 text-sm font-semibold text-text-primary shadow-sm transition-all hover:scale-[1.02] active:scale-[0.98]"><UserPlus size={16} />Create User</button><button onClick={() => setShowInvite(true)} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"><Mail size={16} />Invite User</button></div>}
      />

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
            <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">User</th>
            <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Email</th>
            <th className="hidden md:table-cell px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">MFA</th>
            <th className="px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Active</th>
            <th className="hidden md:table-cell px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Logins</th>
            <th className="hidden md:table-cell px-4 py-2.5 text-left text-xs font-medium text-text-muted uppercase">Created</th>
            <th className="hidden md:table-cell px-4 py-2.5" />
          </tr></thead>
          <tbody className="divide-y divide-surface-2">
            {users.map(u => <tr key={u.id} className={`hover:bg-surface-2/50 cursor-pointer ${selected.has(u.id) ? 'bg-brand-violet/5' : ''}`} onClick={() => setDetailUserId(u.id)} data-testid="user-table-row">
              <td className="px-4 py-3" onClick={e => e.stopPropagation()}><button onClick={() => toggleSelect(u.id)} data-testid="user-select-checkbox" className="rounded p-0.5 text-text-muted hover:text-text-primary">{selected.has(u.id) ? '✓' : '☐'}</button></td>
              <td className="px-4 py-2.5"><div className="flex items-center gap-3"><UserAvatar first={u.first_name} last={u.last_name} /><span className="text-sm font-medium text-text-primary">{u.first_name} {u.last_name}</span></div></td>
              <td className="px-4 py-2.5 text-sm text-text-secondary">{u.email}</td>
              <td className="hidden md:table-cell px-4 py-2.5"><span className={`inline-flex rounded-lg px-2 py-0.5 text-xs font-medium ${u.mfa_enabled ? 'bg-semantic-success/10 text-semantic-success' : 'bg-surface-2 text-text-muted'}`}>{u.mfa_enabled ? 'Enabled' : 'Disabled'}</span></td>
              <td className="px-4 py-2.5" onClick={e => e.stopPropagation()}><button onClick={() => handleToggleActive(u.id, u.is_active)} data-testid="toggle-active-btn" className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 min-h-[44px] py-1 text-xs font-medium ${u.is_active ? 'bg-semantic-success/10 text-semantic-success' : 'bg-semantic-error/10 text-semantic-error'}`}><span className={`h-1.5 w-1.5 rounded-full ${u.is_active ? 'bg-semantic-success' : 'bg-semantic-error'}`} />{u.is_active ? 'Active' : 'Inactive'}</button></td>
              <td className="hidden md:table-cell px-4 py-2.5 text-sm text-text-muted">{u.login_count ?? 0}</td>
              <td className="hidden md:table-cell px-4 py-2.5 text-sm text-text-muted">{formatDateTime(u.created_at)}</td>
              <td className="hidden md:table-cell px-4 py-2.5" onClick={e => e.stopPropagation()}><div className="flex gap-2"><button onClick={() => setRevokeSessionsId(u.id)} className="text-text-muted hover:text-semantic-warning" title="Revoke sessions"><LogOut size={14} /></button>{!u.is_federated && <button onClick={() => setResetMfaId(u.id)} className="text-text-muted hover:text-text-secondary" title="Reset MFA"><ShieldOff size={14} /></button>}{!u.is_federated && <button onClick={() => setDeleteId(u.id)} className="text-text-muted hover:text-semantic-error" title="Delete"><UserX size={14} /></button>}</div></td>
            </tr>)}
          </tbody></table>
        </div>

        {totalPages > 1 && <div className="mt-4 flex items-center justify-between"><span className="text-xs text-text-muted">{total} user{total !== 1 ? 's' : ''} total</span><div className="flex gap-2">{Array.from({ length: totalPages }, (_, i) => <button key={i} onClick={() => setPage(i + 1)} className={`rounded-lg px-3 py-1 text-sm ${page === i + 1 ? 'bg-brand-violet text-white' : 'bg-surface-2 text-text-secondary hover:bg-surface-3'}`}>{i + 1}</button>)}</div></div>}
      </>}

      <ConfirmDialog open={!!deleteId} title="Delete User" message="This action cannot be undone." confirmLabel="Delete" variant="danger" onConfirm={handleDelete} onCancel={() => setDeleteId(null)} />
      <ConfirmDialog open={!!resetMfaId} title="Reset MFA" message="This will disable MFA for this user." confirmLabel="Reset MFA" variant="danger" onConfirm={handleResetMfa} onCancel={() => setResetMfaId(null)} />
      <ConfirmDialog open={!!revokeSessionsId} title="Revoke All Sessions" message="This will log out the user from all devices immediately." confirmLabel="Revoke All" variant="danger" onConfirm={handleRevokeSessions} onCancel={() => setRevokeSessionsId(null)} />
      <ConfirmDialog open={!!bulkAction} title={`${bulkAction} ${selected.size} Users`} message={`${bulkAction === 'delete' ? 'Permanently delete' : bulkAction === 'activate' ? 'Activate' : 'Deactivate'} ${selected.size} selected user${selected.size !== 1 ? 's' : ''}.`} confirmLabel="Confirm" variant="danger" onConfirm={handleBulkAction} onCancel={() => setBulkAction(null)} />

      {showCreate && <div className="fixed inset-0 z-50 flex items-center justify-center"><div className="absolute inset-0 bg-black/50" onClick={() => setShowCreate(false)} /><div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet">
        <h3 className="text-lg font-semibold text-text-primary">Create User</h3>
        <div><label className="mb-1 block text-xs font-medium text-text-muted">Email</label><input value={createForm.email} onChange={e => setCreateForm({...createForm, email: e.target.value})} placeholder="user@example.com" type="email" data-testid="create-user-email" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div>
        <div><label className="mb-1 block text-xs font-medium text-text-muted">Password</label><input value={createForm.password} onChange={e => setCreateForm({...createForm, password: e.target.value})} placeholder="Minimum 8 characters" type="password" data-testid="create-user-password" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div>
        <div className="grid grid-cols-2 gap-3"><div><label className="mb-1 block text-xs font-medium text-text-muted">First name</label><input value={createForm.first_name} onChange={e => setCreateForm({...createForm, first_name: e.target.value})} placeholder="First name" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div><div><label className="mb-1 block text-xs font-medium text-text-muted">Last name</label><input value={createForm.last_name} onChange={e => setCreateForm({...createForm, last_name: e.target.value})} placeholder="Last name" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div></div>
        <div className="grid grid-cols-2 gap-3"><div><label className="mb-1 block text-xs font-medium text-text-muted">Phone</label><input value={createForm.phone} onChange={e => setCreateForm({...createForm, phone: e.target.value})} placeholder="+1234567890" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div><div><label className="mb-1 block text-xs font-medium text-text-muted">Avatar URL</label><input value={createForm.avatar_url} onChange={e => setCreateForm({...createForm, avatar_url: e.target.value})} placeholder="https://..." className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div></div>
        <div><label className="mb-1 block text-xs font-medium text-text-muted">Scopes (comma-separated)</label><input value={createForm.scopes} onChange={e => setCreateForm({...createForm, scopes: e.target.value})} placeholder="openid, profile, email" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" /></div>
        <div className="flex gap-3 pt-2"><button onClick={() => setShowCreate(false)} className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2">Cancel</button><button onClick={handleCreate} disabled={creating || !createForm.email || !createForm.password} data-testid="create-user-submit" className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet disabled:opacity-50">{creating ? <Loader2 size={16} className="animate-spin" /> : <UserPlus size={16} />}Create User</button></div>
      </div></div>}

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
  const drawerRef = useRef<HTMLDivElement>(null)
  const closeButtonRef = useRef<HTMLButtonElement>(null)
  const previouslyFocusedRef = useRef<HTMLElement | null>(null)
  const [activeTab, setActiveTab] = useState('profile')
  const { meta: demoMeta } = useDemoMeta()

  const { data: user, isLoading } = useApiQuery<AdminUserDetail>(['user-detail', userId], `/api/admin/users/${userId}`)
  const { data: keys } = useApiQuery<unknown[]>(['user-keys', userId], `/api/admin/users/${userId}/keys`)
  const { data: passkeys } = useApiQuery<PasskeyItem[]>(['user-passkeys', userId], `/api/admin/users/${userId}/passkeys/list`)
  const { data: sessionsData, refetch: refetchSessions } = useApiQuery<{ items: SessionItem[]; total: number }>(
    ['user-sessions', userId], `/api/admin/users/${userId}/sessions`, { enabled: true },
  )
  const { data: loginHistory } = useApiQuery<{ items: LoginHistoryItem[]; total: number }>(
    ['user-login-history', userId], `/api/admin/users/${userId}/login-history`, { enabled: true },
  )
  const { data: securityEvents } = useApiQuery<{ items: SecurityEventItem[]; total: number }>(
    ['user-security-events', userId], `/api/admin/users/${userId}/security-events`, { enabled: true },
  )
  const { data: oauthConsents } = useApiQuery<OAuthConsentItem[]>(
    ['user-oauth-consents', userId], `/api/admin/users/${userId}/oauth-consents`, { enabled: true },
  )
  const { data: adminActions } = useApiQuery<{ items: AdminActionItem[]; total: number }>(
    ['user-admin-actions', userId], `/api/admin/users/${userId}/admin-actions`, { enabled: true },
  )

  // Close on Escape, trap Tab focus inside drawer, lock body scroll
  useEffect(() => {
    previouslyFocusedRef.current = document.activeElement as HTMLElement | null
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
        return
      }
      if (e.key !== 'Tab') return
      const root = drawerRef.current
      if (!root) return
      const focusables = root.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
      )
      if (focusables.length === 0) return
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      const active = document.activeElement as HTMLElement | null
      if (e.shiftKey && (active === first || !root.contains(active))) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && active === last) {
        e.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    // Defer focus until the close button is mounted
    const focusTimer = window.setTimeout(() => closeButtonRef.current?.focus(), 0)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.body.style.overflow = prevOverflow
      window.clearTimeout(focusTimer)
      previouslyFocusedRef.current?.focus?.()
    }
  }, [onClose])

  interface SessionItem {
    id: string; client_id: string; scopes: string[]
    created_at: string; expires_at: string | null; last_used_at: string | null; ip_address: string | null
  }

  interface PasskeyItem {
    credential_id: string; name: string; device_type: string | null
    transports: string[]; created_at: string; last_used_at: string | null
  }

  interface LoginHistoryItem {
    id: string; success: boolean; ip_address: string | null
    user_agent: string | null; failure_reason: string | null; timestamp: string
  }

  interface SecurityEventItem {
    id: string; event_type: string; description: string | null
    ip_address: string | null; timestamp: string
  }

  interface AdminActionItem {
    id: string; action_type: string; admin_email: string
    target_user_email: string | null; details: Record<string, unknown> | null
    ip_address: string | null; timestamp: string
  }

  interface OAuthConsentItem {
    consent_id: string; client_id: string; client_name: string
    scopes: string[]; granted_at: string; expires_at: string | null
    revoked: boolean; revoked_at: string | null
  }

  const [revokeSessionId, setRevokeSessionId] = useState<string | null>(null)
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null)
  const [deletePasskeyId, setDeletePasskeyId] = useState<string | null>(null)
  const [showSuspend, setShowSuspend] = useState(false)
  const [suspendHours, setSuspendHours] = useState(24)
  const [suspendError, setSuspendError] = useState<string | null>(null)

  type EditState = { first: string; last: string; email: string; verified: boolean; scopes: string[]; phone: string; avatar_url: string }
  const reducer = (state: EditState, action: { type: string; value?: unknown; user?: AdminUserDetail }): EditState => {
    switch (action.type) {
      case 'SET_FIRST': return { ...state, first: action.value as string }
      case 'SET_LAST': return { ...state, last: action.value as string }
      case 'SET_EMAIL': return { ...state, email: action.value as string }
      case 'SET_VERIFIED': return { ...state, verified: action.value as boolean }
      case 'SET_PHONE': return { ...state, phone: action.value as string }
      case 'SET_AVATAR': return { ...state, avatar_url: action.value as string }
      case 'ADD_SCOPE': return { ...state, scopes: [...state.scopes, action.value as string] }
      case 'REMOVE_SCOPE': return { ...state, scopes: state.scopes.filter(s => s !== action.value) }
      case 'INIT': {
        const u = action.user
        return {
          first: u?.first_name ?? '',
          last: u?.last_name ?? '',
          email: u?.email ?? '',
          verified: u?.email_verified ?? false,
          scopes: u?.scopes ? [...u.scopes] : [],
          phone: u?.phone ?? '',
          avatar_url: u?.avatar_url ?? '',
        }
      }
      default: return state
    }
  }

  const [edit, dispatch] = useReducer(reducer, { first: '', last: '', email: '', verified: false, scopes: [], phone: '', avatar_url: '' })
  const [newScope, setNewScope] = useState('')
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const [showSetPassword, setShowSetPassword] = useState(false)
  const [setPasswordForm, setSetPasswordForm] = useState({ password: '', requireChange: false })
  const [setPasswordError, setSetPasswordError] = useState<string | null>(null)
  const [confirmAction, setConfirmAction] = useState<string | null>(null)
  const [confirming, setConfirming] = useState(false)

  useEffect(() => { if (user) dispatch({ type: 'INIT', user }) }, [user])

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
    setSaving(true); setFormError(null)
    try {
      const payload: Record<string, unknown> = {
        first_name: edit.first || null,
        last_name: edit.last || null,
        email_verified: edit.verified,
        scopes: edit.scopes,
      }
      if (edit.email !== user?.email) payload.email = edit.email || null
      if (edit.phone !== (user?.phone ?? '')) payload.phone = edit.phone || null
      if (edit.avatar_url !== (user?.avatar_url ?? '')) payload.avatar_url = edit.avatar_url || null
      await api.put(`/api/admin/users/${userId}`, payload)
      notify.success('User updated.')
      queryClient.invalidateQueries({ queryKey: ['user-detail', userId] })
      queryClient.invalidateQueries({ queryKey: ['admin-users'] })
      onUserUpdated()
    } catch (e) {
      setFormError(e instanceof Error ? e.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  const handleSetPassword = async () => {
    setSaving(true); setSetPasswordError(null)
    try {
      await api.post(`/api/admin/users/${userId}/set-password`, setPasswordForm)
      setShowSetPassword(false)
      setSetPasswordForm({ password: '', requireChange: false })
      setSetPasswordError(null)
      notify.success('Password set successfully.')
      queryClient.invalidateQueries({ queryKey: ['user-detail', userId] })
    } catch (e) {
      setSetPasswordError(e instanceof Error ? e.message : 'Failed to set password')
    } finally {
      setSaving(false)
    }
  }

  const handleConfirmAction = async () => {
    if (!confirmAction || confirming) return
    setFormError(null)
    setConfirming(true)
    try {
      if (confirmAction === 'revoke-all-sessions') {
        await api.post(`/api/admin/users/${userId}/sessions/revoke-all`)
        const currentUser = useAuthStore.getState().user
        if (currentUser && currentUser.id === userId) {
          useAuthStore.getState().logout()
          window.location.assign('/auth/login')
          return
        }
      } else if (confirmAction === 'regenerate-backup-codes') {
        const resp = await api.post<{ backup_codes: string[] }>(`/api/admin/users/${userId}/regenerate-backup-codes`)
        setBackupCodes(resp.backup_codes)
      } else if (confirmAction === 'unsuspend') {
        await api.post(`/api/admin/users/${userId}/unsuspend`)
      } else {
        await api.post(`/api/admin/users/${userId}/${confirmAction}`)
      }
      notify.success(getActionSuccessMessage(confirmAction))
      queryClient.invalidateQueries({ queryKey: ['user-detail', userId] })
      queryClient.invalidateQueries({ queryKey: ['admin-users'] })
      queryClient.invalidateQueries({ queryKey: ['user-sessions', userId] })
      onUserUpdated()
    } catch (e) {
      setFormError(e instanceof Error ? e.message : 'Action failed')
    } finally {
      setConfirmAction(null)
      setConfirming(false)
    }
  }

  const handleRevokeSession = async () => {
    if (!revokeSessionId) return
    try {
      await api.post(`/api/admin/tokens/refresh/${revokeSessionId}/revoke`)
      setRevokeSessionId(null)
      notify.success('Session revoked.')
      refetchSessions()
      queryClient.invalidateQueries({ queryKey: ['user-sessions', userId] })
    } catch (e) {
      notify.error(e instanceof Error ? e.message : 'Failed to revoke session')
    }
  }

  const handleSuspend = async () => {
    setSaving(true); setSuspendError(null)
    try {
      await api.post(`/api/admin/users/${userId}/suspend`, { duration_hours: suspendHours })
      setShowSuspend(false)
      setSuspendError(null)
      notify.success('User suspended.')
      queryClient.invalidateQueries({ queryKey: ['user-detail', userId] })
      queryClient.invalidateQueries({ queryKey: ['admin-users'] })
      onUserUpdated()
    } catch (e) {
      setSuspendError(e instanceof Error ? e.message : 'Failed to suspend')
    } finally {
      setSaving(false)
    }
  }

  const handleExport = async () => {
    try {
      const data = await api.get<Record<string, unknown>>(`/api/admin/users/${userId}/export`)
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `user-${user?.email ?? userId}-export.json`
      a.click()
      URL.revokeObjectURL(url)
      notify.success('User data exported.')
    } catch (e) {
      notify.error(e instanceof Error ? e.message : 'Failed to export')
    }
  }

  const handleDeletePasskey = async () => {
    if (!deletePasskeyId) return
    try {
      await api.delete(`/api/admin/users/${userId}/passkeys/${deletePasskeyId}`)
      setDeletePasskeyId(null)
      notify.success('Passkey removed.')
      queryClient.invalidateQueries({ queryKey: ['user-passkeys', userId] })
      queryClient.invalidateQueries({ queryKey: ['user-detail', userId] })
    } catch (e) {
      notify.error(e instanceof Error ? e.message : 'Failed to delete passkey')
    }
  }

  function getActionSuccessMessage(action: string): string {
    const messages: Record<string, string> = {
      'send-password-reset': 'Password reset email sent.',
      'expire-password': 'Password expired successfully.',
      'unlock': 'Account unlocked successfully.',
      'reset-failed-attempts': 'Failed attempts reset.',
      'revoke-all-sessions': 'All sessions revoked.',
      'disable-mfa': 'MFA disabled.',
      'reset-mfa': 'MFA reset.',
      'regenerate-backup-codes': 'Backup codes regenerated.',
      'unsuspend': 'Suspension removed.',
    }
    return messages[action] || 'Action completed.'
  }

  function getActionTitle(action: string): string {
    const titles: Record<string, string> = {
      'send-password-reset': 'Send Password Reset',
      'expire-password': 'Expire Password',
      'unlock': 'Unlock Account',
      'reset-failed-attempts': 'Reset Failed Attempts',
      'revoke-all-sessions': 'Revoke All Sessions',
      'disable-mfa': 'Disable MFA',
      'reset-mfa': 'Reset MFA',
      'regenerate-backup-codes': 'Regenerate Backup Codes',
      'unsuspend': 'Remove Suspension',
    }
    return titles[action] || ''
  }

  function getActionMessage(action: string): string {
    const messages: Record<string, string> = {
      'send-password-reset': 'Send a password reset email to this user?',
      'expire-password': 'Force this user to change their password on next login?',
      'unlock': 'Unlock this account and reset failed login attempts?',
      'reset-failed-attempts': 'Reset the failed login counter without unlocking the account?',
      'revoke-all-sessions': 'Revoke all active sessions for this user? They will be logged out of all devices.',
      'disable-mfa': 'Disable MFA for this user? They will need to re-enroll to use MFA again.',
      'reset-mfa': 'Reset MFA and delete backup codes for this user?',
      'regenerate-backup-codes': 'Replace existing backup codes with new ones? Old codes will stop working.',
      'unsuspend': 'Remove suspension for this user? They will be able to log in again.',
    }
    return messages[action] || ''
  }

  const isLocked = user?.locked_until ? new Date(user.locked_until) > new Date() : false
  const isSuspended = user?.suspended_until ? new Date(user.suspended_until) > new Date() : false

  const initials = `${user?.first_name?.[0] ?? ''}${user?.last_name?.[0] ?? ''}`.toUpperCase() || '?'

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50 animate-fade-in" onClick={onClose} aria-hidden />
      <div
        ref={drawerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="user-drawer-title"
        className="relative z-10 flex w-full flex-col bg-surface-1 border-l border-surface-2 shadow-glow-violet animate-slide-in-right sm:max-w-lg md:max-w-2xl lg:max-w-4xl xl:max-w-5xl 2xl:max-w-6xl"
        data-testid="user-detail-drawer"
      >
        {/* Sticky header */}
        <div className="sticky top-0 z-20 flex items-center gap-3 border-b border-surface-2 bg-surface-1/95 px-6 py-4 backdrop-blur">
          <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-violet/20 text-sm font-bold text-brand-violet">{initials}</span>
          <div className="min-w-0 flex-1">
            <h2 id="user-drawer-title" className="truncate text-base font-semibold text-text-primary">
              {user?.first_name} {user?.last_name}
            </h2>
            <p className="truncate text-xs text-text-muted">{user?.email}</p>
          </div>
          <button
            ref={closeButtonRef}
            onClick={onClose}
            aria-label="Close user detail"
            className="shrink-0 rounded-lg p-1.5 text-base leading-none text-text-muted hover:text-text-secondary hover:bg-surface-2"
          >
            ✕
          </button>
        </div>

        {isLoading ? <div className="flex-1 overflow-y-auto p-6"><div className="py-8 text-center"><Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" /></div></div>
        : !user ? <div className="flex-1 overflow-y-auto p-6"><p className="text-sm text-text-muted text-center py-8">Could not load user details.</p></div>
        : (
          <Tabs value={activeTab} onValueChange={setActiveTab} className="flex min-h-0 flex-1 flex-col">
            {/* Tab strip (sticky under header) */}
            <TabsList className="sticky top-[73px] z-10 flex h-12 w-full justify-start gap-1 overflow-x-auto whitespace-nowrap border-b border-surface-2 bg-surface-1/95 px-2 backdrop-blur">
              <TabsTrigger value="profile" data-testid="user-tab-profile" className="data-[state=active]:border-b-2 data-[state=active]:border-brand-violet data-[state=active]:text-brand-violet rounded-none bg-transparent px-3 py-1 text-sm">Profile</TabsTrigger>
              <TabsTrigger value="sessions" data-testid="user-tab-sessions" className="data-[state=active]:border-b-2 data-[state=active]:border-brand-violet data-[state=active]:text-brand-violet rounded-none bg-transparent px-3 py-1 text-sm">
                Sessions{sessionsData ? ` (${sessionsData.total})` : ''}
              </TabsTrigger>
              <TabsTrigger value="passkeys" data-testid="user-tab-passkeys" className="data-[state=active]:border-b-2 data-[state=active]:border-brand-violet data-[state=active]:text-brand-violet rounded-none bg-transparent px-3 py-1 text-sm">
                Passkeys{passkeys ? ` (${passkeys.length})` : ''}
              </TabsTrigger>
              <TabsTrigger value="history" data-testid="user-tab-history" className="data-[state=active]:border-b-2 data-[state=active]:border-brand-violet data-[state=active]:text-brand-violet rounded-none bg-transparent px-3 py-1 text-sm">
                Login History{loginHistory ? ` (${loginHistory.total})` : ''}
              </TabsTrigger>
              <TabsTrigger value="events" data-testid="user-tab-events" className="data-[state=active]:border-b-2 data-[state=active]:border-brand-violet data-[state=active]:text-brand-violet rounded-none bg-transparent px-3 py-1 text-sm">
                Security Events{securityEvents ? ` (${securityEvents.total})` : ''}
              </TabsTrigger>
              <TabsTrigger value="apps" data-testid="user-tab-apps" className="data-[state=active]:border-b-2 data-[state=active]:border-brand-violet data-[state=active]:text-brand-violet rounded-none bg-transparent px-3 py-1 text-sm">
                Connected Apps{oauthConsents ? ` (${oauthConsents.length})` : ''}
              </TabsTrigger>
              <TabsTrigger value="admin-log" data-testid="user-tab-admin-log" className="data-[state=active]:border-b-2 data-[state=active]:border-brand-violet data-[state=active]:text-brand-violet rounded-none bg-transparent px-3 py-1 text-sm">
                Admin Log{adminActions ? ` (${adminActions.total})` : ''}
              </TabsTrigger>
              {demoMeta.demo_mode && (
                <TabsTrigger value="demo-inbox" data-testid="user-tab-demo-inbox" className="data-[state=active]:border-b-2 data-[state=active]:border-brand-violet data-[state=active]:text-brand-violet rounded-none bg-transparent px-3 py-1 text-sm">
                  Demo Inbox
                </TabsTrigger>
              )}
            </TabsList>

            {/* Scrollable body */}
            <div className="flex-1 overflow-y-auto">
              {formError && (
                <div className="px-6 pt-4">
                  <Banner variant="error" size="sm" onDismiss={() => setFormError(null)} data-testid="user-drawer-form-error">
                    {formError}
                  </Banner>
                </div>
              )}

              <TabsContent value="profile" className="m-0 focus-visible:outline-none">
                <div className="grid grid-cols-1 gap-6 p-6 lg:grid-cols-[260px_1fr]">
                  {/* Aside — sticky within the scroll container on lg+ */}
                  <aside className="space-y-4 lg:sticky lg:top-0 lg:self-start">
                    <div className="flex flex-col items-center rounded-2xl border border-surface-2 bg-surface-1 p-5 text-center">
                      <span className="inline-flex h-20 w-20 items-center justify-center rounded-full bg-brand-violet/20 text-2xl font-bold text-brand-violet">{initials}</span>
                      <p className="mt-3 text-sm font-semibold text-text-primary">{user.first_name} {user.last_name}</p>
                      <p className="text-xs text-text-muted">{user.email}</p>
                      <div className="mt-3 flex flex-wrap justify-center gap-1.5">
                        <span className={`inline-flex items-center gap-1 rounded-lg px-2 py-0.5 text-[11px] font-medium ${user.is_active ? 'bg-semantic-success/10 text-semantic-success' : 'bg-semantic-error/10 text-semantic-error'}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${user.is_active ? 'bg-semantic-success' : 'bg-semantic-error'}`} />
                          {user.is_active ? 'Active' : 'Inactive'}
                        </span>
                        {user.mfa_enabled && <span className="inline-flex rounded-lg bg-brand-violet/10 px-2 py-0.5 text-[11px] font-medium text-brand-violet">MFA</span>}
                        {isSuspended && <span className="inline-flex rounded-lg bg-semantic-warning/10 px-2 py-0.5 text-[11px] font-medium text-semantic-warning">Suspended</span>}
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="rounded-lg bg-surface-1 border border-surface-2 p-2"><p className="text-text-muted">Logins</p><p className="text-text-primary font-medium">{user.login_count ?? 0}</p></div>
                      <div className="rounded-lg bg-surface-1 border border-surface-2 p-2"><p className="text-text-muted">Failed</p><p className="text-text-primary font-medium">{user.failed_login_count ?? 0}</p></div>
                      <div className="rounded-lg bg-surface-1 border border-surface-2 p-2 col-span-2"><p className="text-text-muted">Created</p><p className="text-text-primary font-medium">{user.created_at ? formatDateTime(user.created_at) : '-'}</p></div>
                      <div className="rounded-lg bg-surface-1 border border-surface-2 p-2 col-span-2"><p className="text-text-muted">Last login</p><p className="text-text-primary font-medium">{user.last_login ? formatDateTime(user.last_login) : '-'}</p></div>
                    </div>
                  </aside>

                  {/* Main column */}
                  <div className="space-y-4">
                    <div className="rounded-xl border border-surface-2 bg-surface-1 p-4 space-y-3">
                      <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Edit Profile</h3>
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                        <div><label className="mb-1 block text-xs text-text-muted">First name</label><input value={edit.first} onChange={e => dispatch({ type: 'SET_FIRST', value: e.target.value })} className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary focus:border-brand-violet focus:outline-none" /></div>
                        <div><label className="mb-1 block text-xs text-text-muted">Last name</label><input value={edit.last} onChange={e => dispatch({ type: 'SET_LAST', value: e.target.value })} className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary focus:border-brand-violet focus:outline-none" /></div>
                      </div>
                      <div><label className="mb-1 block text-xs text-text-muted">Email</label><input value={edit.email} onChange={e => dispatch({ type: 'SET_EMAIL', value: e.target.value })} type="email" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary focus:border-brand-violet focus:outline-none" /></div>
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                        <div><label className="mb-1 block text-xs text-text-muted">Phone</label><input value={edit.phone} onChange={e => dispatch({ type: 'SET_PHONE', value: e.target.value })} placeholder="+1234567890" className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary focus:border-brand-violet focus:outline-none" /></div>
                        <div><label className="mb-1 block text-xs text-text-muted">Avatar URL</label><input value={edit.avatar_url} onChange={e => dispatch({ type: 'SET_AVATAR', value: e.target.value })} placeholder="https://..." className="w-full rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-sm text-text-primary focus:border-brand-violet focus:outline-none" /></div>
                      </div>
                      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={edit.verified} onChange={e => dispatch({ type: 'SET_VERIFIED', value: e.target.checked })} className="rounded border-surface-2 text-brand-violet focus:ring-brand-violet" /><span className="text-text-primary">Email verified</span></label>
                    </div>

                    <div className="rounded-xl border border-surface-2 bg-surface-1 p-4 space-y-3">
                      <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Scopes</h3>
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

                    {!user.is_federated && (
                      <div className="rounded-xl border border-surface-2 bg-surface-1 p-4 space-y-3">
                        <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Password &amp; Credentials</h3>
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                          <button onClick={() => setShowSetPassword(true)} data-testid="set-password-btn" className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-medium text-text-primary hover:bg-surface-2 text-left">
                            Set Password
                          </button>
                          <button onClick={() => setConfirmAction('send-password-reset')} data-testid="send-password-reset-btn" className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-medium text-text-primary hover:bg-surface-2 text-left">
                            Send Password Reset
                          </button>
                          {!user.password_expired && (
                            <button onClick={() => setConfirmAction('expire-password')} data-testid="expire-password-btn" className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-medium text-text-primary hover:bg-surface-2 text-left">
                              Expire Password
                            </button>
                          )}
                          {isLocked && (
                            <button onClick={() => setConfirmAction('unlock')} data-testid="unlock-account-btn" className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-medium text-text-primary hover:bg-surface-2 text-left">
                              Unlock Account
                            </button>
                          )}
                          {user.failed_login_count > 0 && (
                            <button onClick={() => setConfirmAction('reset-failed-attempts')} data-testid="reset-attempts-btn" className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-medium text-text-primary hover:bg-surface-2 text-left">
                              Reset Failed Attempts
                            </button>
                          )}
                        </div>
                      </div>
                    )}

                    {!user.is_federated && (
                      <div className="rounded-xl border border-surface-2 bg-surface-1 p-4 space-y-3">
                        <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">MFA</h3>
                        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                          {user.mfa_enabled && (
                            <button onClick={() => setConfirmAction('disable-mfa')} data-testid="disable-mfa-btn" className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-medium text-text-primary hover:bg-surface-2 text-left">
                              <Shield size={12} className="inline mr-1.5" />Disable MFA
                            </button>
                          )}
                          {user.mfa_enabled && (
                            <button onClick={() => setConfirmAction('reset-mfa')} data-testid="reset-mfa-btn" className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-medium text-text-primary hover:bg-surface-2 text-left">
                              <ShieldOff size={12} className="inline mr-1.5" />Reset MFA
                            </button>
                          )}
                          {user.mfa_enabled && (
                            <button onClick={() => setConfirmAction('regenerate-backup-codes')} data-testid="regenerate-codes-btn" className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-medium text-text-primary hover:bg-surface-2 text-left">
                              <RefreshCw size={12} className="inline mr-1.5" />Regenerate Backup Codes
                            </button>
                          )}
                          {!user.mfa_enabled && (
                            <p className="col-span-full text-xs text-text-muted italic py-1">MFA is not enabled</p>
                          )}
                        </div>
                      </div>
                    )}

                    {user.is_federated && (
                      <div className="rounded-xl border border-surface-2 bg-surface-1 p-4">
                        <p className="text-xs text-text-muted italic">
                          Credentials and MFA for this account are managed by an external identity provider.
                        </p>
                      </div>
                    )}

                    <div className="rounded-xl border border-surface-2 bg-surface-1 p-4 space-y-3">
                      <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Account Status</h3>
                      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                        {isSuspended ? (
                          <button onClick={() => setConfirmAction('unsuspend')} data-testid="unsuspend-btn" className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-medium text-text-primary hover:bg-surface-2 text-left">
                            <Clock size={12} className="inline mr-1.5" />Remove Suspension (until {formatDateTime(user.suspended_until!)})
                          </button>
                        ) : (
                          <button onClick={() => setShowSuspend(true)} data-testid="suspend-btn" className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-xs font-medium text-text-primary hover:bg-surface-2 text-left">
                            <Ban size={12} className="inline mr-1.5" />Suspend User
                          </button>
                        )}
                      </div>
                    </div>

                    {keys && keys.length > 0 && (
                      <div className="rounded-xl border border-surface-2 bg-surface-1 p-4 space-y-3">
                        <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">API Keys ({keys.length})</h3>
                        <div className="space-y-1.5">
                          {(keys as Array<Record<string, unknown>>).map(k => (
                            <div key={k.key_id as string} className="rounded-lg bg-surface-2 px-3 py-2 text-xs">
                              <span className="text-text-primary font-medium">{k.name as string}</span>
                              <code className="ml-2 text-text-muted">{((k.key_prefix ?? (k.key_id as string)?.slice(0,8)) as string)}...</code>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="sessions" className="m-0 focus-visible:outline-none">
                <div className="p-6 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Active Sessions</h3>
                    {(sessionsData?.items ?? []).length > 0 && (
                      <button onClick={() => setConfirmAction('revoke-all-sessions')} data-testid="revoke-all-sessions-btn" className="flex items-center gap-1 rounded-lg bg-semantic-error/10 px-2 py-1 text-[11px] font-medium text-semantic-error hover:bg-semantic-error/20">
                        <LogOut size={12} />Revoke All
                      </button>
                    )}
                  </div>
                  {!sessionsData ? (
                    <div className="py-4 text-center"><Loader2 className="mx-auto h-4 w-4 animate-spin text-brand-violet" /></div>
                  ) : sessionsData.items.length === 0 ? (
                    <p className="text-xs text-text-muted italic py-2">No active sessions</p>
                  ) : (
                    <div className="overflow-x-auto rounded-lg border border-surface-2">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-surface-2 bg-surface-2/50">
                            <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Client</th>
                            <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Created</th>
                            <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Last Used</th>
                            <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">IP</th>
                            <th className="px-3 py-2" />
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-surface-2">
                          {sessionsData.items.map(s => (
                            <tr key={s.id} className="hover:bg-surface-2/30">
                              <td className="px-3 py-2 text-text-primary font-medium">{s.client_id}</td>
                              <td className="px-3 py-2 text-text-muted">{formatDateTime(s.created_at)}</td>
                              <td className="px-3 py-2 text-text-muted">{s.last_used_at ? formatDateTime(s.last_used_at) : '-'}</td>
                              <td className="px-3 py-2 text-text-muted font-mono">{s.ip_address ?? '-'}</td>
                              <td className="px-3 py-2 text-right">
                                <button onClick={() => setRevokeSessionId(s.id)} data-testid={`revoke-session-${s.id}`} className="rounded p-1 text-text-muted hover:text-semantic-error" title="Revoke session">
                                  <Trash2 size={14} />
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </TabsContent>

              <TabsContent value="passkeys" className="m-0 focus-visible:outline-none">
                <div className="p-6 space-y-3">
                  <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">Passkeys {passkeys ? `(${passkeys.length})` : ''}</h3>
                  {!passkeys ? (
                    <div className="py-4 text-center"><Loader2 className="mx-auto h-4 w-4 animate-spin text-brand-violet" /></div>
                  ) : passkeys.length === 0 ? (
                    <div className="flex flex-col items-center py-8 text-center rounded-xl border border-surface-2 bg-surface-1">
                      <Fingerprint size={32} className="text-text-muted mb-2 opacity-40" />
                      <p className="text-sm text-text-muted italic">No passkeys registered</p>
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      {passkeys.map(pk => (
                        <div key={pk.credential_id} className="flex items-center justify-between rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-sm">
                          <div className="flex items-center gap-3 min-w-0">
                            {pk.device_type === 'phone' ? <Smartphone size={16} className="shrink-0 text-text-muted" />
                              : pk.device_type === 'computer' ? <Monitor size={16} className="shrink-0 text-text-muted" />
                              : <KeyRound size={16} className="shrink-0 text-text-muted" />}
                            <div className="min-w-0">
                              <p className="text-text-primary truncate font-medium">{pk.name}</p>
                              <p className="text-xs text-text-muted">
                                {formatDateTime(pk.created_at)}
                                {pk.last_used_at ? ` · Last used ${formatDateTime(pk.last_used_at)}` : ''}
                                {pk.transports?.length ? ` · ${pk.transports.join(', ')}` : ''}
                              </p>
                            </div>
                          </div>
                          <button onClick={() => setDeletePasskeyId(pk.credential_id)} data-testid={`delete-passkey-${pk.credential_id}`} className="shrink-0 rounded p-1 text-text-muted hover:text-semantic-error ml-2" title="Delete passkey">
                            <Trash2 size={14} />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </TabsContent>

              <TabsContent value="history" className="m-0 focus-visible:outline-none">
                <div className="p-6 space-y-3">
                  <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider flex items-center gap-1.5">
                    <History size={12} />Login History {loginHistory ? `(${loginHistory.total})` : ''}
                  </h3>
                  {!loginHistory ? (
                    <div className="py-3 text-center"><Loader2 className="mx-auto h-4 w-4 animate-spin text-brand-violet" /></div>
                  ) : loginHistory.items.length === 0 ? (
                    <p className="text-xs text-text-muted italic py-2">No login history</p>
                  ) : (
                    <div className="overflow-x-auto max-h-96 overflow-y-auto rounded-lg border border-surface-2">
                      <table className="w-full text-sm">
                        <thead className="sticky top-0 bg-surface-1"><tr className="border-b border-surface-2">
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Status</th>
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Time</th>
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">IP</th>
                        </tr></thead>
                        <tbody className="divide-y divide-surface-2">
                          {loginHistory.items.slice(0, 20).map(h => (
                            <tr key={h.id} className="hover:bg-surface-2/30">
                              <td className="px-3 py-2">
                                <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium ${h.success ? 'bg-semantic-success/10 text-semantic-success' : 'bg-semantic-error/10 text-semantic-error'}`}>
                                  {h.success ? 'OK' : 'FAIL'}
                                </span>
                              </td>
                              <td className="px-3 py-2 text-text-muted whitespace-nowrap">{formatDateTime(h.timestamp)}</td>
                              <td className="px-3 py-2 text-text-muted font-mono">{h.ip_address ?? '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </TabsContent>

              <TabsContent value="events" className="m-0 focus-visible:outline-none">
                <div className="p-6 space-y-3">
                  <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider flex items-center gap-1.5">
                    <AlertTriangle size={12} />Security Events {securityEvents ? `(${securityEvents.total})` : ''}
                  </h3>
                  {!securityEvents ? (
                    <div className="py-3 text-center"><Loader2 className="mx-auto h-4 w-4 animate-spin text-brand-violet" /></div>
                  ) : securityEvents.items.length === 0 ? (
                    <p className="text-xs text-text-muted italic py-2">No security events</p>
                  ) : (
                    <div className="overflow-x-auto max-h-96 overflow-y-auto rounded-lg border border-surface-2">
                      <table className="w-full text-sm">
                        <thead className="sticky top-0 bg-surface-1"><tr className="border-b border-surface-2">
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Event</th>
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Time</th>
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Description</th>
                        </tr></thead>
                        <tbody className="divide-y divide-surface-2">
                          {securityEvents.items.slice(0, 20).map(e => (
                            <tr key={e.id} className="hover:bg-surface-2/30">
                              <td className="px-3 py-2">
                                <span className="rounded bg-brand-violet/10 px-1.5 py-0.5 font-mono text-xs text-brand-violet">
                                  {e.event_type.replace(/_/g, ' ')}
                                </span>
                              </td>
                              <td className="px-3 py-2 text-text-muted whitespace-nowrap">{formatDateTime(e.timestamp)}</td>
                              <td className="px-3 py-2 text-text-muted truncate max-w-[280px]">{e.description ?? '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </TabsContent>

              <TabsContent value="apps" className="m-0 focus-visible:outline-none">
                <div className="p-6 space-y-3">
                  <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider flex items-center gap-1.5">
                    <Globe size={12} />Connected Apps {oauthConsents ? `(${oauthConsents.length})` : ''}
                  </h3>
                  {!oauthConsents ? (
                    <div className="py-3 text-center"><Loader2 className="mx-auto h-4 w-4 animate-spin text-brand-violet" /></div>
                  ) : oauthConsents.length === 0 ? (
                    <p className="text-xs text-text-muted italic py-2">No connected apps</p>
                  ) : (
                    <div className="space-y-1.5">
                      {oauthConsents.filter(c => !c.revoked).map(c => (
                        <div key={c.consent_id} className="flex items-center justify-between rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-sm">
                          <div className="min-w-0">
                            <p className="text-text-primary font-medium">{c.client_name}</p>
                            <p className="text-xs text-text-muted">
                              {c.scopes.join(', ')} · {formatDateTime(c.granted_at)}
                            </p>
                          </div>
                        </div>
                      ))}
                      {oauthConsents.filter(c => c.revoked).length > 0 && (
                        <>
                          <p className="text-xs text-text-muted pt-2 pb-1 uppercase tracking-wider">Revoked</p>
                          {oauthConsents.filter(c => c.revoked).map(c => (
                            <div key={c.consent_id} className="flex items-center justify-between rounded-lg border border-surface-2 bg-surface-1 px-3 py-2 text-sm opacity-60">
                              <div className="min-w-0">
                                <p className="text-text-primary font-medium">{c.client_name}</p>
                                <p className="text-xs text-text-muted">Revoked {c.revoked_at ? formatDateTime(c.revoked_at) : ''}</p>
                              </div>
                            </div>
                          ))}
                        </>
                      )}
                    </div>
                  )}
                </div>
              </TabsContent>

              <TabsContent value="admin-log" className="m-0 focus-visible:outline-none">
                <div className="p-6 space-y-3">
                  <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider flex items-center gap-1.5">
                    <History size={12} />Admin Actions {adminActions ? `(${adminActions.total})` : ''}
                  </h3>
                  {!adminActions ? (
                    <div className="py-3 text-center"><Loader2 className="mx-auto h-4 w-4 animate-spin text-brand-violet" /></div>
                  ) : adminActions.items.length === 0 ? (
                    <p className="text-xs text-text-muted italic py-2">No admin actions</p>
                  ) : (
                    <div className="overflow-x-auto max-h-96 overflow-y-auto rounded-lg border border-surface-2">
                      <table className="w-full text-sm">
                        <thead className="sticky top-0 bg-surface-1"><tr className="border-b border-surface-2">
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Action</th>
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Admin</th>
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-muted">Time</th>
                        </tr></thead>
                        <tbody className="divide-y divide-surface-2">
                          {adminActions.items.slice(0, 20).map(a => (
                            <tr key={a.id} className="hover:bg-surface-2/30">
                              <td className="px-3 py-2">
                                <span className="rounded bg-brand-violet/10 px-1.5 py-0.5 font-mono text-xs text-brand-violet">
                                  {a.action_type.replace(/_/g, ' ')}
                                </span>
                              </td>
                              <td className="px-3 py-2 text-text-muted">{a.admin_email}</td>
                              <td className="px-3 py-2 text-text-muted whitespace-nowrap">{formatDateTime(a.timestamp)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </TabsContent>
              {demoMeta.demo_mode && (
                <TabsContent value="demo-inbox" className="m-0 focus-visible:outline-none">
                  <div className="p-6 space-y-3">
                    <h3 className="text-xs font-semibold text-text-muted uppercase tracking-wider">
                      Emails captured for this user (demo mode)
                    </h3>
                    <DemoInbox email={user.email} />
                  </div>
                </TabsContent>
              )}
            </div>

            {/* Sticky footer */}
            <div className="sticky bottom-0 z-10 flex shrink-0 gap-2 border-t border-surface-2 bg-surface-1/95 px-6 py-3 backdrop-blur">
              <button onClick={handleExport} className="flex items-center justify-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-4 py-2 text-sm font-semibold text-text-primary hover:bg-surface-2">
                <Download size={16} />Export
              </button>
              <button onClick={handleSave} disabled={saving} className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed">
                {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Save Changes
              </button>
            </div>
          </Tabs>
        )}

          {showSetPassword && (
            <div className="fixed inset-0 z-[60] flex items-center justify-center">
              <div className="absolute inset-0 bg-black/50" onClick={() => { setShowSetPassword(false); setSetPasswordError('') }} />
              <div className="relative z-10 w-full max-w-sm rounded-2xl border border-surface-2 bg-surface-1 p-5 space-y-4 shadow-glow-violet">
                <h4 className="text-sm font-semibold text-text-primary">Set Password</h4>
                <div>
                  <label className="mb-1 block text-xs text-text-muted">New password</label>
                  <input type="password" value={setPasswordForm.password} onChange={e => { setSetPasswordForm({ ...setPasswordForm, password: e.target.value }); if (setPasswordError) setSetPasswordError('') }} data-testid="set-password-input" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none" />
                  {setPasswordForm.password.length > 0 && (
                    <ul className="mt-2 space-y-1" data-testid="set-password-rules">
                      {PASSWORD_RULES.map((rule) => {
                        const ok = rule.test(setPasswordForm.password)
                        return (
                          <li key={rule.label} className={`flex items-center gap-1.5 text-[11px] ${ok ? 'text-semantic-success' : 'text-text-muted'}`}>
                            {ok ? <Check size={11} /> : <span className="inline-block h-1.5 w-1.5 rounded-full bg-text-muted" />}
                            <span>{rule.label}</span>
                          </li>
                        )
                      })}
                    </ul>
                  )}
                </div>
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={setPasswordForm.requireChange} onChange={e => setSetPasswordForm({ ...setPasswordForm, requireChange: e.target.checked })} className="rounded border-surface-2 text-brand-violet focus:ring-brand-violet" />
                  <span className="text-text-primary">Require change at next login</span>
                </label>
                {setPasswordError && (
                  <Banner
                    variant="error"
                    size="sm"
                    onDismiss={() => setSetPasswordError(null)}
                    data-testid="set-password-error"
                  >
                    {setPasswordError}
                  </Banner>
                )}
                <div className="flex gap-3 pt-1">
                  <button onClick={() => { setShowSetPassword(false); setSetPasswordForm({ password: '', requireChange: false }); setSetPasswordError(null) }} className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-xs text-text-secondary hover:bg-surface-2">Cancel</button>
                  <button onClick={handleSetPassword} disabled={saving || !setPasswordForm.password || !passwordIsValid(setPasswordForm.password)} data-testid="set-password-submit" className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-xs font-semibold text-white shadow-glow-violet disabled:opacity-50 disabled:cursor-not-allowed">
                    {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
                    Set Password
                  </button>
                </div>
              </div>
            </div>
          )}

          <ConfirmDialog open={confirmAction === 'send-password-reset'} title={getActionTitle('send-password-reset')} message={getActionMessage('send-password-reset')} confirmLabel="Send" variant="default" loading={confirming} onConfirm={handleConfirmAction} onCancel={() => setConfirmAction(null)} />
          <ConfirmDialog open={confirmAction === 'expire-password'} title={getActionTitle('expire-password')} message={getActionMessage('expire-password')} confirmLabel="Expire" variant="danger" loading={confirming} onConfirm={handleConfirmAction} onCancel={() => setConfirmAction(null)} />
          <ConfirmDialog open={confirmAction === 'unlock'} title={getActionTitle('unlock')} message={getActionMessage('unlock')} confirmLabel="Unlock" variant="default" loading={confirming} onConfirm={handleConfirmAction} onCancel={() => setConfirmAction(null)} />
          <ConfirmDialog open={confirmAction === 'reset-failed-attempts'} title={getActionTitle('reset-failed-attempts')} message={getActionMessage('reset-failed-attempts')} confirmLabel="Reset" variant="default" loading={confirming} onConfirm={handleConfirmAction} onCancel={() => setConfirmAction(null)} />
          <ConfirmDialog open={confirmAction === 'revoke-all-sessions'} title={getActionTitle('revoke-all-sessions')} message={getActionMessage('revoke-all-sessions')} confirmLabel="Revoke All" variant="danger" loading={confirming} onConfirm={handleConfirmAction} onCancel={() => setConfirmAction(null)} />
          <ConfirmDialog open={confirmAction === 'disable-mfa'} title={getActionTitle('disable-mfa')} message={getActionMessage('disable-mfa')} confirmLabel="Disable" variant="danger" loading={confirming} onConfirm={handleConfirmAction} onCancel={() => setConfirmAction(null)} />
          <ConfirmDialog open={confirmAction === 'reset-mfa'} title={getActionTitle('reset-mfa')} message={getActionMessage('reset-mfa')} confirmLabel="Reset MFA" variant="danger" loading={confirming} onConfirm={handleConfirmAction} onCancel={() => setConfirmAction(null)} />
          <ConfirmDialog open={confirmAction === 'regenerate-backup-codes'} title={getActionTitle('regenerate-backup-codes')} message={getActionMessage('regenerate-backup-codes')} confirmLabel="Regenerate" variant="default" loading={confirming} onConfirm={handleConfirmAction} onCancel={() => setConfirmAction(null)} />
          <ConfirmDialog open={confirmAction === 'unsuspend'} title={getActionTitle('unsuspend')} message={getActionMessage('unsuspend')} confirmLabel="Remove Suspension" variant="default" loading={confirming} onConfirm={handleConfirmAction} onCancel={() => setConfirmAction(null)} />
          <ConfirmDialog open={!!revokeSessionId} title="Revoke Session" message="Revoke this session? The user will be logged out of this device." confirmLabel="Revoke" variant="danger" onConfirm={handleRevokeSession} onCancel={() => setRevokeSessionId(null)} />
          <ConfirmDialog open={!!deletePasskeyId} title="Delete Passkey" message="Remove this passkey from the user's account?" confirmLabel="Delete" variant="danger" onConfirm={handleDeletePasskey} onCancel={() => setDeletePasskeyId(null)} />

          {backupCodes && (
            <div className="fixed inset-0 z-[60] flex items-center justify-center">
              <div className="absolute inset-0 bg-black/50" onClick={() => setBackupCodes(null)} />
              <div className="relative z-10 w-full max-w-sm rounded-2xl border border-surface-2 bg-surface-1 p-5 space-y-4 shadow-glow-violet">
                <h4 className="text-sm font-semibold text-text-primary">New Backup Codes</h4>
                <p className="text-xs text-text-muted">Share these codes with the user. Each code can only be used once.</p>
                <div className="space-y-1.5">
                  {backupCodes.map((code, i) => (
                    <div key={i} className="rounded-lg bg-surface-2 px-3 py-2 font-mono text-xs text-text-primary text-center tracking-wider">
                      {code}
                    </div>
                  ))}
                </div>
                <button onClick={() => setBackupCodes(null)} className="w-full rounded-xl bg-gradient-cta px-4 py-2 text-xs font-semibold text-white shadow-glow-violet">
                  Done
                </button>
              </div>
            </div>
          )}

          {showSuspend && (
            <div className="fixed inset-0 z-[60] flex items-center justify-center">
              <div className="absolute inset-0 bg-black/50" onClick={() => setShowSuspend(false)} />
              <div className="relative z-10 w-full max-w-sm rounded-2xl border border-surface-2 bg-surface-1 p-5 space-y-4 shadow-glow-violet">
                <h4 className="text-sm font-semibold text-text-primary">Suspend User</h4>
                <p className="text-xs text-text-muted">The user will not be able to log in for the selected duration.</p>
                <div>
                  <label className="mb-1 block text-xs text-text-muted">Duration</label>
                  <select value={suspendHours} onChange={e => { setSuspendHours(Number(e.target.value)); if (suspendError) setSuspendError('') }} className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2 text-sm text-text-primary focus:border-brand-violet focus:outline-none">
                    <option value={1}>1 hour</option>
                    <option value={6}>6 hours</option>
                    <option value={12}>12 hours</option>
                    <option value={24}>24 hours</option>
                    <option value={48}>48 hours</option>
                    <option value={72}>72 hours</option>
                    <option value={168}>7 days</option>
                    <option value={720}>30 days</option>
                  </select>
                </div>
                {suspendError && (
                  <Banner
                    variant="error"
                    size="sm"
                    onDismiss={() => setSuspendError(null)}
                    data-testid="suspend-error"
                  >
                    {suspendError}
                  </Banner>
                )}
                <div className="flex gap-3 pt-1">
                  <button onClick={() => { setShowSuspend(false); setSuspendError(null) }} className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-xs text-text-secondary hover:bg-surface-2">Cancel</button>
                  <button onClick={handleSuspend} disabled={saving} data-testid="suspend-confirm-btn" className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-semantic-error px-4 py-2 text-xs font-semibold text-white disabled:opacity-50 disabled:cursor-not-allowed">
                    {saving ? <Loader2 size={14} className="animate-spin" /> : <Ban size={14} />}
                    Suspend
                  </button>
                </div>
              </div>
            </div>
          )}
      </div>
    </div>
  )
}
