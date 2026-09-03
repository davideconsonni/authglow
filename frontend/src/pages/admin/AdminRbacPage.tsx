import { useState } from 'react'
import { Plus, Trash2, Loader2, Save, Shield, Edit } from 'lucide-react'
import { api } from '../../lib/api'
import { useApiQuery } from '../../hooks/useApi'
import { ConfirmDialog } from '../../components/shared/ConfirmDialog'
import { PageHeader } from '../../components/layout/PageHeader'
import { formatDateTime } from '../../lib/utils'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { notify } from '../../stores/toastStore'

const RBAC_ROLES_QUERY_KEY: string[] = ['admin-roles']

interface Permission {
  permission_id?: string
  name: string
  description: string
}

interface Role {
  id?: string
  role_id?: string
  name: string
  description: string
  permissions: string[]
  is_system: boolean
}

interface UserRoleAssignment {
  role_id: string
  user_email?: string
  role_name?: string
  expires_at?: string | null
}

export function AdminRbacPage() {
  useDocumentTitle('RBAC')
  const [tab, setTab] = useState<'roles' | 'permissions'>('roles')

  return (
    <div>
      <PageHeader title="Role-Based Access Control" description="Manage roles, permissions, and user assignments." />

      <div className="mb-6 flex gap-2">
        {(['roles', 'permissions'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-xl px-4 py-2 text-sm font-medium capitalize transition-colors ${
              tab === t
                ? 'bg-brand-accent text-white'
                : 'bg-surface-2 text-text-secondary hover:bg-surface-3'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === 'roles' ? <RolesTab /> : <PermissionsTab />}

      <div className="mt-12">
        <UserRoleAssignments />
      </div>
    </div>
  )
}

function RolesTab() {
  const [showCreate, setShowCreate] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [selPerms, setSelPerms] = useState<string[]>([])
  const [saving, setSaving] = useState(false)

  const { data: roles, refetch: refetchRoles, isLoading } = useApiQuery<Role[]>(
    RBAC_ROLES_QUERY_KEY,
    '/api/rbac/roles',
  )
  const roleList = Array.isArray(roles) ? roles : []

  const { data: allPerms } = useApiQuery<Permission[]>(['admin-permissions'], '/api/rbac/permissions')
  const permList = Array.isArray(allPerms) ? allPerms : []

  const resetForm = () => {
    setName('')
    setDescription('')
    setSelPerms([])
    setShowCreate(false)
    setEditId(null)
  }

  const openEdit = (r: Role) => {
    setEditId(r.role_id ?? r.id ?? null)
    setName(r.name)
    setDescription(r.description || '')
    setSelPerms(r.permissions)
    setShowCreate(true)
  }

  const handleSave = async () => {
    setSaving(true)
    try {
      if (editId) {
        await api.patch(`/api/rbac/roles/${editId}`, {
          name,
          description,
          permissions: selPerms,
        })
      } else {
        await api.post('/api/rbac/roles', {
          name,
          description,
          permissions: selPerms,
        })
      }
      resetForm()
      notify.success(editId ? 'Role updated.' : 'Role created.')
      await refetchRoles()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to save role')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.delete(`/api/rbac/roles/${deleteId}`)
      setDeleteId(null)
      notify.success('Role deleted.')
      await refetchRoles()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to delete role')
    }
  }

  const togglePerm = (permName: string) => {
    setSelPerms((p) => (p.includes(permName) ? p.filter((x) => x !== permName) : [...p, permName]))
  }

  return (
    <>
      <div className="mb-4">
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          <Plus size={16} /> Create Role
        </button>
      </div>

      {isLoading ? (
        <div className="py-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-accent" />
        </div>
      ) : roleList.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-surface-2 bg-surface-1 py-16 text-center">
          <div className="rounded-2xl bg-surface-2 p-4">
            <Shield className="h-8 w-8 text-text-muted" />
          </div>
          <h3 className="mt-4 text-lg font-semibold text-text-primary">No roles</h3>
          <p className="mt-2 max-w-sm text-sm text-text-muted">
            Create roles and assign permissions to them.
          </p>
          <button
            onClick={() => setShowCreate(true)}
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Plus size={16} />
            Create Role
          </button>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase hidden md:table-cell">Description</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase hidden md:table-cell">Permissions</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {roleList.map((r, idx) => (
                <tr key={r.role_id || r.id || idx} className="hover:bg-surface-2/50">
                  <td className="px-6 py-3">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-text-primary">{r.name}</span>
                      {r.is_system && (
                        <span className="rounded-md bg-surface-2 px-1.5 py-0.5 text-[10px] font-medium text-text-muted">
                          SYSTEM
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-3 text-sm text-text-secondary hidden md:table-cell">{r.description || '-'}</td>
                  <td className="px-6 py-3 hidden md:table-cell">
                    <div className="flex flex-wrap gap-1">
                      {r.permissions?.length > 0 ? (
                        r.permissions.map((p, i) => (
                          <span
                            key={p || i}
                            className="rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary"
                          >
                            {p}
                          </span>
                        ))
                      ) : (
                        <span className="text-xs text-text-muted">None</span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-3">
                    <div className="flex gap-2">
                      {!r.is_system && (
                        <>
                          <button
                            onClick={() => openEdit(r)}
                            className="text-text-muted hover:text-text-secondary transition-colors"
                            title="Edit role"
                          >
                            <Edit size={14} />
                          </button>
                          <button
                            onClick={() => setDeleteId(r.role_id ?? r.id ?? null)}
                            className="text-text-muted hover:text-semantic-error transition-colors"
                            title="Delete role"
                          >
                            <Trash2 size={14} />
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={resetForm} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-accent max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-text-primary">
              {editId ? 'Edit Role' : 'Create Role'}
            </h3>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Role name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="admin"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Description</label>
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Administrator role"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
              />
            </div>
            <div>
              <p className="mb-2 text-xs font-medium text-text-muted">
                Permissions ({selPerms.length} selected)
              </p>
              <div className="max-h-48 overflow-y-auto space-y-1 rounded-xl border border-surface-2 bg-surface-1 p-2">
                {permList.map((p, i) => (
                  <label
                    key={p.permission_id || p.name || i}
                    className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-surface-2/50 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={selPerms.includes(p.name)}
                      onChange={() => togglePerm(p.name)}
                      className="accent-brand-accent"
                    />
                    <div className="flex flex-col">
                      <span className="text-xs text-text-primary">{p.name}</span>
                      {p.description && (
                        <span className="text-[10px] text-text-muted">{p.description}</span>
                      )}
                    </div>
                  </label>
                ))}
                {permList.length === 0 && (
                  <p className="p-2 text-xs text-text-muted">No permissions available</p>
                )}
              </div>
            </div>
            <div className="flex gap-3 pt-2">
              <button
                onClick={resetForm}
                className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !name}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] btn-cta disabled:hover:scale-100"
              >
                {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Save
              </button>
            </div>
          </div>
        </div>
      )}

      <ConfirmDialog
        open={!!deleteId}
        title="Delete Role"
        message="This will remove the role from all assigned users. This action cannot be undone."
        confirmLabel="Delete"
        variant="danger"
        onConfirm={handleDelete}
        onCancel={() => setDeleteId(null)}
      />
    </>
  )
}

function PermissionsTab() {
  const [showCreate, setShowCreate] = useState(false)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [saving, setSaving] = useState(false)

  const { data: permissions, refetch, isLoading } = useApiQuery<Permission[]>(
    ['admin-permissions'],
    '/api/rbac/permissions',
  )
  const permList = Array.isArray(permissions) ? permissions : []

  const handleSave = async () => {
    setSaving(true)
    try {
      await api.post('/api/rbac/permissions', { name, description })
      setName('')
      setDescription('')
      setShowCreate(false)
      notify.success('Permission created.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to create permission')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.delete(`/api/rbac/permissions/${deleteId}`)
      setDeleteId(null)
      notify.success('Permission deleted.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to delete permission')
    }
  }

  return (
    <>
      <div className="mb-4">
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          <Plus size={16} /> Create Permission
        </button>
      </div>

      {isLoading ? (
        <div className="py-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-accent" />
        </div>
      ) : permList.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-2xl border border-surface-2 bg-surface-1 py-16 text-center">
          <div className="rounded-2xl bg-surface-2 p-4">
            <Shield className="h-8 w-8 text-text-muted" />
          </div>
          <h3 className="mt-4 text-lg font-semibold text-text-primary">No permissions</h3>
          <p className="mt-2 max-w-sm text-sm text-text-muted">
            Create permissions to assign to roles.
          </p>
          <button
            onClick={() => setShowCreate(true)}
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <Plus size={16} />
            Create Permission
          </button>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase hidden md:table-cell">Description</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {permList.map((p, i) => (
                <tr key={p.permission_id || p.name || i} className="hover:bg-surface-2/50">
                  <td className="px-6 py-3 text-sm font-medium text-text-primary">{p.name}</td>
                  <td className="px-6 py-3 text-sm text-text-secondary hidden md:table-cell">{p.description || '-'}</td>
                  <td className="px-6 py-3">
                    <button
                      onClick={() => setDeleteId(p.permission_id || p.name)}
                      className="text-text-muted hover:text-semantic-error transition-colors"
                      title="Delete permission"
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/50" onClick={() => setShowCreate(false)} />
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-accent">
            <h3 className="text-lg font-semibold text-text-primary">Create Permission</h3>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="users.read"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Description</label>
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="View user profiles"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
              />
            </div>
            <div className="flex gap-3 pt-2">
              <button
                onClick={() => setShowCreate(false)}
                className="flex-1 rounded-xl border border-surface-2 px-4 py-2 text-sm text-text-secondary hover:bg-surface-2 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !name}
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] btn-cta disabled:hover:scale-100"
              >
                {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                Create
              </button>
            </div>
          </div>
        </div>
      )}

      <ConfirmDialog
        open={!!deleteId}
        title="Delete Permission"
        message="This will remove the permission from all roles. This action cannot be undone."
        confirmLabel="Delete"
        variant="danger"
        onConfirm={handleDelete}
        onCancel={() => setDeleteId(null)}
      />
    </>
  )
}

function UserRoleAssignments() {
  const [userEmail, setUserEmail] = useState('')
  const [selectedRole, setSelectedRole] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [assigning, setAssigning] = useState(false)
  const [revokeId, setRevokeId] = useState<string | null>(null)
  const [searchUserId, setSearchUserId] = useState('')
  const [searched, setSearched] = useState(false)

  const { data: allRoles } = useApiQuery<Role[]>(RBAC_ROLES_QUERY_KEY, '/api/rbac/roles')
  const roleOptions = Array.isArray(allRoles) ? allRoles : []

  // Fetch user roles only when searching for a specific user
  const { data: userRolesRaw, refetch, isLoading } = useApiQuery<UserRoleAssignment[]>(
    ['user-roles', searchUserId] as string[],
    `/api/rbac/user-roles/${searchUserId}`,
    { enabled: Boolean(searchUserId) },
  )
  const userRoles = Array.isArray(userRolesRaw) ? userRolesRaw : []

  const handleSearch = async () => {
    if (!userEmail.trim()) return
    try {
      const res = await api.get<{ items?: Array<{ id: string }> }>(`/api/admin/users/search?q=${encodeURIComponent(userEmail)}&limit=1`)
      const items = res?.items || (Array.isArray(res) ? res : [])
      if (items.length > 0) {
        setSearchUserId(items[0].id)
        setSearched(true)
      } else {
        notify.error('User not found')
      }
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to find user')
    }
  }

  const handleAssign = async () => {
    if (!searchUserId || !selectedRole) return
    setAssigning(true)
    try {
      const body: Record<string, unknown> = { user_id: searchUserId, role_id: selectedRole }
      if (expiresAt) body.expires_at = expiresAt
      await api.post('/api/rbac/user-roles', body)
      setSelectedRole(''); setExpiresAt('')
      notify.success('Role assigned.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to assign role')
    } finally { setAssigning(false) }
  }

  const handleRevoke = async () => {
    if (!revokeId) return
    try {
      await api.delete(`/api/rbac/user-roles/${searchUserId}/${revokeId}`)
      setRevokeId(null)
      notify.success('Assignment revoked.')
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to revoke')
    }
  }

  return (
    <div>
      <h2 className="mb-4 text-lg font-semibold text-text-primary">User Role Assignments</h2>
      <p className="mb-4 text-xs text-text-muted">Search for a user, see their assigned roles, and manage assignments.</p>

      <div className="mb-4 rounded-2xl border border-surface-2 bg-surface-1 p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[200px]">
            <label className="mb-1 block text-xs font-medium text-text-muted">User email</label>
            <input
              value={userEmail}
              onChange={e => { setUserEmail(e.target.value); setSearchUserId(''); setSearched(false) }}
              placeholder="user@example.com"
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none"
              onKeyDown={e => { if (e.key === 'Enter') handleSearch() }}
            />
          </div>
          <button onClick={handleSearch} disabled={!userEmail.trim()} className="rounded-xl bg-brand-wash px-4 py-2.5 text-sm font-medium text-brand-accent hover:bg-brand-wash-faint btn-cta">
            Search
          </button>
        </div>
      </div>

      {searched && searchUserId && (
        <>
          <div className="mb-4 flex flex-wrap items-end gap-3 rounded-2xl border border-surface-2 bg-surface-1 p-4">
            <div className="flex-1 min-w-[180px]">
              <label className="mb-1 block text-xs font-medium text-text-muted">Assign role</label>
              <select
                value={selectedRole}
                onChange={e => setSelectedRole(e.target.value)}
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary focus:border-brand-accent focus:outline-none"
              >
                <option value="">Select a role...</option>
                {roleOptions.map(r => <option key={r.role_id || r.id} value={r.role_id || r.id}>{r.name || r.role_id || r.id}</option>)}
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Expires (optional)</label>
              <input
                type="date"
                value={expiresAt}
                onChange={e => setExpiresAt(e.target.value)}
                className="rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary focus:border-brand-accent focus:outline-none"
              />
            </div>
            <button
              onClick={handleAssign}
              disabled={assigning || !selectedRole}
              className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2.5 text-sm font-semibold text-white shadow-glow-accent btn-cta"
            >
              {assigning ? <Loader2 size={14} className="animate-spin" /> : null}
              Assign
            </button>
          </div>

          {isLoading ? (
            <div className="py-4 text-center"><Loader2 className="mx-auto h-5 w-5 animate-spin text-brand-accent" /></div>
          ) : userRoles.length === 0 ? (
            <div className="rounded-2xl border border-surface-2 bg-surface-1 p-8 text-center">
              <Shield className="mx-auto h-6 w-6 text-text-muted" />
              <p className="mt-2 text-sm text-text-muted">No roles assigned to this user.</p>
            </div>
          ) : (
            <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
              <table className="w-full">
                <thead className="border-b border-surface-2">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Email</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase hidden md:table-cell">Role</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase hidden md:table-cell">Expires</th>
                    <th className="px-6 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-2">
                  {userRoles.map((ur, i: number) => (
                    <tr key={ur.role_id || i}>
                      <td className="px-6 py-3 text-sm text-text-primary">{ur.user_email || userEmail}</td>
                      <td className="px-6 py-3 text-sm text-text-secondary hidden md:table-cell">{ur.role_name || ur.role_id || '-'}</td>
                      <td className="px-6 py-3 text-sm text-text-muted hidden md:table-cell">{ur.expires_at ? formatDateTime(ur.expires_at) : 'Never'}</td>
                      <td className="px-6 py-3">
                        <button onClick={() => setRevokeId(ur.role_id)} className="text-text-muted hover:text-semantic-error" title="Revoke"><Trash2 size={14} /></button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      <ConfirmDialog
        open={!!revokeId}
        title="Revoke Role Assignment"
        message="The user will lose all permissions granted by this role."
        confirmLabel="Revoke"
        variant="danger"
        onConfirm={handleRevoke}
        onCancel={() => setRevokeId(null)}
      />
    </div>
  )
}
