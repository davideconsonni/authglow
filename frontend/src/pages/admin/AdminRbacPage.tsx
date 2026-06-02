import { useState, useEffect } from 'react'
import { Plus, Trash2, Loader2, Save, Shield, Edit, Calendar, X } from 'lucide-react'
import { api } from '@/lib/api'
import { useApiQuery } from '@/hooks/useApi'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { PageHeader } from '@/components/layout/PageHeader'
import { formatDateTime } from '@/lib/utils'

interface Permission {
  id: string
  name: string
  description: string
}

interface Role {
  id: string
  name: string
  description: string
  permissions: Permission[]
  is_system: boolean
}

interface UserRole {
  id: string
  user_email: string
  role_name: string
  expires_at: string | null
}

export function AdminRbacPage() {
  const [tab, setTab] = useState<'roles' | 'permissions'>('roles')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  useEffect(() => {
    if (success) {
      const t = setTimeout(() => setSuccess(''), 3000)
      return () => clearTimeout(t)
    }
  }, [success])

  return (
    <div>
      <PageHeader title="Role-Based Access Control" description="Manage roles, permissions, and user assignments." />

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

      <div className="mb-6 flex gap-2">
        {(['roles', 'permissions'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-xl px-4 py-2 text-sm font-medium capitalize transition-colors ${
              tab === t
                ? 'bg-brand-violet text-white'
                : 'bg-surface-2 text-text-secondary hover:bg-surface-3'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === 'roles' ? (
        <RolesTab onError={setError} onSuccess={setSuccess} />
      ) : (
        <PermissionsTab onError={setError} onSuccess={setSuccess} />
      )}

      <div className="mt-12">
        <UserRoleAssignments onError={setError} onSuccess={setSuccess} />
      </div>
    </div>
  )
}

function RolesTab({
  onError,
  onSuccess,
}: {
  onError: (e: string) => void
  onSuccess: (e: string) => void
}) {
  const [showCreate, setShowCreate] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [selPerms, setSelPerms] = useState<string[]>([])
  const [saving, setSaving] = useState(false)

  const { data: roles, refetch: refetchRoles, isLoading } = useApiQuery<Role[]>(
    ['admin-roles'],
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
    setEditId(r.id)
    setName(r.name)
    setDescription(r.description || '')
    setSelPerms(r.permissions.map((p) => p.id))
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
      onSuccess(editId ? 'Role updated.' : 'Role created.')
      await refetchRoles()
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : 'Failed to save role')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.delete(`/api/rbac/roles/${deleteId}`)
      setDeleteId(null)
      onSuccess('Role deleted.')
      await refetchRoles()
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : 'Failed to delete role')
    }
  }

  const togglePerm = (id: string) => {
    setSelPerms((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]))
  }

  return (
    <>
      <div className="mb-4">
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          <Plus size={16} /> Create Role
        </button>
      </div>

      {isLoading ? (
        <div className="py-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" />
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
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
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
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Description</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Permissions</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {roleList.map((r) => (
                <tr key={r.id} className="hover:bg-surface-2/50">
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
                  <td className="px-6 py-3 text-sm text-text-secondary">{r.description || '-'}</td>
                  <td className="px-6 py-3">
                    <div className="flex flex-wrap gap-1">
                      {r.permissions?.length > 0 ? (
                        r.permissions.map((p) => (
                          <span
                            key={p.id}
                            className="rounded-lg bg-surface-2 px-2 py-0.5 text-xs text-text-secondary"
                          >
                            {p.name}
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
                            onClick={() => setDeleteId(r.id)}
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
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-text-primary">
              {editId ? 'Edit Role' : 'Create Role'}
            </h3>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Role name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="admin"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Description</label>
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Administrator role"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>
            <div>
              <p className="mb-2 text-xs font-medium text-text-muted">
                Permissions ({selPerms.length} selected)
              </p>
              <div className="max-h-48 overflow-y-auto space-y-1 rounded-xl border border-surface-2 bg-surface-1 p-2">
                {permList.map((p) => (
                  <label
                    key={p.id}
                    className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-surface-2/50 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={selPerms.includes(p.id)}
                      onChange={() => togglePerm(p.id)}
                      className="accent-brand-violet"
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
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
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

function PermissionsTab({
  onError,
  onSuccess,
}: {
  onError: (e: string) => void
  onSuccess: (e: string) => void
}) {
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
      onSuccess('Permission created.')
      await refetch()
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : 'Failed to create permission')
    } finally {
      setSaving(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteId) return
    try {
      await api.delete(`/api/rbac/permissions/${deleteId}`)
      setDeleteId(null)
      onSuccess('Permission deleted.')
      await refetch()
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : 'Failed to delete permission')
    }
  }

  return (
    <>
      <div className="mb-4">
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          <Plus size={16} /> Create Permission
        </button>
      </div>

      {isLoading ? (
        <div className="py-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" />
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
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
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
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Description</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {permList.map((p) => (
                <tr key={p.id} className="hover:bg-surface-2/50">
                  <td className="px-6 py-3 text-sm font-medium text-text-primary">{p.name}</td>
                  <td className="px-6 py-3 text-sm text-text-secondary">{p.description || '-'}</td>
                  <td className="px-6 py-3">
                    <button
                      onClick={() => setDeleteId(p.id)}
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
          <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4 shadow-glow-violet">
            <h3 className="text-lg font-semibold text-text-primary">Create Permission</h3>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Name</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="users.read"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-text-muted">Description</label>
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="View user profiles"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
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
                className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100"
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

function UserRoleAssignments({
  onError,
  onSuccess,
}: {
  onError: (e: string) => void
  onSuccess: (e: string) => void
}) {
  const [userEmail, setUserEmail] = useState('')
  const [selectedRole, setSelectedRole] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [assigning, setAssigning] = useState(false)
  const [revokeId, setRevokeId] = useState<string | null>(null)

  const { data: assignments, refetch, isLoading } = useApiQuery<UserRole[]>(
    ['admin-user-roles'],
    '/api/rbac/user-roles',
  )
  const userRoles = Array.isArray(assignments) ? assignments : []

  const { data: allRoles } = useApiQuery<Role[]>(['admin-roles-for-assign'], '/api/rbac/roles')
  const roleOptions = Array.isArray(allRoles) ? allRoles : []

  const handleAssign = async () => {
    if (!userEmail || !selectedRole) return
    setAssigning(true)
    try {
      const body: Record<string, unknown> = {
        user_email: userEmail,
        role_id: selectedRole,
      }
      if (expiresAt) {
        body.expires_at = expiresAt
      }
      await api.post('/api/rbac/user-roles', body)
      setUserEmail('')
      setSelectedRole('')
      setExpiresAt('')
      onSuccess('Role assigned successfully.')
      await refetch()
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : 'Failed to assign role')
    } finally {
      setAssigning(false)
    }
  }

  const handleRevoke = async () => {
    if (!revokeId) return
    try {
      await api.delete(`/api/rbac/user-roles/${revokeId}`)
      setRevokeId(null)
      onSuccess('Assignment revoked.')
      await refetch()
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : 'Failed to revoke assignment')
    }
  }

  return (
    <div>
      <h2 className="mb-4 text-lg font-semibold text-text-primary">User Role Assignments</h2>

      <div className="mb-6 rounded-2xl border border-surface-2 bg-surface-1 p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[180px]">
            <label className="mb-1 block text-xs font-medium text-text-muted">User email</label>
            <input
              value={userEmail}
              onChange={(e) => setUserEmail(e.target.value)}
              placeholder="user@example.com"
              type="email"
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none"
            />
          </div>
          <div className="flex-1 min-w-[180px]">
            <label className="mb-1 block text-xs font-medium text-text-muted">Role</label>
            <select
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value)}
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary focus:border-brand-violet focus:outline-none"
            >
              <option value="">Select a role...</option>
              {roleOptions.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name}
                </option>
              ))}
            </select>
          </div>
          <div className="w-40">
            <label className="mb-1 flex items-center gap-1 text-xs font-medium text-text-muted">
              <Calendar size={12} />
              Expires (optional)
            </label>
            <input
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              type="date"
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary focus:border-brand-violet focus:outline-none"
            />
          </div>
          <button
            onClick={handleAssign}
            disabled={assigning || !userEmail || !selectedRole}
            className="flex items-center gap-2 rounded-xl bg-gradient-cta px-6 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50 disabled:hover:scale-100 h-[42px]"
          >
            {assigning ? <Loader2 size={16} className="animate-spin" /> : <Plus size={16} />}
            Assign
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="py-8 text-center">
          <Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" />
        </div>
      ) : userRoles.length === 0 ? (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-8 text-center">
          <Shield className="mx-auto h-6 w-6 text-text-muted" />
          <h3 className="mt-3 text-sm font-semibold text-text-primary">No role assignments</h3>
          <p className="mt-1 text-xs text-text-muted">
            Assign roles to users to grant permissions.
          </p>
        </div>
      ) : (
        <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-surface-2">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">User</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Role</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-text-muted uppercase">Expires</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-2">
              {userRoles.map((ur) => (
                <tr key={ur.id} className="hover:bg-surface-2/50">
                  <td className="px-6 py-3 text-sm text-text-primary">{ur.user_email}</td>
                  <td className="px-6 py-3">
                    <span className="rounded-lg bg-brand-violet/10 px-2 py-0.5 text-xs font-medium text-brand-violet">
                      {ur.role_name}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-sm text-text-muted">
                    {ur.expires_at ? formatDateTime(ur.expires_at) : 'Never'}
                  </td>
                  <td className="px-6 py-3">
                    <button
                      onClick={() => setRevokeId(ur.id)}
                      className="text-text-muted hover:text-semantic-error transition-colors"
                      title="Revoke assignment"
                    >
                      <X size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={!!revokeId}
        title="Revoke Assignment"
        message="This will remove the role from the user. They will lose all permissions granted by this role."
        confirmLabel="Revoke"
        variant="danger"
        onConfirm={handleRevoke}
        onCancel={() => setRevokeId(null)}
      />
    </div>
  )
}
