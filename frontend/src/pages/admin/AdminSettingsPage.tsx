import { useState } from 'react'
import { Loader2, Save, RotateCcw, AlertTriangle, SlidersHorizontal } from 'lucide-react'
import { api } from '../../lib/api'
import { useApiQuery } from '../../hooks/useApi'
import { ConfirmDialog } from '../../components/shared/ConfirmDialog'
import { PageHeader } from '../../components/layout/PageHeader'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { notify } from '../../stores/toastStore'
import { cn } from '../../lib/utils'

interface SettingField {
  key: string
  value: unknown
  type: 'boolean' | 'number' | 'string'
  default: unknown
  label: string
  category: string
  restart_required: boolean
  editable: boolean
}

interface SettingsData {
  categories: string[]
  settings: SettingField[]
}

const CATEGORY_LABELS: Record<string, string> = {
  general: 'General',
  security: 'Security',
  sessions: 'Sessions',
  cors: 'CORS',
  headers: 'Security Headers',
  password_policy: 'Password Policy',
  registration: 'Registration',
  oauth2: 'OAuth2 / OIDC',
  oauth2_client: 'OAuth2 Client Defaults',
  devices: 'Device Auth',
  email: 'Email',
  storage: 'Storage',
  cache: 'Cache',
  passkey: 'Passkey / WebAuthn',
  audit: 'Audit',
}

export function AdminSettingsPage() {
  useDocumentTitle('System Settings')
  const [activeCategory, setActiveCategory] = useState('general')
  const [edited, setEdited] = useState<Record<string, unknown>>({})
  const [saving, setSaving] = useState(false)
  const [showRestartConfirm, setShowRestartConfirm] = useState(false)

  const { data, isLoading, refetch } = useApiQuery<SettingsData>(
    ['admin-settings'],
    '/api/admin/settings',
  )

  const settings = data?.settings ?? []
  const categories = data?.categories ?? []
  const filtered = settings.filter((s) => s.category === activeCategory)
  const dirtyKeys = Object.keys(edited)

  const hasRestartFields = dirtyKeys.some(
    (k) => settings.find((s) => s.key === k)?.restart_required,
  )

  const getValue = (field: SettingField): unknown =>
    field.key in edited ? edited[field.key] : field.value

  const setValue = (field: SettingField, value: unknown) => {
    if (value === field.value) {
      const next = { ...edited }
      delete next[field.key]
      setEdited(next)
      return
    }
    setEdited((prev) => ({ ...prev, [field.key]: value }))
  }

  const handleSave = async () => {
    if (hasRestartFields) {
      setShowRestartConfirm(true)
      return
    }
    await doSave()
  }

  const doSave = async () => {
    setSaving(true)
    try {
      await api.patch('/api/admin/settings', edited)
      notify.success('Settings updated.')
      setEdited({})
      setShowRestartConfirm(false)
      await refetch()
    } catch (err: unknown) {
      notify.error(err instanceof Error ? err.message : 'Failed to update settings')
    } finally {
      setSaving(false)
    }
  }

  const handleReset = () => {
    setEdited({})
  }

  return (
    <div className="flex gap-6">
      {/* Category sidebar */}
      <div className="w-52 shrink-0">
        <PageHeader
          title="System Settings"
          description="Configure application settings."
        />
        <nav className="mt-4 space-y-0.5">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setActiveCategory(cat)}
              className={cn(
                'w-full rounded-lg px-3 py-2 text-left text-sm font-medium transition-colors',
                activeCategory === cat
                  ? 'bg-brand-violet/15 text-brand-violet'
                  : 'text-text-secondary hover:bg-surface-2 hover:text-text-primary',
              )}
            >
              {CATEGORY_LABELS[cat] ?? cat}
            </button>
          ))}
        </nav>
      </div>

      {/* Settings form */}
      <div className="flex-1 min-w-0">
        {isLoading ? (
          <div className="py-16 text-center">
            <Loader2 className="mx-auto h-6 w-6 animate-spin text-brand-violet" />
          </div>
        ) : (
          <>
            <div className="rounded-2xl border border-surface-2 bg-surface-1">
              <div className="border-b border-surface-2 px-6 py-4">
                <h2 className="text-lg font-semibold text-text-primary">
                  {CATEGORY_LABELS[activeCategory] ?? activeCategory}
                </h2>
              </div>
              <div className="divide-y divide-surface-2">
                {filtered.map((field) => {
                  const currentValue = getValue(field)
                  const isDirty = field.key in edited

                  return (
                    <div
                      key={field.key}
                      className={cn(
                        'px-6 py-4 transition-colors',
                        isDirty && 'bg-brand-violet/5',
                      )}
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <label
                              htmlFor={`setting-${field.key}`}
                              className="text-sm font-medium text-text-primary"
                            >
                              {field.label}
                            </label>
                            {field.restart_required && (
                              <span className="inline-flex items-center gap-1 rounded-md bg-semantic-warning/10 px-1.5 py-0.5 text-[10px] font-medium text-semantic-warning">
                                <AlertTriangle size={10} />
                                Restart required
                              </span>
                            )}
                          </div>
                          <p className="mt-0.5 text-xs text-text-muted">{field.key}</p>
                        </div>
                        <div className="shrink-0">
                          {field.type === 'boolean' ? (
                            <button
                              id={`setting-${field.key}`}
                              type="button"
                              role="switch"
                              aria-checked={Boolean(currentValue)}
                              disabled={!field.editable}
                              onClick={() => setValue(field, !currentValue)}
                              className={cn(
                                'relative inline-flex h-6 w-10 items-center rounded-full transition-colors',
                                currentValue ? 'bg-brand-violet' : 'bg-surface-3',
                                !field.editable && 'opacity-50 cursor-not-allowed',
                              )}
                            >
                              <span
                                className={cn(
                                  'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                                  currentValue ? 'translate-x-5' : 'translate-x-1',
                                )}
                              />
                            </button>
                          ) : field.type === 'number' ? (
                            <input
                              id={`setting-${field.key}`}
                              type="number"
                              value={String(currentValue ?? '')}
                              disabled={!field.editable}
                              onChange={(e) => setValue(field, Number(e.target.value))}
                              className="w-28 rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-sm text-text-primary focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 disabled:opacity-50"
                            />
                          ) : (
                            <input
                              id={`setting-${field.key}`}
                              type="text"
                              value={String(currentValue ?? '')}
                              disabled={!field.editable}
                              onChange={(e) => setValue(field, e.target.value)}
                              className="w-64 rounded-lg border border-surface-2 bg-surface-1 px-3 py-1.5 text-sm text-text-primary focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 disabled:opacity-50"
                            />
                          )}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Save bar */}
            {dirtyKeys.length > 0 && (
              <div className="mt-4 flex items-center justify-end gap-3">
                <button
                  onClick={handleReset}
                  disabled={saving}
                  className="flex items-center gap-2 rounded-xl border border-surface-2 px-4 py-2 text-sm font-medium text-text-secondary hover:bg-surface-2 transition-colors disabled:opacity-50"
                >
                  <RotateCcw size={16} />
                  Reset
                </button>
                <button
                  onClick={handleSave}
                  disabled={saving}
                  className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] disabled:opacity-50"
                >
                  {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />}
                  Save changes
                </button>
              </div>
            )}

            {filtered.length === 0 && !isLoading && (
              <div className="rounded-2xl border border-surface-2 bg-surface-1 p-12 text-center">
                <SlidersHorizontal className="mx-auto h-8 w-8 text-text-muted" />
                <h3 className="mt-3 text-sm font-semibold text-text-primary">No settings</h3>
                <p className="mt-1 text-xs text-text-muted">Select a category to view settings.</p>
              </div>
            )}
          </>
        )}
      </div>

      <ConfirmDialog
        open={showRestartConfirm}
        title="Restart required"
        message="Some changed settings require a server restart to take effect. Save changes anyway?"
        confirmLabel="Save & restart later"
        variant="default"
        onConfirm={doSave}
        onCancel={() => setShowRestartConfirm(false)}
      />
    </div>
  )
}
