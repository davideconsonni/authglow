// Inline template picker shared by the claim policy editors.
//
// Fetches GET /api/admin/claim-templates and shows the built-in
// recipes as clickable cards. Selecting one hands the raw template
// to the parent tab, which maps it onto its local ClaimRulePayload
// shape and appends it to the draft. Purely additive — persistence
// still goes through the existing PUT endpoints that validate
// server-side.

import { useState } from 'react'
import { ChevronDown, LayoutTemplate, Loader2 } from 'lucide-react'
import { useApiQuery } from '../../hooks/useApi'

export interface ClaimTemplate {
  id: string
  label: string
  description: string
  /** Server-resolved (namespace-expanded) claim name — ready to save as-is. */
  claim_name: string
  source: string
  include_in: string[]
  required_scope?: string | null
  source_config: Record<string, unknown>
}

interface ClaimTemplatePickerProps {
  onSelect: (template: ClaimTemplate) => void
  /** Sources irrelevant in this context are hidden (e.g. ``api_key_field`` inside the OAuth-client modal). */
  excludeSources?: string[]
  /** data-testid prefix so each tab keeps its own selector namespace. */
  testPrefix?: string
}

export function ClaimTemplatePicker({
  onSelect,
  excludeSources = [],
  testPrefix = 'claim-template',
}: ClaimTemplatePickerProps) {
  const [open, setOpen] = useState(false)
  const { data, isLoading } = useApiQuery<ClaimTemplate[]>(
    ['claim-templates'],
    '/api/admin/claim-templates',
  )
  const templates = (data ?? []).filter(t => !excludeSources.includes(t.source))

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
        data-testid={`${testPrefix}-btn`}
        className="flex w-full items-center justify-center gap-1.5 rounded-xl border border-dashed border-surface-2 py-2 text-[11px] font-semibold text-text-muted transition-all hover:border-brand-violet/30 hover:text-brand-violet hover:bg-brand-violet/5"
      >
        <LayoutTemplate size={12} /> Start from a template
        <ChevronDown size={12} className={`transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div
          data-testid={`${testPrefix}-list`}
          className="mt-2 grid gap-2 rounded-xl border border-surface-2 bg-bg-primary p-3 sm:grid-cols-2"
        >
          {isLoading && (
            <div className="col-span-full flex items-center justify-center py-4 text-text-muted">
              <Loader2 size={16} className="animate-spin" />
            </div>
          )}
          {!isLoading && templates.length === 0 && (
            <p className="col-span-full text-center text-[10px] text-text-muted">
              No templates available.
            </p>
          )}
          {templates.map(t => (
            <button
              key={t.id}
              type="button"
              onClick={() => {
                onSelect(t)
                setOpen(false)
              }}
              title={t.description}
              data-testid={`${testPrefix}-${t.id}`}
              className="rounded-xl border border-surface-2 bg-surface-1 p-2.5 text-left transition-all hover:border-brand-violet/40 hover:bg-brand-violet/5"
            >
              <p className="text-[11px] font-semibold text-text-primary">{t.label}</p>
              <p className="mt-0.5 truncate font-mono text-[9px] text-text-muted">{t.claim_name}</p>
              <div className="mt-1 flex flex-wrap gap-1">
                {t.include_in.map(target => (
                  <span
                    key={target}
                    className="rounded bg-surface-2 px-1.5 py-0.5 text-[8px] font-semibold uppercase tracking-wider text-text-secondary"
                  >
                    {target.replace('_', ' ')}
                  </span>
                ))}
                {t.required_scope && (
                  <span className="rounded bg-semantic-warning/10 px-1.5 py-0.5 text-[8px] font-semibold text-semantic-warning">
                    scope: {t.required_scope}
                  </span>
                )}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
