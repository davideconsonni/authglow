import { ChevronDown, Code, ExternalLink, FileText, Terminal } from 'lucide-react'
import { CopyButton } from '../../components/shared/CopyButton'
import { getCodeSnippet, getDocUrl } from './oauthClientSnippets'

const FRAMEWORKS = [
  { id: 'nextjs', label: 'Next.js (App Router)', icon: FileText },
  { id: 'react', label: 'React SPA', icon: Code },
  { id: 'python', label: 'Python / FastAPI', icon: Terminal },
  { id: 'node', label: 'Node / Express', icon: Terminal },
  { id: 'go', label: 'Go', icon: Terminal },
  { id: 'dotnet', label: 'ASP.NET Core', icon: Terminal },
]

interface ClientSnippetsListProps {
  clientId: string
  /** Plaintext secret, or a placeholder when the real secret is unknown (edit mode). */
  clientSecret: string
  /** False in edit mode: the secret is hashed server-side and never returned. */
  secretKnown: boolean
  /** When true the whole section starts collapsed (used in the edit modal). */
  startCollapsed?: boolean
}

export function ClientSnippetsList({ clientId, clientSecret, secretKnown, startCollapsed }: ClientSnippetsListProps) {
  const body = (
    <>
      {!secretKnown && (
        <p role="note" className="mb-3 rounded-xl border border-surface-2 bg-surface-2 px-3 py-2 text-xs text-text-secondary">
          The client secret is not shown for existing clients — paste the one saved at creation time,
          or rotate it to get a new one.
        </p>
      )}
      <div className="space-y-3" role="tablist" aria-label="Framework examples">
        {FRAMEWORKS.map((fw) => (
          <details
            key={fw.id}
            data-testid={`snippet-${fw.id}`}
            className="group rounded-xl border border-surface-2 bg-surface-1"
          >
            <summary className="flex items-center gap-3 p-3 cursor-pointer list-none text-sm font-medium text-text-primary hover:bg-surface-2">
              <fw.icon size={16} className="text-text-muted" />
              {fw.label}
              <ChevronDown size={14} className="ml-auto text-text-muted group-open:rotate-180 transition-transform" />
            </summary>
            <div className="p-3 border-t border-surface-2 bg-surface-2">
              <pre className="overflow-x-auto text-[11px] font-mono text-text-primary">
                <code>{getCodeSnippet(fw.id, { client_id: clientId, client_secret: clientSecret })}</code>
              </pre>
              <div className="mt-2 flex gap-2">
                <CopyButton
                  text={getCodeSnippet(fw.id, { client_id: clientId, client_secret: clientSecret })}
                  label="Copy"
                  className="text-[11px]"
                />
                <a
                  href={getDocUrl(fw.id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-[11px] text-brand-accent hover:underline"
                >
                  <ExternalLink size={12} /> Docs
                </a>
              </div>
            </div>
          </details>
        ))}
      </div>
    </>
  )

  if (startCollapsed) {
    return (
      <details data-testid="client-snippets" className="group rounded-xl border border-surface-2 bg-surface-1">
        <summary className="flex items-center gap-3 p-3 cursor-pointer list-none text-sm font-semibold text-text-primary hover:bg-surface-2">
          Quick Start — Copy-Paste Config
          <ChevronDown size={14} className="ml-auto text-text-muted group-open:rotate-180 transition-transform" />
        </summary>
        <div className="border-t border-surface-2 p-3">{body}</div>
      </details>
    )
  }

  return (
    <div data-testid="client-snippets">
      <h4 className="mb-4 text-sm font-semibold text-text-primary">Quick Start — Copy-Paste Config</h4>
      {body}
    </div>
  )
}
