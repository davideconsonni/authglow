import { Inbox, Loader2, RefreshCw } from 'lucide-react'
import { useDemoInbox } from '../../hooks/useDemoInbox'

interface DemoInboxProps {
  /** The email address whose demo mailbox should be shown. */
  email: string | null
}

/**
 * Demo-mode email inbox.
 *
 * Rendered on pages where an anonymous demo visitor is waiting for an email
 * (post-registration, email verification, password reset). In demo mode the
 * server captures outgoing emails in memory and exposes them via
 * ``GET /api/demo/inbox``; this panel shows them so the visitor can copy
 * their verification / reset code without a real mail provider.
 */
export function DemoInbox({ email }: DemoInboxProps) {
  const { emails, loading, refresh } = useDemoInbox(email)

  return (
    <div
      data-testid="demo-inbox"
      className="rounded-xl border border-surface-2 bg-surface-1/50 p-4 text-sm"
    >
      <div className="flex items-center justify-between gap-2">
        <p className="flex items-center gap-1.5 font-medium text-text-primary">
          <Inbox className="h-4 w-4 text-brand-violet" aria-hidden="true" />
          Demo inbox
        </p>
        <button
          type="button"
          onClick={refresh}
          aria-label="Refresh demo inbox"
          className="inline-flex items-center gap-1 text-xs text-text-muted transition-colors hover:text-text-secondary disabled:opacity-50"
        >
          {loading ? <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-3 w-3" aria-hidden="true" />}
        </button>
      </div>
      {email && <p className="mt-0.5 break-all font-mono text-xs text-text-muted">{email}</p>}

      <p className="mt-2 text-xs text-text-muted">
        No mail provider is configured on this demo server. Emails the server "sent" to this
        address are shown here instead.
      </p>

      {emails.length === 0 ? (
        <p className="mt-3 rounded-lg border border-dashed border-surface-2 px-3 py-4 text-center text-xs text-text-muted">
          No emails yet. Trigger a flow (registration, password reset) and refresh.
        </p>
      ) : (
        <ul className="mt-3 space-y-3">
          {emails.map((message, index) => (
            <li
              key={`${message.timestamp}-${index}`}
              data-testid="demo-inbox-email"
              className="rounded-lg border border-surface-2 bg-surface-1 px-3 py-2.5"
            >
              <p className="text-xs font-medium text-text-secondary">{message.subject}</p>
              <p className="mt-0.5 text-xs text-text-muted">
                {new Date(message.timestamp).toLocaleString()}
              </p>
              {message.body_text && (
                <pre className="mt-2 whitespace-pre-wrap break-words rounded-md bg-bg-primary/60 px-2 py-1.5 font-mono text-[11px] leading-relaxed text-text-primary">
                  {message.body_text}
                </pre>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
