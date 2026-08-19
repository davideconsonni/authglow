import { useCallback, useEffect, useState } from 'react'
import { api } from '../lib/api'
import { useDemoMeta } from './useDemoMeta'

export interface DemoInboxEmail {
  timestamp: string
  to: string[]
  cc: string[]
  subject: string
  body_text: string | null
  body_html: string | null
  provider: string
}

export interface DemoInboxState {
  emails: DemoInboxEmail[]
  loading: boolean
  refresh: () => void
}

/**
 * Demo-mode email inbox (GET /api/demo/inbox).
 *
 * In demo mode the server captures every outgoing email in memory and this
 * hook fetches the ones addressed to `email`, so anonymous sandbox visitors
 * can read their verification / reset codes without a real mail provider.
 * When the server is not running in demo mode (or no email is provided) it
 * stays idle and returns an empty list.
 */
export function useDemoInbox(email: string | null): DemoInboxState {
  const { meta } = useDemoMeta()
  const [emails, setEmails] = useState<DemoInboxEmail[]>([])
  const [loading, setLoading] = useState(false)
  const [version, setVersion] = useState(0)

  const refresh = useCallback(() => setVersion((v) => v + 1), [])

  useEffect(() => {
    if (!meta.demo_mode || !email) {
      setEmails([])
      setLoading(false)
      return
    }

    let cancelled = false
    setLoading(true)
    api
      .get<{ emails: DemoInboxEmail[] }>(`/api/demo/inbox?email=${encodeURIComponent(email)}`, {
        cache: 'no-store',
      })
      .then((data) => {
        if (!cancelled) setEmails(data.emails ?? [])
      })
      .catch(() => {
        if (!cancelled) setEmails([])
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [meta.demo_mode, email, version])

  return { emails, loading, refresh }
}
