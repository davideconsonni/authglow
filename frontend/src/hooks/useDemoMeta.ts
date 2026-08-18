import { useEffect, useState } from 'react'
import { api } from '../lib/api'

export interface DemoMeta {
  demo_mode: boolean
  demo_banner_text?: string
  demo_user_email?: string
  demo_user_password?: string
}

const EMPTY: DemoMeta = { demo_mode: false }

/**
 * Public environment metadata (GET /api/meta), available before sign-in.
 * Used to render the demo-mode warning banner and the demo credentials box.
 * The meta endpoint is public and rate-limited; it returns no credential
 * material unless the server runs with demo_mode enabled.
 */
export function useDemoMeta() {
  const [meta, setMeta] = useState<DemoMeta>(EMPTY)
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    let cancelled = false
    api
      .get<DemoMeta>('/api/meta', { cache: 'no-store' })
      .then((data) => {
        if (!cancelled) setMeta(data)
      })
      .catch(() => {
        /* meta unavailable: assume not a demo */
      })
      .finally(() => {
        if (!cancelled) setLoaded(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  return { meta, loaded }
}