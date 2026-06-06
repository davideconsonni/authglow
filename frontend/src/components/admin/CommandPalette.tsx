import { useState, useEffect, useCallback } from 'react'
import { Search, Key, ArrowRight } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { api } from '@/lib/api'
import { ROUTES } from '@/lib/constants'

interface UserResult {
  id: string
  email: string
  first_name: string | null
  last_name: string | null
}

interface ClientResult {
  client_id: string
  client_name?: string
  name?: string
}

export function CommandPalette() {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [users, setUsers] = useState<UserResult[]>([])
  const [clients, setClients] = useState<ClientResult[]>([])
  const navigate = useNavigate()

  const search = useCallback(async (q: string) => {
    if (q.length < 2) { setUsers([]); setClients([]); return }
    try {
      const [userRes, clientRes] = await Promise.all([
        api.get<{ items: UserResult[] }>(`/api/admin/users/search?q=${encodeURIComponent(q)}&limit=5`),
        api.get<ClientResult[]>(`/api/oauth-clients`),
      ])
      setUsers((userRes as { items: UserResult[] })?.items ?? [])
      const filteredClients = (Array.isArray(clientRes) ? clientRes : (clientRes as { items?: ClientResult[] })?.items ?? [])
        .filter((c: ClientResult) => {
          const name = (c.client_name || c.name || c.client_id).toLowerCase()
          return name.includes(q.toLowerCase())
        })
        .slice(0, 5)
      setClients(filteredClients)
    } catch {
      setUsers([])
      setClients([])
    }
  }, [])

  useEffect(() => {
    const t = setTimeout(() => { search(query) }, 200)
    return () => clearTimeout(t)
  }, [query, search])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        setOpen(prev => !prev)
        setQuery('')
      }
      if (e.key === 'Escape') { setOpen(false); setQuery('') }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  if (!open) return null

  const close = () => { setOpen(false); setQuery('') }

  return (
    <div className="fixed inset-0 z-[70] flex items-start justify-center pt-[15vh]">
      <div className="absolute inset-0 bg-black/50" onClick={close} />
      <div className="relative z-10 w-full max-w-lg rounded-2xl border border-surface-2 bg-surface-1 shadow-glow-violet overflow-hidden">
        <div className="flex items-center gap-3 px-4 py-3 border-b border-surface-2">
          <Search size={18} className="text-text-muted shrink-0" />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Search users or OAuth clients..."
            autoFocus
            className="flex-1 bg-transparent text-sm text-text-primary placeholder:text-text-muted focus:outline-none"
          />
          <kbd className="hidden sm:inline-flex items-center rounded-md bg-surface-2 px-2 py-0.5 text-[10px] text-text-muted font-mono">Esc</kbd>
        </div>
        {(users.length > 0 || clients.length > 0) && (
          <div className="max-h-80 overflow-y-auto">
            {users.length > 0 && (
              <div>
                <p className="px-4 py-2 text-[11px] font-semibold text-text-muted uppercase tracking-wider">Users</p>
                {users.map(u => (
                  <button
                    key={u.id}
                    onClick={() => { close(); navigate(ROUTES.ADMIN.USERS) }}
                    className="flex items-center gap-3 w-full px-4 py-2.5 hover:bg-surface-2 transition-colors text-left"
                  >
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-brand-violet/15 text-xs font-bold text-brand-violet">
                      {(u.first_name?.[0] || '') + (u.last_name?.[0] || '') || '?'}
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-text-primary truncate">{u.first_name} {u.last_name}</p>
                      <p className="text-xs text-text-muted truncate">{u.email}</p>
                    </div>
                    <ArrowRight size={14} className="text-text-muted shrink-0" />
                  </button>
                ))}
              </div>
            )}
            {clients.length > 0 && (
              <div>
                <p className="px-4 py-2 text-[11px] font-semibold text-text-muted uppercase tracking-wider">OAuth Clients</p>
                {clients.map(c => (
                  <button
                    key={c.client_id}
                    onClick={() => { close(); navigate(ROUTES.ADMIN.OAUTH_CLIENTS) }}
                    className="flex items-center gap-3 w-full px-4 py-2.5 hover:bg-surface-2 transition-colors text-left"
                  >
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-brand-magenta/10 text-brand-magenta">
                      <Key size={14} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-text-primary truncate">{c.client_name || c.name || c.client_id}</p>
                      <p className="text-xs text-text-muted truncate font-mono">{c.client_id}</p>
                    </div>
                    <ArrowRight size={14} className="text-text-muted shrink-0" />
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
        {query.length >= 2 && users.length === 0 && clients.length === 0 && (
          <div className="px-4 py-8 text-center">
            <p className="text-sm text-text-muted">No results for "{query}"</p>
          </div>
        )}
        {query.length === 0 && (
          <div className="px-4 py-6 text-center">
            <p className="text-xs text-text-muted">Type to search users and OAuth clients</p>
          </div>
        )}
      </div>
    </div>
  )
}
