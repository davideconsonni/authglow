import { API_URL } from '../lib/constants'
import { notify, useToastStore } from '../stores/toastStore'

interface ApiOptions extends Omit<RequestInit, 'body'> {
  body?: unknown
  formBody?: Record<string, string>
}

class ApiError extends Error {
  status: number
  data: unknown

  constructor(message: string, status: number, data?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.data = data
  }
}

function extractErrorMessage(data: unknown): string {
  if (!data) return ''
  if (typeof data === 'string') return data
  if (typeof data === 'object' && data !== null) {
    const detail = (data as Record<string, unknown>).detail
    if (typeof detail === 'string') return detail
    if (Array.isArray(detail)) {
      return detail
        .map((d: Record<string, unknown>) => {
          const loc = (d.loc as string[])?.slice(1).join('.')
          const prefix = loc ? `${loc}: ` : ''
          return prefix + (d.msg || JSON.stringify(d))
        })
        .join('. ')
    }
    return JSON.stringify(data)
  }
  return ''
}

let isRefreshing = false
let pendingRequests: (() => void)[] = []
// Endpoints where a 401 is an *expected* credential failure (e.g. a wrong
// password on the sign-in form). The refresh dance is skipped there: it can
// never succeed in that state and it masks the backend's real detail
// ("Invalid credentials") behind a generic "Unauthorized" — plus it fires a
// spurious "session expired" toast right before a fresh sign-in attempt.
const CREDENTIAL_ENDPOINTS = ['/api/auth/refresh', '/api/oauth2/authorize']
// Guards against toast spam when many parallel requests 401 at once.
// The flag is per-module-load, so it resets on the next page navigation
// (after the soft redirect to /auth/login).
let sessionExpiredNotified = false
let csrfToken: string | null = null

async function getCsrfToken(): Promise<string> {
  // T0-1 (VAPT-066): the token is cached and reused across unsafe
  // requests — backend validation is non-consuming and bound to the
  // holder's csrf_session_id cookie, so one fetch per page load is
  // enough. Fetching a fresh token per request would race parallel
  // mutations (each fetch rotates the server-side token).
  if (csrfToken) return csrfToken
  const response = await fetch(`${API_URL}/api/oauth2/csrf-token`, { credentials: 'include' })
  const data = await response.json() as { csrf_token?: string }
  if (!response.ok || !data.csrf_token) throw new Error('Unable to initialize CSRF protection')
  csrfToken = data.csrf_token
  return csrfToken
}

/** Drop the cached CSRF token (e.g. on a 403 from the CSRF gate, or
 * after a hard sign-out) so the next unsafe request re-bootstraps. */
export function clearCsrfToken() {
  csrfToken = null
}
async function attemptRefresh(): Promise<boolean> {
  try {
    const token = await getCsrfToken()
    const resp = await fetch(`${API_URL}/api/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': token },
    })
    return resp.ok
  } catch {
    return false
  }
}

function onRefreshed() {
  for (const resolve of pendingRequests) {
    resolve()
  }
  pendingRequests = []
}

function onRefreshFailed() {
  // Resolve pending requests so they retry (and get 401 from the original
  // endpoint) instead of hanging forever. The page-level error handling
  // then handles each query's 401 as a normal error.
  onRefreshed()

  if (window.location.pathname === '/auth/login') return
  if (sessionExpiredNotified) return
  sessionExpiredNotified = true

  // Soft UX: show a toast so the user understands what happened, then
  // redirect after a short delay so the message is actually visible.
  // Previously the user was silently kicked to /auth/login with no
  // explanation, losing their page context without warning.
  notify.error('Your session has expired. Please sign in again.')
  setTimeout(() => {
    window.dispatchEvent(new CustomEvent('auth:session-expired'))
  }, 2500)
}

async function request<T>(endpoint: string, options: ApiOptions = {}): Promise<T> {
  const { body, formBody, headers: customHeaders, ...rest } = options

  const isForm = !!formBody

  const headers: Record<string, string> = {
    ...(isForm ? {} : { 'Content-Type': 'application/json' }),
    ...(customHeaders as Record<string, string>),
  }

  const requestBody = isForm
    ? new URLSearchParams(formBody)
    : body
      ? JSON.stringify(body)
      : undefined

  const isUnsafe = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(rest.method || '')
  const doFetch = async () => {
    if (isUnsafe) headers['X-CSRF-Token'] = await getCsrfToken()
    return fetch(`${API_URL}${endpoint}`, {
      ...rest,
      headers,
      body: requestBody,
      credentials: 'include',
    })
  }

  let response = await doFetch()

  // A 403 from the CSRF gate means the cached token went stale (e.g.
  // another tab rotated it, or the server-side entry expired). Drop it
  // and retry once with a fresh token before surfacing the error.
  if (isUnsafe && response.status === 403) {
    const errDetail = extractErrorMessage(await response.clone().json().catch(() => null))
    if (errDetail.includes('CSRF')) {
      clearCsrfToken()
      response = await doFetch()
    }
  }

  if (response.status === 401 && !CREDENTIAL_ENDPOINTS.some((e) => endpoint.startsWith(e))) {
    if (!isRefreshing) {
      isRefreshing = true
      const ok = await attemptRefresh()
      isRefreshing = false
      if (ok) {
        onRefreshed()
        response = await doFetch()
      } else {
        onRefreshFailed()
        throw new ApiError('Unauthorized', 401)
      }
    } else {
      await new Promise<void>((resolve) => {
        pendingRequests.push(resolve)
      })
      response = await doFetch()
    }
  }

  if (response.status === 429) {
    useToastStore.getState().addToast('error', 'Too many requests. Please wait before trying again.')
  }

  if (response.status === 204) {
    return undefined as T
  }

  const data = await response.json().catch(() => null)

  if (!response.ok) {
    throw new ApiError(
      extractErrorMessage(data) || `Request failed with status ${response.status}`,
      response.status,
      data,
    )
  }

  return data as T
}

export const api = {
  get<T>(endpoint: string, options?: ApiOptions) {
    return request<T>(endpoint, { ...options, method: 'GET' })
  },
  post<T>(endpoint: string, body?: unknown, options?: ApiOptions) {
    return request<T>(endpoint, { ...options, method: 'POST', body })
  },
  postForm<T>(endpoint: string, formBody: Record<string, string>, options?: ApiOptions) {
    return request<T>(endpoint, { ...options, method: 'POST', formBody })
  },
  put<T>(endpoint: string, body?: unknown, options?: ApiOptions) {
    return request<T>(endpoint, { ...options, method: 'PUT', body })
  },
  patch<T>(endpoint: string, body?: unknown, options?: ApiOptions) {
    return request<T>(endpoint, { ...options, method: 'PATCH', body })
  },
  delete<T>(endpoint: string, options?: ApiOptions) {
    return request<T>(endpoint, { ...options, method: 'DELETE' })
  },
}

export { ApiError }
