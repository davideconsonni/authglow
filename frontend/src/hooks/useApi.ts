import {
  useQuery,
  useMutation,
  useQueryClient,
  type UseQueryOptions,
  type UseMutationOptions,
} from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'

export function useApiQuery<T>(
  key: string[],
  endpoint: string,
  options?: Omit<UseQueryOptions<T, ApiError>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<T, ApiError>({
    queryKey: key,
    queryFn: () => api.get<T>(endpoint),
    ...options,
  })
}

export function useApiMutation<TData, TBody = unknown>(
  method: 'post' | 'put' | 'patch' | 'delete',
  endpoint: string | ((vars: TBody) => string),
  options?: Omit<UseMutationOptions<TData, ApiError, TBody>, 'mutationFn'>,
) {
  return useMutation<TData, ApiError, TBody>({
    mutationFn: async (variables) => {
      const url = typeof endpoint === 'function' ? endpoint(variables) : endpoint

      switch (method) {
        case 'post':
          return api.post<TData>(url, variables)
        case 'put':
          return api.put<TData>(url, variables)
        case 'patch':
          return api.patch<TData>(url, variables)
        case 'delete':
          return api.delete<TData>(url)
        default:
          throw new Error(`Unsupported method: ${method}`)
      }
    },
    ...options,
  })
}

/**
 * Cross-page cache invalidation for API keys.
 *
 * The frontend has several query keys that read API-key lists:
 *
 *   - `['my-keys']`           – ApiKeysPage (current user's own keys)
 *   - `['admin-keys', …]`     – AdminApiKeysPage (all keys, admin-only)
 *   - `['my-dash-keys']`      – DashboardPage (current user's keys, summary)
 *   - `['user-keys', userId]` – AdminUsersPage → user detail drawer
 *
 * When a key is created/revoked/restored/edited/deleted/rotated from one
 * page, the other pages' lists go stale but their TanStack Query caches
 * still hold a fresh entry (5-minute staleTime, see `App.tsx`). Without
 * invalidation, navigating to another page after a mutation shows the
 * old list — the user has to press F5 to see the updated record.
 *
 * `invalidateQueries` marks the matching caches as stale; the actual
 * refetch only runs when a page observing that key is mounted, so this
 * is cheap when the other pages are not on screen.
 */
export function useApiKeyInvalidation() {
  const queryClient = useQueryClient()
  return {
    invalidateApiKeyLists: () => {
      void queryClient.invalidateQueries({ queryKey: ['my-keys'] })
      void queryClient.invalidateQueries({ queryKey: ['admin-keys'] })
      void queryClient.invalidateQueries({ queryKey: ['my-dash-keys'] })
      void queryClient.invalidateQueries({ queryKey: ['user-keys'] })
    },
  }
}
