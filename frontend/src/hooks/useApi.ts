import { useQuery, useMutation, type UseQueryOptions, type UseMutationOptions } from '@tanstack/react-query'
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
