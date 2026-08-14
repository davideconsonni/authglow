export function decodeJwt(
  token: string,
): { header: Record<string, unknown>; payload: Record<string, unknown> } | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null

    const header = JSON.parse(_base64UrlDecode(parts[0]))
    const payload = JSON.parse(_base64UrlDecode(parts[1]))
    if (!header || !payload) return null

    return { header, payload }
  } catch {
    return null
  }
}

function _base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4 !== 0) {
    base64 += '='
  }
  return atob(base64)
}
