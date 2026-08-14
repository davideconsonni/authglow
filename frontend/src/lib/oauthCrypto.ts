const OAUTH_RANDOM_BYTES = 32
export const PLAYGROUND_TRANSACTION_KEY = 'authglow-playground-oauth-transaction'

function encodeBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function randomBase64Url(byteLength = OAUTH_RANDOM_BYTES): string {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return encodeBase64Url(bytes)
}

export function generateOAuthState(): string {
  return randomBase64Url()
}

export function generateOAuthNonce(): string {
  return randomBase64Url()
}

export function generatePkceVerifier(): string {
  return randomBase64Url()
}

export async function generatePkceChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return encodeBase64Url(new Uint8Array(digest))
}

export function readJwtClaim<T>(token: string, claim: string): T | undefined {
  try {
    const payload = token.split('.')[1]
    if (!payload) return undefined
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/')
    const decoded = JSON.parse(atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='))) as Record<string, unknown>
    return decoded[claim] as T | undefined
  } catch {
    return undefined
  }
}

export function parseAuthorizationCallback(
  callbackUrl: string,
  expectedRedirectUri: string,
  expectedState: string,
): string {
  const callback = new URL(callbackUrl)
  const redirect = new URL(expectedRedirectUri)

  if (callback.origin !== redirect.origin || callback.pathname !== redirect.pathname) {
    throw new Error('OAuth callback URL does not match the registered redirect URI')
  }

  const returnedState = callback.searchParams.get('state')
  if (!returnedState || returnedState !== expectedState) {
    throw new Error('OAuth state validation failed')
  }

  const oauthError = callback.searchParams.get('error')
  if (oauthError) {
    throw new Error(callback.searchParams.get('error_description') || oauthError)
  }

  const code = callback.searchParams.get('code')
  if (!code) throw new Error('Authorization code is missing from the callback URL')
  return code
}
