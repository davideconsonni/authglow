import { create } from 'zustand'

export type PlaygroundFlow =
  | 'authorization-code'
  | 'client-credentials'
  | 'pkce'
  | 'refresh-token'
  | 'introspection'
  | 'revocation'
  | 'api-key-exchange'
  | 'oidc-discovery'
  | 'generic'

export interface PlaygroundState {
  currentFlow: PlaygroundFlow
  accessToken: string
  refreshToken: string
  idToken: string
  clientId: string
  clientSecret: string
  codeVerifier: string
  codeChallenge: string
  authCode: string
  redirectUri: string
  scopes: string
  state: string
  apiKey: string
  responseData: string | null

  setCurrentFlow: (flow: PlaygroundFlow) => void
  setAccessToken: (token: string) => void
  setRefreshToken: (token: string) => void
  setIdToken: (token: string) => void
  setClientId: (id: string) => void
  setClientSecret: (secret: string) => void
  setCodeVerifier: (verifier: string) => void
  setCodeChallenge: (challenge: string) => void
  setAuthCode: (code: string) => void
  setRedirectUri: (uri: string) => void
  setScopes: (scopes: string) => void
  setState: (state: string) => void
  setApiKey: (key: string) => void
  setResponseData: (data: string | null) => void
  persistTokens: (access?: string, refresh?: string, id?: string) => void
  clearAll: () => void
}

function generateState(): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
  let result = ''
  for (let i = 0; i < 16; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

function generatePkceVerifier(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
  let result = ''
  for (let i = 0; i < 64; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

async function generatePkceChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

export const usePlaygroundStore = create<PlaygroundState>((set) => ({
  currentFlow: 'authorization-code',
  accessToken: '',
  refreshToken: '',
  idToken: '',
  clientId: '',
  clientSecret: '',
  codeVerifier: '',
  codeChallenge: '',
  authCode: '',
  redirectUri: '',
  scopes: 'openid profile email',
  state: generateState(),
  apiKey: '',
  responseData: null,

  setCurrentFlow: (flow) => set({ currentFlow: flow }),
  setAccessToken: (token) => set({ accessToken: token }),
  setRefreshToken: (token) => set({ refreshToken: token }),
  setIdToken: (token) => set({ idToken: token }),
  setClientId: (id) => set({ clientId: id }),
  setClientSecret: (secret) => set({ clientSecret: secret }),
  setCodeVerifier: (verifier) => set({ codeVerifier: verifier }),
  setCodeChallenge: (challenge) => set({ codeChallenge: challenge }),
  setAuthCode: (code) => set({ authCode: code }),
  setRedirectUri: (uri) => set({ redirectUri: uri }),
  setScopes: (scopes) => set({ scopes }),
  setState: (state) => set({ state }),
  setApiKey: (key) => set({ apiKey: key }),
  setResponseData: (data) => set({ responseData: data }),

  persistTokens: (access, refresh, id) =>
    set((s) => ({
      accessToken: access ?? s.accessToken,
      refreshToken: refresh ?? s.refreshToken,
      idToken: id ?? s.idToken,
    })),

  clearAll: () =>
    set({
      accessToken: '',
      refreshToken: '',
      idToken: '',
      clientId: '',
      clientSecret: '',
      codeVerifier: '',
      codeChallenge: '',
      authCode: '',
      redirectUri: '',
      apiKey: '',
      responseData: null,
    }),
}))

export { generateState, generatePkceVerifier, generatePkceChallenge }
