/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL?: string
  readonly VITE_AUTHGLOW_CLIENT_ID?: string
  readonly VITE_AUTHGLOW_ISSUER?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
