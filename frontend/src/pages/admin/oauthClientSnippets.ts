// Quick-start snippet templates for the OAuth-client success screen.
//
// The templates live as plain-text files under `./snippets/` and are inlined
// at build time via Vite `?raw` imports. Keeping them out of `.tsx` source
// means backticks, `${...}` and `<...>` inside the examples can never break
// the page bundle or confuse IDE inspections — placeholders
// (`__CLIENT_ID__`, `__CLIENT_SECRET__`, `__BASE_URL__`, `__SCOPES__`) are
// replaced with real values by `getCodeSnippet`.
import dotnetTpl from './snippets/dotnet.txt?raw'
import goTpl from './snippets/go.txt?raw'
import nextjsTpl from './snippets/nextjs.txt?raw'
import nodeTpl from './snippets/node.txt?raw'
import pythonTpl from './snippets/python.txt?raw'
import reactTpl from './snippets/react.txt?raw'

const TEMPLATES: Record<string, string> = {
  nextjs: nextjsTpl,
  react: reactTpl,
  python: pythonTpl,
  node: nodeTpl,
  go: goTpl,
  dotnet: dotnetTpl,
}

export function getCodeSnippet(
  framework: string,
  client: { client_id: string; client_secret: string },
): string {
  const tpl = TEMPLATES[framework]
  if (!tpl) return ''
  const { client_id, client_secret } = client
  const baseUrl =
    typeof window !== 'undefined' ? window.location.origin : 'https://your-authglow.example.com'
  const scopes = 'openid profile email offline_access'
  return tpl
    .replaceAll('__CLIENT_ID__', client_id)
    .replaceAll('__CLIENT_SECRET__', client_secret)
    .replaceAll('__BASE_URL__', baseUrl)
    .replaceAll('__SCOPES__', scopes)
}

export function getDocUrl(framework: string): string {
  const docs: Record<string, string> = {
    nextjs: 'https://next-auth.js.org/providers/authglow',
    react: 'https://github.com/authglow/react-authglow',
    python: 'https://docs.authlib.org/en/latest/client/oidc.html',
    node: 'https://github.com/panva/node-openid-client',
    go: 'https://github.com/coreos/go-oidc',
    dotnet: 'https://learn.microsoft.com/aspnet/core/security/authentication/oidc',
  }
  return docs[framework] || '#'
}
