// RFC 6749 §3.3: a scope-token is printable ASCII minus space (the
// list separator) and double-quote. On top of that we explicitly
// reject commas: scope lists are SPACE-delimited and "read,write"
// is always a CSV habit, never a real token name.

const SCOPE_TOKEN_RE = /^[\x21\x23-\x5B\x5D-\x7E]+$/

export interface ParsedScopes {
  tokens: string[]
  invalid: string[]
}

function isValidScopeToken(token: string): boolean {
  return SCOPE_TOKEN_RE.test(token) && !token.includes(',')
}

export function parseScopeInput(text: string): ParsedScopes {
  const tokens = text.trim().split(/\s+/).filter(Boolean)
  const invalid = tokens.filter((t) => !isValidScopeToken(t))
  return { tokens, invalid }
}
