import { useMemo } from 'react'

const JSON_KEY = /("(?:[^"\\]|\\.)*")\s*:/g
const JSON_STRING = /("(?:[^"\\]|\\.)*")/g
const JSON_NUMBER = /(-?\d+\.?\d*(?:[eE][+-]?\d+)?)/g
const JSON_BOOL_NULL = /\b(true|false|null)\b/g

function highlight(json: string): string {
  let html = json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')

  html = html.replace(JSON_KEY, '<span class="text-brand-violet">$1</span>:')
  html = html.replace(JSON_BOOL_NULL, '<span class="text-amber-400">$1</span>')
  html = html.replace(JSON_NUMBER, '<span class="text-emerald-400">$1</span>')
  html = html.replace(JSON_STRING, (match) => {
    if (match.includes('text-brand-violet')) return match
    return `<span class="text-emerald-300">${match}</span>`
  })

  return html
}

export function JsonHighlight({ json, maxHeight = 'max-h-[500px]' }: { json: string; maxHeight?: string }) {
  const highlighted = useMemo(() => highlight(json), [json])

  return (
    <pre
      className={`min-h-[120px] ${maxHeight} overflow-auto rounded-xl border border-surface-2 bg-surface-2/50 p-4 font-mono text-xs whitespace-pre-wrap leading-relaxed`}
      dangerouslySetInnerHTML={{ __html: highlighted }}
    />
  )
}
