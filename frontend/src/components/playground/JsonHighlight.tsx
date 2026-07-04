import { useMemo } from 'react'

function highlight(json: string): string {
  let html = ''
  let i = 0

  while (i < json.length) {
    const ch = json[i]

    if (ch === '&') { html += '&amp;'; i++; continue }
    if (ch === '<') { html += '&lt;'; i++; continue }
    if (ch === '>') { html += '&gt;'; i++; continue }

    if (ch === '"') {
      let content = ''
      i++
      while (i < json.length) {
        if (json[i] === '\\' && i + 1 < json.length) {
          content += '\\' + json[i + 1]
          i += 2
          continue
        }
        if (json[i] === '"') {
          i++
          break
        }
        if (json[i] === '&') content += '&amp;'
        else if (json[i] === '<') content += '&lt;'
        else if (json[i] === '>') content += '&gt;'
        else content += json[i]
        i++
      }

      let j = i
      while (j < json.length && json[j] === ' ') j++
      if (j < json.length && json[j] === ':') {
        html += '<span class="text-brand-violet">"' + content + '"</span>:'
        i = j + 1
      } else {
        html += '<span class="text-semantic-success">"' + content + '"</span>'
      }
      continue
    }

    if ((ch >= '0' && ch <= '9') || ch === '-') {
      let num = ''
      while (i < json.length && '0123456789.eE+-'.includes(json[i])) {
        num += json[i]
        i++
      }
      html += '<span class="text-brand-blue">' + num + '</span>'
      continue
    }

    if (json.slice(i, i + 4) === 'true') {
      html += '<span class="text-semantic-warning">true</span>'
      i += 4
      continue
    }
    if (json.slice(i, i + 5) === 'false') {
      html += '<span class="text-semantic-warning">false</span>'
      i += 5
      continue
    }
    if (json.slice(i, i + 4) === 'null') {
      html += '<span class="text-semantic-warning">null</span>'
      i += 4
      continue
    }

    html += ch
    i++
  }

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
