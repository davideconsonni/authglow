import { useState } from 'react'
import { RefreshCw, Download, Copy, Check } from 'lucide-react'
import { Loader2 } from 'lucide-react'
import { api } from '@/lib/api'

interface BackupCodesProps {
  codes: string[]
  onRegenerate: () => void
}

export function BackupCodes({ codes, onRegenerate }: BackupCodesProps) {
  const [copied, setCopied] = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [regenerating, setRegenerating] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(codes.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownload = () => {
    setDownloading(true)
    const content = codes.join('\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'authglow-backup-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
    setTimeout(() => setDownloading(false), 500)
  }

  const handleRegenerate = async () => {
    setRegenerating(true)
    try {
      await api.post('/api/mfa/regenerate-backup-codes')
      onRegenerate()
    } catch {
      // handled by parent
    } finally {
      setRegenerating(false)
    }
  }

  const remaining = codes.length
  const total = 10

  return (
    <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-text-primary">Backup Codes</h3>
          <p className="text-xs text-text-muted">
            {remaining} of {total} codes remaining
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 rounded-lg bg-surface-2 px-2.5 py-1 text-xs text-text-secondary hover:text-text-primary transition-colors"
          >
            {copied ? <Check size={12} className="text-semantic-success" /> : <Copy size={12} />}
            {copied ? 'Copied' : 'Copy all'}
          </button>
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="flex items-center gap-1 rounded-lg bg-surface-2 px-2.5 py-1 text-xs text-text-secondary hover:text-text-primary transition-colors"
          >
            <Download size={12} />
            Download
          </button>
          <button
            onClick={handleRegenerate}
            disabled={regenerating}
            className="flex items-center gap-1 rounded-lg bg-surface-2 px-2.5 py-1 text-xs text-text-secondary hover:text-text-primary transition-colors"
          >
            {regenerating ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
            Regenerate
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2">
        {codes.map((code, i) => (
          <code
            key={i}
            className="rounded-lg bg-surface-2 px-3 py-1.5 text-center text-xs font-mono text-text-secondary"
          >
            {code}
          </code>
        ))}
      </div>

      {remaining <= 2 && (
        <p className="text-xs text-semantic-warning">
          You are running low on backup codes. Regenerate soon.
        </p>
      )}
    </div>
  )
}
