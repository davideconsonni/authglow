import { useState } from 'react'
import { Copy, Check } from 'lucide-react'

interface CopyButtonProps {
  text: string
  label?: string
  className?: string
}

export function CopyButton({ text, label, className = '' }: CopyButtonProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button
      onClick={handleCopy}
      className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs font-medium transition-all ${
        copied
          ? 'bg-semantic-success/10 text-semantic-success'
          : 'bg-surface-2 text-text-muted hover:text-text-secondary hover:bg-surface-3'
      } ${className}`}
      aria-label={label || 'Copy to clipboard'}
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
      {label && <span>{label}</span>}
    </button>
  )
}
