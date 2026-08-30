import { Loader2 } from 'lucide-react'

export function LoadingState({ message = 'Loading...' }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-text-muted">
      <Loader2 className="h-8 w-8 animate-spin text-brand-accent" />
      <p className="mt-4 text-sm">{message}</p>
    </div>
  )
}
