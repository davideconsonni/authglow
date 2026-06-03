interface TableSkeletonProps {
  rows?: number
  columns?: number
}

export function TableSkeleton({ rows = 5, columns = 4 }: TableSkeletonProps) {
  return (
    <div className="rounded-2xl border border-surface-2 bg-surface-1 overflow-hidden">
      <div className="border-b border-surface-2 px-6 py-3">
        <div className="flex gap-6">
          {Array.from({ length: columns }, (_, i) => (
            <div
              key={i}
              className="h-3 rounded bg-surface-2 animate-pulse"
              style={{ width: `${60 + Math.random() * 40}%` }}
            />
          ))}
        </div>
      </div>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="border-b border-surface-2 px-6 py-4 last:border-b-0">
          <div className="flex gap-6">
            {Array.from({ length: columns }, (_, j) => (
              <div
                key={j}
                className="h-4 rounded bg-surface-2/60 animate-pulse"
                style={{ width: `${50 + Math.random() * 50}%` }}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
