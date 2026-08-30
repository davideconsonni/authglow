import { Check, Circle } from 'lucide-react'
import { cn } from '../../lib/utils'

interface Step {
  id: string
  label: string
}

interface FlowStepperProps {
  steps: Step[]
  currentStep: string
  completedSteps: string[]
}

export function FlowStepper({ steps, currentStep, completedSteps }: FlowStepperProps) {
  return (
    <div className="flex items-center gap-1 mb-6">
      {steps.map((step, idx) => {
        const isCompleted = completedSteps.includes(step.id)
        const isCurrent = currentStep === step.id
        const isFuture = !isCompleted && !isCurrent

        return (
          <div key={step.id} className="flex items-center gap-1">
            <div
              className={cn(
                'flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 transition-colors',
                isCompleted && 'bg-semantic-success/10 text-semantic-success',
                isCurrent && 'bg-brand-wash text-brand-accent',
                isFuture && 'text-text-muted',
              )}
            >
              <div className="flex items-center justify-center w-5 h-5 rounded-full">
                {isCompleted ? (
                  <Check size={14} />
                ) : isCurrent ? (
                  <Circle size={14} className="fill-current" />
                ) : (
                  <span className="text-xs font-mono">{idx + 1}</span>
                )}
              </div>
              <span className="text-xs font-medium whitespace-nowrap hidden sm:inline">
                {step.label}
              </span>
            </div>
            {idx < steps.length - 1 && (
              <div
                className={cn(
                  'h-px w-4',
                  isCompleted ? 'bg-semantic-success/30' : 'bg-surface-3',
                )}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}
