import { useState } from 'react';
import { ResponseProtocol, ActiveProtocol, ProtocolStep } from '@/types/psoc';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { 
  Shield, 
  Users, 
  Clock, 
  ChevronRight, 
  AlertTriangle,
  CheckCircle,
  Circle,
  Lock,
  Play,
  RotateCcw
} from 'lucide-react';
import { toast } from '@/hooks/use-toast';

interface SequentialProtocolPanelProps {
  protocols: ResponseProtocol[];
  onProtocolComplete?: (level: number) => void;
}

export function SequentialProtocolPanel({ protocols, onProtocolComplete }: SequentialProtocolPanelProps) {
  const [activeProtocol, setActiveProtocol] = useState<ActiveProtocol | null>(null);
  const [completedLevels, setCompletedLevels] = useState<number[]>([]);

  const colorConfig = {
    success: { bg: 'bg-success/10', border: 'border-success/30', text: 'text-success', ring: 'ring-success' },
    warning: { bg: 'bg-warning/10', border: 'border-warning/30', text: 'text-warning', ring: 'ring-warning' },
    high: { bg: 'bg-severity-high/10', border: 'border-severity-high/30', text: 'text-severity-high', ring: 'ring-severity-high' },
    critical: { bg: 'bg-destructive/10', border: 'border-destructive/30', text: 'text-destructive', ring: 'ring-destructive' },
  };

  const canActivateLevel = (level: number) => {
    if (level === 1) return !activeProtocol;
    return completedLevels.includes(level - 1) && !activeProtocol;
  };

  const startProtocol = (protocol: ResponseProtocol) => {
    const steps: ProtocolStep[] = protocol.actions.map((action, i) => ({
      id: `step-${i}`,
      action,
      completed: false,
    }));

    setActiveProtocol({
      level: protocol.level,
      startedAt: new Date(),
      currentStepIndex: 0,
      steps,
      status: 'in_progress',
    });

    toast({
      title: `Level ${protocol.level} Protocol Started`,
      description: `Beginning "${protocol.name}" - Complete all steps in order.`,
    });
  };

  const completeCurrentStep = () => {
    if (!activeProtocol) return;

    const newSteps = [...activeProtocol.steps];
    newSteps[activeProtocol.currentStepIndex] = {
      ...newSteps[activeProtocol.currentStepIndex],
      completed: true,
      completedAt: new Date(),
      completedBy: 'Current User',
    };

    const isLastStep = activeProtocol.currentStepIndex === activeProtocol.steps.length - 1;

    if (isLastStep) {
      setCompletedLevels(prev => [...prev, activeProtocol.level]);
      setActiveProtocol(null);
      onProtocolComplete?.(activeProtocol.level);
      toast({
        title: `Level ${activeProtocol.level} Complete`,
        description: `Protocol completed successfully. ${activeProtocol.level < 5 ? `Level ${activeProtocol.level + 1} is now available.` : 'Maximum response level reached.'}`,
      });
    } else {
      setActiveProtocol({
        ...activeProtocol,
        currentStepIndex: activeProtocol.currentStepIndex + 1,
        steps: newSteps,
      });
      toast({
        title: "Step Completed",
        description: `Moving to step ${activeProtocol.currentStepIndex + 2} of ${activeProtocol.steps.length}`,
      });
    }
  };

  const resetProtocols = () => {
    setActiveProtocol(null);
    setCompletedLevels([]);
    toast({
      title: "Protocols Reset",
      description: "All response protocols have been reset to initial state.",
    });
  };

  return (
    <div className="rounded-xl border border-border bg-card/50 backdrop-blur-sm overflow-hidden">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" />
          <h3 className="font-semibold">Response Protocols</h3>
        </div>
        <div className="flex items-center gap-2">
          {activeProtocol && (
            <div className="flex items-center gap-2 px-3 py-1 bg-primary/20 rounded-lg border border-primary/30 animate-pulse">
              <Play className="w-4 h-4 text-primary" />
              <span className="text-sm font-medium text-primary">Level {activeProtocol.level} In Progress</span>
            </div>
          )}
          {completedLevels.length > 0 && (
            <Button variant="ghost" size="sm" onClick={resetProtocols}>
              <RotateCcw className="w-4 h-4 mr-1" />
              Reset
            </Button>
          )}
        </div>
      </div>

      <div className="p-4 space-y-3">
        {protocols.map((protocol) => {
          const config = colorConfig[protocol.color as keyof typeof colorConfig] || colorConfig.success;
          const isActive = activeProtocol?.level === protocol.level;
          const isCompleted = completedLevels.includes(protocol.level);
          const canActivate = canActivateLevel(protocol.level);
          const isLocked = !canActivate && !isActive && !isCompleted;
          
          return (
            <div 
              key={protocol.level}
              className={cn(
                "rounded-lg border transition-all duration-300 overflow-hidden",
                isActive && `${config.border} ${config.bg} ring-2 ring-offset-2 ring-offset-background ${config.ring}`,
                isCompleted && "border-success/50 bg-success/5",
                isLocked && "opacity-60",
                !isActive && !isCompleted && !isLocked && "border-border hover:border-primary/30"
              )}
            >
              {/* Protocol Header */}
              <div className="p-4">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className={cn(
                        "w-8 h-8 rounded-lg flex items-center justify-center font-bold text-lg",
                        isCompleted ? "bg-success/20 text-success" : `${config.bg} ${config.text}`
                      )}>
                        {isCompleted ? <CheckCircle className="w-5 h-5" /> : protocol.level}
                      </span>
                      <div>
                        <div className="flex items-center gap-2">
                          <h4 className="font-semibold">{protocol.name}</h4>
                          {isLocked && <Lock className="w-3.5 h-3.5 text-muted-foreground" />}
                        </div>
                        <p className="text-xs text-muted-foreground">{protocol.description}</p>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-3 mt-3">
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Users className="w-3.5 h-3.5" />
                        <span>{protocol.teams.slice(0, 2).join(', ')}</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Clock className="w-3.5 h-3.5" />
                        <span>Escalation: {protocol.escalationTime}</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {isCompleted && (
                      <span className="text-xs text-success font-medium px-2 py-1 bg-success/20 rounded">
                        Completed
                      </span>
                    )}
                    {!isActive && !isCompleted && (
                      <Button 
                        variant={canActivate ? "cyber" : "ghost"}
                        size="sm"
                        onClick={() => startProtocol(protocol)}
                        disabled={!canActivate}
                      >
                        {isLocked ? (
                          <>
                            <Lock className="w-4 h-4 mr-1" />
                            Locked
                          </>
                        ) : (
                          <>
                            Start
                            <ChevronRight className="w-4 h-4 ml-1" />
                          </>
                        )}
                      </Button>
                    )}
                  </div>
                </div>
              </div>

              {/* Active Protocol Steps */}
              {isActive && activeProtocol && (
                <div className="border-t border-border bg-background/50 p-4">
                  <p className="text-xs font-medium text-muted-foreground mb-3">
                    Step {activeProtocol.currentStepIndex + 1} of {activeProtocol.steps.length}
                  </p>
                  <div className="space-y-2">
                    {activeProtocol.steps.map((step, index) => {
                      const isCurrent = index === activeProtocol.currentStepIndex;
                      const isPast = step.completed;
                      const isFuture = index > activeProtocol.currentStepIndex;

                      return (
                        <div 
                          key={step.id}
                          className={cn(
                            "flex items-center gap-3 p-3 rounded-lg transition-all",
                            isCurrent && "bg-primary/20 border border-primary/30",
                            isPast && "bg-success/10",
                            isFuture && "opacity-50"
                          )}
                        >
                          {isPast ? (
                            <CheckCircle className="w-5 h-5 text-success flex-shrink-0" />
                          ) : isCurrent ? (
                            <div className="w-5 h-5 rounded-full border-2 border-primary flex items-center justify-center">
                              <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                            </div>
                          ) : (
                            <Circle className="w-5 h-5 text-muted-foreground flex-shrink-0" />
                          )}
                          <span className={cn(
                            "text-sm flex-1",
                            isPast && "text-success",
                            isCurrent && "font-medium",
                            isFuture && "text-muted-foreground"
                          )}>
                            {step.action}
                          </span>
                          {isPast && step.completedAt && (
                            <span className="text-xs text-muted-foreground">
                              ✓ Done
                            </span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                  
                  <Button 
                    onClick={completeCurrentStep}
                    className="w-full mt-4"
                    variant="cyber"
                  >
                    <CheckCircle className="w-4 h-4 mr-2" />
                    Complete Step {activeProtocol.currentStepIndex + 1}
                  </Button>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Progress Summary */}
      {completedLevels.length > 0 && (
        <div className="p-4 border-t border-border bg-success/5">
          <div className="flex items-center gap-2 text-sm">
            <CheckCircle className="w-4 h-4 text-success" />
            <span className="text-success font-medium">
              {completedLevels.length} of {protocols.length} protocols completed
            </span>
          </div>
          <div className="flex gap-1 mt-2">
            {protocols.map((p) => (
              <div 
                key={p.level}
                className={cn(
                  "flex-1 h-2 rounded-full",
                  completedLevels.includes(p.level) ? "bg-success" : "bg-secondary"
                )}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
