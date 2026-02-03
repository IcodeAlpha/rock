import { ResponseProtocol } from '@/types/psoc';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { Shield, Users, Clock, ChevronRight, AlertTriangle } from 'lucide-react';

interface ResponseProtocolPanelProps {
  protocols: ResponseProtocol[];
  activeLevel?: number;
  onActivate: (level: number) => void;
}

export function ResponseProtocolPanel({ protocols, activeLevel, onActivate }: ResponseProtocolPanelProps) {
  const colorConfig = {
    success: { bg: 'bg-success/10', border: 'border-success/30', text: 'text-success' },
    warning: { bg: 'bg-warning/10', border: 'border-warning/30', text: 'text-warning' },
    high: { bg: 'bg-severity-high/10', border: 'border-severity-high/30', text: 'text-severity-high' },
    critical: { bg: 'bg-destructive/10', border: 'border-destructive/30', text: 'text-destructive' },
  };

  return (
    <div className="rounded-xl border border-border bg-card/50 backdrop-blur-sm overflow-hidden">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" />
          <h3 className="font-semibold">Response Protocols</h3>
        </div>
        {activeLevel && (
          <div className="flex items-center gap-2 px-3 py-1 bg-destructive/20 rounded-lg border border-destructive/30">
            <AlertTriangle className="w-4 h-4 text-destructive" />
            <span className="text-sm font-medium text-destructive">Level {activeLevel} Active</span>
          </div>
        )}
      </div>

      <div className="p-4 space-y-3">
        {protocols.map((protocol) => {
          const config = colorConfig[protocol.color as keyof typeof colorConfig] || colorConfig.success;
          const isActive = activeLevel === protocol.level;
          
          return (
            <div 
              key={protocol.level}
              className={cn(
                "p-4 rounded-lg border transition-all duration-300",
                isActive 
                  ? `${config.border} ${config.bg} ring-2 ring-offset-2 ring-offset-background` 
                  : "border-border hover:border-primary/30 hover:bg-secondary/30",
                isActive && protocol.level >= 4 && "animate-pulse"
              )}
              style={isActive ? { ['--tw-ring-color' as string]: `hsl(var(--${protocol.color === 'critical' ? 'destructive' : protocol.color}))` } : {}}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className={cn(
                      "w-8 h-8 rounded-lg flex items-center justify-center font-bold text-lg",
                      config.bg, config.text
                    )}>
                      {protocol.level}
                    </span>
                    <div>
                      <h4 className="font-semibold">{protocol.name}</h4>
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

                <Button 
                  variant={isActive ? "destructive" : "glass"}
                  size="sm"
                  onClick={() => onActivate(protocol.level)}
                  disabled={isActive}
                >
                  {isActive ? 'Active' : 'Activate'}
                  {!isActive && <ChevronRight className="w-4 h-4 ml-1" />}
                </Button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
