import { Alert } from '@/types/psoc';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { Bell, Check, X, Clock } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

interface AlertsListProps {
  alerts: Alert[];
  onAcknowledge: (alertId: string) => void;
  onDismiss: (alertId: string) => void;
}

export function AlertsList({ alerts, onAcknowledge, onDismiss }: AlertsListProps) {
  const severityConfig = {
    critical: { badge: 'critical' as const, icon: 'text-destructive', bg: 'bg-destructive/10' },
    high: { badge: 'high' as const, icon: 'text-severity-high', bg: 'bg-severity-high/10' },
    medium: { badge: 'medium' as const, icon: 'text-warning', bg: 'bg-warning/10' },
    low: { badge: 'low' as const, icon: 'text-success', bg: 'bg-success/10' },
  };

  return (
    <div className="rounded-xl border border-border bg-card/50 backdrop-blur-sm overflow-hidden">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bell className="w-5 h-5 text-primary" />
          <h3 className="font-semibold">Recent Alerts</h3>
        </div>
        <Badge variant="info">{alerts.filter(a => !a.acknowledged).length} unread</Badge>
      </div>
      
      <div className="divide-y divide-border max-h-96 overflow-y-auto">
        {alerts.map((alert) => {
          const config = severityConfig[alert.severity];
          
          return (
            <div 
              key={alert.id}
              className={cn(
                "p-4 transition-all duration-200 hover:bg-secondary/30",
                !alert.acknowledged && config.bg
              )}
            >
              <div className="flex items-start gap-3">
                <div className={cn(
                  "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0",
                  config.bg
                )}>
                  <Bell className={cn("w-4 h-4", config.icon)} />
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge variant={config.badge} className="text-xs">
                      {alert.severity}
                    </Badge>
                    <span className="text-xs text-muted-foreground font-mono">
                      {alert.source}
                    </span>
                  </div>
                  <h4 className="font-medium text-sm mb-1 truncate">{alert.title}</h4>
                  <p className="text-xs text-muted-foreground line-clamp-2">{alert.message}</p>
                  <div className="flex items-center gap-1 mt-2 text-xs text-muted-foreground">
                    <Clock className="w-3 h-3" />
                    {formatDistanceToNow(alert.timestamp, { addSuffix: true })}
                  </div>
                </div>

                {!alert.acknowledged && (
                  <div className="flex items-center gap-1">
                    <Button 
                      variant="ghost" 
                      size="icon" 
                      className="h-7 w-7 hover:bg-success/20 hover:text-success"
                      onClick={() => onAcknowledge(alert.id)}
                    >
                      <Check className="w-4 h-4" />
                    </Button>
                    <Button 
                      variant="ghost" 
                      size="icon" 
                      className="h-7 w-7 hover:bg-destructive/20 hover:text-destructive"
                      onClick={() => onDismiss(alert.id)}
                    >
                      <X className="w-4 h-4" />
                    </Button>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
