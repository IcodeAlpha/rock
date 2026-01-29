import { Incident } from '@/types/psoc';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { AlertTriangle, Clock, Users, ChevronRight } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

interface IncidentsListProps {
  incidents: Incident[];
  onSelectIncident: (incident: Incident) => void;
}

export function IncidentsList({ incidents, onSelectIncident }: IncidentsListProps) {
  const statusConfig = {
    active: { color: 'bg-destructive', text: 'text-destructive' },
    investigating: { color: 'bg-warning', text: 'text-warning' },
    contained: { color: 'bg-primary', text: 'text-primary' },
    resolved: { color: 'bg-success', text: 'text-success' },
  };

  const severityBadge = {
    critical: 'critical' as const,
    high: 'high' as const,
    medium: 'medium' as const,
    low: 'low' as const,
  };

  return (
    <div className="rounded-xl border border-border bg-card/50 backdrop-blur-sm overflow-hidden">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-warning" />
          <h3 className="font-semibold">Active Incidents</h3>
        </div>
        <Badge variant="outline">{incidents.length} total</Badge>
      </div>

      <div className="divide-y divide-border">
        {incidents.map((incident) => {
          const status = statusConfig[incident.status];
          
          return (
            <button
              key={incident.id}
              onClick={() => onSelectIncident(incident)}
              className="w-full p-4 text-left transition-all duration-200 hover:bg-secondary/30 group"
            >
              <div className="flex items-start gap-3">
                <div className={cn(
                  "w-3 h-3 rounded-full mt-1.5 flex-shrink-0",
                  status.color,
                  incident.status === 'active' && "animate-pulse"
                )} />
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge variant={severityBadge[incident.severity]} className="text-xs">
                      {incident.severity}
                    </Badge>
                    <span className="text-xs text-muted-foreground font-mono uppercase">
                      {incident.id}
                    </span>
                    <span className={cn(
                      "text-xs font-medium capitalize px-2 py-0.5 rounded",
                      `${status.text} bg-current/10`
                    )}>
                      {incident.status}
                    </span>
                  </div>
                  
                  <h4 className="font-medium text-sm mb-2 group-hover:text-primary transition-colors">
                    {incident.title}
                  </h4>
                  
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <div className="flex items-center gap-1">
                      <Users className="w-3 h-3" />
                      {incident.assignedTeam}
                    </div>
                    <div className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {formatDistanceToNow(incident.createdAt, { addSuffix: true })}
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="font-medium">Level {incident.responseLevel}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground group-hover:text-primary transition-colors hidden sm:inline">
                    Full Details
                  </span>
                  <ChevronRight className="w-5 h-5 text-muted-foreground group-hover:text-primary transition-colors" />
                </div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
