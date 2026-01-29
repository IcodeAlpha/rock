import { Incident } from '@/types/psoc';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { cn } from '@/lib/utils';
import { 
  AlertTriangle, 
  Clock, 
  Users, 
  Server, 
  CheckCircle,
  XCircle,
  Shield,
  Activity
} from 'lucide-react';
import { formatDistanceToNow, format } from 'date-fns';

interface IncidentDetailModalProps {
  incident: Incident | null;
  isOpen: boolean;
  onClose: () => void;
  onResolve?: (incident: Incident) => void;
}

export function IncidentDetailModal({ incident, isOpen, onClose, onResolve }: IncidentDetailModalProps) {
  if (!incident) return null;

  const statusConfig = {
    active: { color: 'bg-destructive', text: 'text-destructive', label: 'Active' },
    investigating: { color: 'bg-warning', text: 'text-warning', label: 'Investigating' },
    contained: { color: 'bg-primary', text: 'text-primary', label: 'Contained' },
    resolved: { color: 'bg-success', text: 'text-success', label: 'Resolved' },
  };

  const status = statusConfig[incident.status];

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <div className="flex items-center gap-3">
            <div className={cn("w-4 h-4 rounded-full", status.color, incident.status === 'active' && "animate-pulse")} />
            <DialogTitle className="text-xl">{incident.title}</DialogTitle>
          </div>
        </DialogHeader>

        <div className="space-y-6 mt-4">
          {/* Status & Severity Row */}
          <div className="flex flex-wrap items-center gap-3">
            <Badge variant={incident.severity as 'critical' | 'high' | 'medium' | 'low'} className="text-sm">
              {incident.severity.toUpperCase()}
            </Badge>
            <Badge variant="outline" className={cn("font-medium", status.text)}>
              {status.label}
            </Badge>
            <span className="text-xs text-muted-foreground font-mono uppercase">
              {incident.id}
            </span>
            <Badge variant="secondary" className="ml-auto">
              Response Level {incident.responseLevel}
            </Badge>
          </div>

          {/* Description */}
          <div className="p-4 rounded-lg bg-secondary/30 border border-border">
            <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
              <Activity className="w-4 h-4 text-primary" />
              Description
            </h4>
            <p className="text-sm text-muted-foreground">{incident.description}</p>
          </div>

          {/* Info Grid */}
          <div className="grid grid-cols-2 gap-4">
            <div className="p-3 rounded-lg bg-secondary/20 border border-border">
              <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
                <Users className="w-3 h-3" />
                Assigned Team
              </div>
              <p className="text-sm font-medium">{incident.assignedTeam}</p>
            </div>
            <div className="p-3 rounded-lg bg-secondary/20 border border-border">
              <div className="flex items-center gap-2 text-xs text-muted-foreground mb-1">
                <Clock className="w-3 h-3" />
                Created
              </div>
              <p className="text-sm font-medium">
                {formatDistanceToNow(incident.createdAt, { addSuffix: true })}
              </p>
            </div>
          </div>

          {/* Affected Systems */}
          <div>
            <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
              <Server className="w-4 h-4 text-warning" />
              Affected Systems
            </h4>
            <div className="flex flex-wrap gap-2">
              {incident.affectedSystems.map((system, index) => (
                <Badge key={index} variant="outline" className="text-xs">
                  {system}
                </Badge>
              ))}
            </div>
          </div>

          {/* Timeline */}
          <div>
            <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
              <Clock className="w-4 h-4 text-primary" />
              Incident Timeline
            </h4>
            <div className="space-y-3 pl-4 border-l-2 border-border">
              {incident.timeline.map((event, index) => (
                <div key={index} className="relative">
                  <div className="absolute -left-[21px] top-1 w-2 h-2 rounded-full bg-primary" />
                  <div className="text-xs text-muted-foreground mb-1">
                    {format(event.timestamp, 'MMM d, HH:mm')}
                  </div>
                  <p className="text-sm">{event.action}</p>
                  {event.actor && (
                    <p className="text-xs text-muted-foreground mt-0.5">by {event.actor}</p>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-3 pt-4 border-t border-border">
            {incident.status !== 'resolved' && onResolve && (
              <Button variant="cyber" onClick={() => onResolve(incident)}>
                <CheckCircle className="w-4 h-4 mr-2" />
                Mark Resolved
              </Button>
            )}
            <Button variant="glass" onClick={onClose}>
              <XCircle className="w-4 h-4 mr-2" />
              Close
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
