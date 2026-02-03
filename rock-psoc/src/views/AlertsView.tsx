import { useState } from 'react';
import { Alert } from '@/types/psoc';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { 
  Bell, 
  Check, 
  X, 
  Clock,
  CheckCheck,
  AlertTriangle,
  Plus,
  Loader2
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { CreateAlertWizard, AlertFormData } from '@/components/wizards/CreateAlertWizard';
import { useAlerts } from '@/hooks/useAlerts';
import { Severity } from '@/types/psoc';

export function AlertsView() {
  const { alerts, isLoading, createAlert, acknowledgeAlert, dismissAlert, acknowledgeAll } = useAlerts();
  const [filter, setFilter] = useState<'all' | 'unacknowledged' | 'acknowledged'>('all');
  const [isWizardOpen, setIsWizardOpen] = useState(false);

  const handleCreateAlert = (data: AlertFormData) => {
    createAlert.mutate({
      title: data.title,
      description: data.description,
      severity: data.severity as Severity,
      source: data.source,
    });
  };

  const filteredAlerts = alerts.filter(alert => {
    if (filter === 'all') return true;
    if (filter === 'unacknowledged') return !alert.acknowledged;
    return alert.acknowledged;
  });

  const unacknowledgedCount = alerts.filter(a => !a.acknowledged).length;

  const handleAcknowledge = (alertId: string) => {
    acknowledgeAlert.mutate(alertId);
  };

  const handleDismiss = (alertId: string) => {
    dismissAlert.mutate(alertId);
  };

  const handleAcknowledgeAll = () => {
    acknowledgeAll.mutate();
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Bell className="w-7 h-7 text-primary" />
            Alerts Center
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time security notifications and alerts
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="cyber" onClick={() => setIsWizardOpen(true)}>
            <Plus className="w-4 h-4 mr-2" />
            Create Alert
          </Button>
          {unacknowledgedCount > 0 && (
            <Button variant="glass" onClick={handleAcknowledgeAll} disabled={acknowledgeAll.isPending}>
              <CheckCheck className="w-4 h-4 mr-2" />
              Acknowledge All ({unacknowledgedCount})
            </Button>
          )}
        </div>
      </div>

      <CreateAlertWizard
        isOpen={isWizardOpen}
        onClose={() => setIsWizardOpen(false)}
        onSubmit={handleCreateAlert}
      />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-lg border border-border bg-card/50">
          <p className="text-2xl font-bold">{alerts.length}</p>
          <p className="text-sm text-muted-foreground">Total Alerts</p>
        </div>
        <div className="p-4 rounded-lg border border-destructive/30 bg-destructive/10">
          <p className="text-2xl font-bold text-destructive">{unacknowledgedCount}</p>
          <p className="text-sm text-muted-foreground">Unacknowledged</p>
        </div>
        <div className="p-4 rounded-lg border border-success/30 bg-success/10">
          <p className="text-2xl font-bold text-success">{alerts.filter(a => a.acknowledged).length}</p>
          <p className="text-sm text-muted-foreground">Acknowledged</p>
        </div>
        <div className="p-4 rounded-lg border border-warning/30 bg-warning/10">
          <p className="text-2xl font-bold text-warning">
            {alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length}
          </p>
          <p className="text-sm text-muted-foreground">High Priority</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        {(['all', 'unacknowledged', 'acknowledged'] as const).map((f) => (
          <Button
            key={f}
            variant={filter === f ? 'cyber' : 'glass'}
            size="sm"
            onClick={() => setFilter(f)}
          >
            {f === 'all' && 'All'}
            {f === 'unacknowledged' && `Unacknowledged (${unacknowledgedCount})`}
            {f === 'acknowledged' && 'Acknowledged'}
          </Button>
        ))}
      </div>

      {/* Alerts List */}
      <div className="space-y-3">
        {filteredAlerts.length === 0 ? (
          <div className="p-12 text-center rounded-lg border border-dashed border-border">
            <Bell className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
            <p className="text-muted-foreground">No alerts to display</p>
          </div>
        ) : (
          filteredAlerts.map((alert) => (
            <div
              key={alert.id}
              className={cn(
                "p-4 rounded-lg border transition-all",
                alert.acknowledged 
                  ? "border-border bg-card/30 opacity-75" 
                  : "border-primary/30 bg-card/50"
              )}
            >
              <div className="flex items-start gap-4">
                <div className={cn(
                  "w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0",
                  alert.severity === 'critical' && "bg-destructive/20",
                  alert.severity === 'high' && "bg-severity-high/20",
                  alert.severity === 'medium' && "bg-warning/20",
                  alert.severity === 'low' && "bg-success/20"
                )}>
                  <AlertTriangle className={cn(
                    "w-5 h-5",
                    alert.severity === 'critical' && "text-destructive",
                    alert.severity === 'high' && "text-severity-high",
                    alert.severity === 'medium' && "text-warning",
                    alert.severity === 'low' && "text-success"
                  )} />
                </div>

                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge variant={alert.severity}>{alert.severity}</Badge>
                    {alert.acknowledged && (
                      <span className="text-xs text-success flex items-center gap-1">
                        <Check className="w-3 h-3" /> Acknowledged
                      </span>
                    )}
                  </div>
                  <h3 className="font-medium">{alert.title}</h3>
                  <p className="text-sm text-muted-foreground mt-1">{alert.message}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {formatDistanceToNow(alert.timestamp, { addSuffix: true })}
                    </span>
                    <span>Source: {alert.source}</span>
                  </div>
                </div>

                <div className="flex gap-2">
                  {!alert.acknowledged && (
                    <Button
                      variant="glass"
                      size="sm"
                      onClick={() => handleAcknowledge(alert.id)}
                      disabled={acknowledgeAlert.isPending}
                    >
                      <Check className="w-4 h-4" />
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleDismiss(alert.id)}
                    disabled={dismissAlert.isPending}
                  >
                    <X className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
