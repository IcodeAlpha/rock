import { useState } from 'react';
import { Incident, IncidentStatus, Severity } from '@/types/psoc';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { 
  AlertTriangle, 
  Clock, 
  Users, 
  ChevronRight,
  Search,
  Plus,
  CheckCircle,
  Eye,
  Loader2
} from 'lucide-react';
import { format } from 'date-fns';
import { Input } from '@/components/ui/input';
import { CreateIncidentWizard, IncidentFormData } from '@/components/wizards/CreateIncidentWizard';
import { useIncidents } from '@/hooks/useIncidents';

export function IncidentsView() {
  const { incidents, isLoading, createIncident, resolveIncident } = useIncidents();
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [filter, setFilter] = useState<IncidentStatus | 'all'>('all');
  const [search, setSearch] = useState('');
  const [isWizardOpen, setIsWizardOpen] = useState(false);

  const handleCreateIncident = (data: IncidentFormData) => {
    createIncident.mutate({
      title: data.title,
      description: data.description,
      severity: data.severity as Severity,
      assignedTeam: data.assignedTeam,
      source: data.source,
    });
  };

  const statusConfig = {
    active: { bg: 'bg-destructive/20', text: 'text-destructive', label: 'Active' },
    investigating: { bg: 'bg-warning/20', text: 'text-warning', label: 'Investigating' },
    contained: { bg: 'bg-primary/20', text: 'text-primary', label: 'Contained' },
    resolved: { bg: 'bg-success/20', text: 'text-success', label: 'Resolved' },
  };

  const filteredIncidents = incidents.filter(inc => {
    const matchesFilter = filter === 'all' || inc.status === filter;
    const matchesSearch = inc.title.toLowerCase().includes(search.toLowerCase()) ||
                          inc.description.toLowerCase().includes(search.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  const handleResolve = (incidentId: string) => {
    resolveIncident.mutate(incidentId);
    setSelectedIncident(null);
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
            <AlertTriangle className="w-7 h-7 text-warning" />
            Incident Management
          </h1>
          <p className="text-muted-foreground mt-1">
            Track and manage security incidents
          </p>
        </div>
        <Button variant="cyber" onClick={() => setIsWizardOpen(true)}>
          <Plus className="w-4 h-4 mr-2" />
          New Incident
        </Button>
      </div>

      <CreateIncidentWizard
        isOpen={isWizardOpen}
        onClose={() => setIsWizardOpen(false)}
        onSubmit={handleCreateIncident}
      />

      {/* Filters */}
      <div className="flex flex-wrap gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search incidents..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="flex gap-2">
          {(['all', 'active', 'investigating', 'contained', 'resolved'] as const).map((status) => (
            <Button
              key={status}
              variant={filter === status ? 'cyber' : 'glass'}
              size="sm"
              onClick={() => setFilter(status)}
            >
              {status === 'all' ? 'All' : statusConfig[status as IncidentStatus]?.label}
            </Button>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {(['active', 'investigating', 'contained', 'resolved'] as const).map((status) => {
          const count = incidents.filter(inc => inc.status === status).length;
          const config = statusConfig[status];
          return (
            <div 
              key={status}
              className={cn(
                "p-4 rounded-lg border border-border",
                config.bg
              )}
            >
              <p className={cn("text-2xl font-bold", config.text)}>{count}</p>
              <p className="text-sm text-muted-foreground">{config.label}</p>
            </div>
          );
        })}
      </div>

      {/* Incidents List */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* List */}
        <div className="space-y-3">
          <h2 className="text-lg font-semibold">
            Incidents ({filteredIncidents.length})
          </h2>
          {filteredIncidents.length === 0 ? (
            <div className="p-8 text-center rounded-lg border border-dashed border-border">
              <AlertTriangle className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
              <p className="text-muted-foreground">No incidents found</p>
            </div>
          ) : (
            <div className="space-y-2">
              {filteredIncidents.map((incident) => {
                const statusCfg = statusConfig[incident.status];
                return (
                  <div
                    key={incident.id}
                    className={cn(
                      "p-4 rounded-lg border border-border bg-card/50 cursor-pointer transition-all hover:border-primary/50",
                      selectedIncident?.id === incident.id && "ring-2 ring-primary"
                    )}
                    onClick={() => setSelectedIncident(incident)}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge variant={incident.severity}>{incident.severity}</Badge>
                          <span className={cn(
                            "text-xs px-2 py-0.5 rounded",
                            statusCfg.bg, statusCfg.text
                          )}>
                            {statusCfg.label}
                          </span>
                        </div>
                        <h3 className="font-medium">{incident.title}</h3>
                        <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                          {incident.description}
                        </p>
                        <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {format(incident.createdAt, 'MMM d, HH:mm')}
                          </span>
                          <span className="flex items-center gap-1">
                            <Users className="w-3 h-3" />
                            {incident.assignedTeam}
                          </span>
                        </div>
                      </div>
                      <ChevronRight className="w-5 h-5 text-muted-foreground" />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Detail Panel */}
        <div className="lg:sticky lg:top-6">
          {selectedIncident ? (
            <div className="rounded-xl border border-border bg-card/50 overflow-hidden">
              <div className="p-4 border-b border-border">
                <div className="flex items-center justify-between">
                  <Badge variant={selectedIncident.severity}>
                    {selectedIncident.severity.toUpperCase()}
                  </Badge>
                  <span className="text-xs text-muted-foreground font-mono">
                    {selectedIncident.id.slice(0, 8).toUpperCase()}
                  </span>
                </div>
                <h2 className="text-lg font-semibold mt-2">{selectedIncident.title}</h2>
                <p className="text-sm text-muted-foreground mt-1">{selectedIncident.description}</p>
              </div>

              <div className="p-4 border-b border-border">
                <h3 className="text-sm font-medium mb-3">Timeline</h3>
                <div className="space-y-3">
                  {selectedIncident.timeline.map((event, i) => (
                    <div key={event.id} className="flex gap-3">
                      <div className="flex flex-col items-center">
                        <div className="w-2 h-2 rounded-full bg-primary" />
                        {i < selectedIncident.timeline.length - 1 && (
                          <div className="w-0.5 flex-1 bg-border mt-1" />
                        )}
                      </div>
                      <div className="flex-1 pb-3">
                        <p className="text-sm font-medium">{event.action}</p>
                        <p className="text-xs text-muted-foreground">{event.details}</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          {event.actor} • {format(event.timestamp, 'MMM d, HH:mm')}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-4 flex gap-3">
                {selectedIncident.status !== 'resolved' && (
                  <Button 
                    variant="success" 
                    className="flex-1"
                    onClick={() => handleResolve(selectedIncident.id)}
                    disabled={resolveIncident.isPending}
                  >
                    <CheckCircle className="w-4 h-4 mr-2" />
                    {resolveIncident.isPending ? 'Resolving...' : 'Resolve'}
                  </Button>
                )}
                <Button variant="glass">
                  <Eye className="w-4 h-4 mr-2" />
                  Full Details
                </Button>
              </div>
            </div>
          ) : (
            <div className="rounded-xl border border-dashed border-border p-12 text-center">
              <Eye className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
              <p className="text-muted-foreground">
                Select an incident to view details
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
