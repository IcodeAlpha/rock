import { useState } from 'react';
import { StatCard } from '@/components/dashboard/StatCard';
import { ThreatChart } from '@/components/dashboard/ThreatChart';
import { PredictionCard } from '@/components/dashboard/PredictionCard';
import { AlertsList } from '@/components/dashboard/AlertsList';
import { IncidentsList } from '@/components/dashboard/IncidentsList';
import { IncidentDetailModal } from '@/components/dashboard/IncidentDetailModal';
import { WeeklyThreatSummary } from '@/components/dashboard/WeeklyThreatSummary';
import { PredictionModal } from '@/components/predictions/PredictionModal';
import { AISecurityChat } from '@/components/chat/AISecurityChat';
import { 
  Carousel,
  CarouselContent,
  CarouselItem,
  CarouselNext,
  CarouselPrevious,
} from '@/components/ui/carousel';
import { useBackendThreats } from '@/hooks/useBackendThreats';
import { useBackendStats } from '@/hooks/useBackendStats';
import { useIncidents } from '@/hooks/useIncidents';
import { useAlerts } from '@/hooks/useAlerts';
import { ThreatPrediction, Incident } from '@/types/psoc';
import { Brain, AlertTriangle, Bell, TrendingUp, Shield, DollarSign, Loader2 } from 'lucide-react';

export function DashboardView() {
  const { threats: predictions, loading: predictionsLoading } = useBackendThreats({ limit: 50 });
  const { stats, loading: statsLoading } = useBackendStats();
  const { incidents, resolveIncident, isLoading: incidentsLoading } = useIncidents();
  const { alerts, acknowledgeAlert, dismissAlert, isLoading: alertsLoading } = useAlerts();
  
  const [selectedPrediction, setSelectedPrediction] = useState<ThreatPrediction | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);

  const handleAcknowledgeAlert = (alertId: string) => {
    acknowledgeAlert.mutate(alertId);
  };

  const handleDismissAlert = (alertId: string) => {
    dismissAlert.mutate(alertId);
  };

  const handleConvertToIncident = async (prediction: ThreatPrediction) => {
    // This will be handled by useIncidents when integrated with backend
    console.log('Converting to incident:', prediction);
  };

  const handleSelectIncident = (incident: Incident) => {
    setSelectedIncident(incident);
  };

  const handleResolveIncident = (incident: Incident) => {
    resolveIncident.mutate(incident.id);
    setSelectedIncident(null);
  };

  // Map backend stats to dashboard stats
  const dashboardStats = stats ? {
    activePredictions: stats.total_threats,
    activeIncidents: incidents.filter(i => i.status !== 'resolved').length,
    unresolvedAlerts: alerts.length,
    avgConfidenceScore: Math.round(
      stats.total_threats > 0 
        ? ((stats.by_severity.critical * 90 + stats.by_severity.high * 75 + stats.by_severity.medium * 60 + stats.by_severity.low * 40) / stats.total_threats)
        : 0
    ),
    threatsPreventedThisMonth: stats.recent_24h * 30, // Estimate
    costSavedEstimate: stats.total_threats * 50000, // $50k per threat prevented
  } : {
    activePredictions: 0,
    activeIncidents: 0,
    unresolvedAlerts: 0,
    avgConfidenceScore: 0,
    threatsPreventedThisMonth: 0,
    costSavedEstimate: 0,
  };

  const isLoading = predictionsLoading || incidentsLoading || alertsLoading || statsLoading;

  // Convert backend threats to ThreatPrediction format
  const formattedPredictions: ThreatPrediction[] = predictions.map(threat => ({
    id: threat.id,
    title: threat.title,
    description: threat.description || '',
    severity: threat.severity,
    probability: Math.round(threat.probability * 100),
    confidence: threat.confidence ? Math.round(threat.confidence * 100) : 0,
    impactScore: threat.severity === 'critical' ? 10 : threat.severity === 'high' ? 8 : threat.severity === 'medium' ? 5 : 3,
    timeframe: threat.timeframe || '5-7 days',
    affectedSystems: threat.affected_systems 
  ? (Array.isArray(threat.affected_systems) 
      ? threat.affected_systems              // Already an array, use as-is
      : threat.affected_systems.split(',').map(s => s.trim()))  // String, split it
  : [],
    attackVector: threat.source || 'Unknown',
    indicators: [],
    osintCorrelations: [],
    recommendedActions: [],
    predictedAt: new Date(threat.created_at),
    status: threat.status as 'active' | 'monitoring' | 'dismissed',
  }));

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          title="Active Predictions"
          value={statsLoading ? '...' : dashboardStats.activePredictions}
          icon={Brain}
          variant="primary"
          subtitle="From ML models"
        />
        <StatCard
          title="Active Incidents"
          value={statsLoading ? '...' : dashboardStats.activeIncidents}
          icon={AlertTriangle}
          variant="warning"
          trend={{ value: -15, positive: true }}
        />
        <StatCard
          title="Unresolved Alerts"
          value={statsLoading ? '...' : dashboardStats.unresolvedAlerts}
          icon={Bell}
          variant="destructive"
        />
        <StatCard
          title="Avg Confidence"
          value={statsLoading ? '...' : `${dashboardStats.avgConfidenceScore}%`}
          icon={TrendingUp}
          variant="success"
          trend={{ value: 5, positive: true }}
        />
        <StatCard
          title="Threats Prevented"
          value={statsLoading ? '...' : dashboardStats.threatsPreventedThisMonth}
          icon={Shield}
          subtitle="This month"
        />
        <StatCard
          title="Cost Saved"
          value={statsLoading ? '...' : `$${(dashboardStats.costSavedEstimate / 1000000).toFixed(1)}M`}
          icon={DollarSign}
          variant="success"
          subtitle="Estimated"
        />
      </div>

      {/* Predictions Carousel */}
      <div>
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Brain className="w-5 h-5 text-primary" />
          Active Threat Predictions
          {formattedPredictions.length === 0 && !isLoading && (
            <span className="text-sm font-normal text-muted-foreground ml-2">
              (Run the AI Prediction Engine to generate predictions)
            </span>
          )}
        </h2>
        {formattedPredictions.length > 0 ? (
          <Carousel
            opts={{
              align: "start",
              loop: true,
            }}
            className="w-full"
          >
            <CarouselContent className="-ml-2 md:-ml-4">
              {formattedPredictions.map((prediction) => (
                <CarouselItem key={prediction.id} className="pl-2 md:pl-4 basis-full">
                  <PredictionCard
                    prediction={prediction}
                    onViewDetails={setSelectedPrediction}
                    onConvertToIncident={handleConvertToIncident}
                  />
                </CarouselItem>
              ))}
            </CarouselContent>
            <CarouselPrevious className="left-0 -translate-x-1/2 bg-background/80 backdrop-blur-sm border-primary/30 hover:bg-primary/20" />
            <CarouselNext className="right-0 translate-x-1/2 bg-background/80 backdrop-blur-sm border-primary/30 hover:bg-primary/20" />
          </Carousel>
        ) : (
          <div className="p-8 rounded-lg border border-dashed border-border text-center">
            <Brain className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
            <p className="text-muted-foreground">
              No active predictions. Run the AI Prediction Engine from the Predictions page.
            </p>
          </div>
        )}
      </div>

      {/* Incidents, Alerts & Weekly Summary Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <IncidentsList 
          incidents={incidents.filter(i => i.status !== 'resolved').slice(0, 5)} 
          onSelectIncident={handleSelectIncident}
        />
        <AlertsList
          alerts={alerts.slice(0, 5)}
          onAcknowledge={handleAcknowledgeAlert}
          onDismiss={handleDismissAlert}
        />
        <WeeklyThreatSummary />
      </div>

      {/* Threat Activity Timeline - Full Width */}
      <ThreatChart />

      {/* Prediction Modal */}
      <PredictionModal
        prediction={selectedPrediction}
        isOpen={!!selectedPrediction}
        onClose={() => setSelectedPrediction(null)}
        onConvertToIncident={handleConvertToIncident}
      />

      {/* Incident Detail Modal */}
      <IncidentDetailModal
        incident={selectedIncident}
        isOpen={!!selectedIncident}
        onClose={() => setSelectedIncident(null)}
        onResolve={handleResolveIncident}
      />

      {/* AI Security Chat */}
<div className="col-span-full lg:col-span-2">
  <AISecurityChat />
</div>
    </div>
  );
}