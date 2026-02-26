import { useState } from 'react';
import { StatCard } from '@/components/dashboard/StatCard';
import { ThreatChart } from '@/components/dashboard/ThreatChart';
import { PredictionCard } from '@/components/dashboard/PredictionCard';
import { AlertsList } from '@/components/dashboard/AlertsList';
import { IncidentsList } from '@/components/dashboard/IncidentsList';
import { IncidentDetailModal } from '@/components/dashboard/IncidentDetailModal';
import { WeeklyThreatSummary } from '@/components/dashboard/WeeklyThreatSummary';
import { PredictionModal } from '@/components/predictions/PredictionModal';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { 
  Carousel,
  CarouselContent,
  CarouselItem,
  CarouselNext,
  CarouselPrevious,
} from '@/components/ui/carousel';
import { usePredictions } from '@/hooks/usePredictions';
import { useIncidents } from '@/hooks/useIncidents';
import { useAlerts } from '@/hooks/useAlerts';
import { useDashboardStats } from '@/hooks/useDashboardStats';
import { ThreatPrediction, Incident } from '@/types/psoc';
import { Brain, AlertTriangle, Bell, TrendingUp, Shield, DollarSign, Loader2, Activity, ArrowRight } from 'lucide-react';

interface DashboardViewProps {
  onViewChange?: (view: string) => void;
}

export function DashboardView({ onViewChange }: DashboardViewProps) {
  const { predictions, convertToIncident } = usePredictions();
  const { incidents, resolveIncident, isLoading: incidentsLoading } = useIncidents();
  const { alerts, acknowledgeAlert, dismissAlert, isLoading: alertsLoading } = useAlerts();
  const { data: stats, isLoading: statsLoading } = useDashboardStats();
  
  const [selectedPrediction, setSelectedPrediction] = useState<ThreatPrediction | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);

  const handleAcknowledgeAlert = (alertId: string) => {
    acknowledgeAlert.mutate(alertId);
  };

  const handleDismissAlert = (alertId: string) => {
    dismissAlert.mutate(alertId);
  };

  const handleConvertToIncident = (prediction: ThreatPrediction) => {
    convertToIncident.mutate(prediction);
  };

  const handleSelectIncident = (incident: Incident) => {
    setSelectedIncident(incident);
  };

  const handleResolveIncident = (incident: Incident) => {
    resolveIncident.mutate(incident.id);
    setSelectedIncident(null);
  };

  const dashboardStats = stats || {
    activePredictions: 0,
    activeIncidents: 0,
    unresolvedAlerts: 0,
    avgConfidenceScore: 0,
    threatsPreventedThisMonth: 0,
    costSavedEstimate: 0,
  };

  const isLoading = incidentsLoading || alertsLoading || statsLoading;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          title="Active Predictions"
          value={statsLoading ? '...' : dashboardStats.activePredictions}
          icon={Brain}
          variant="primary"
          subtitle="Last 7 days"
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
          {predictions.length === 0 && !isLoading && (
            <span className="text-sm font-normal text-muted-foreground ml-2">
              (Run the AI Prediction Engine to generate predictions)
            </span>
          )}
        </h2>
        {predictions.length > 0 ? (
          <Carousel
            opts={{
              align: "start",
              loop: true,
            }}
            className="w-full"
          >
            <CarouselContent className="-ml-2 md:-ml-4">
              {predictions.map((prediction) => (
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

      {/* Model Performance Card - Full Width */}
      <Card className="border-primary/20 bg-gradient-to-br from-primary/5 to-transparent">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            Model Performance Dashboard
          </CardTitle>
          <CardDescription>
            View real-time metrics, accuracy trends, and per-model predictions
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Intrusion Detection</p>
              <p className="text-2xl font-bold">82.8%</p>
              <p className="text-xs text-muted-foreground">UNSW-NB15 v2.0 • 10 attack types</p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Phishing Detection</p>
              <p className="text-2xl font-bold">92.3%</p>
              <p className="text-xs text-muted-foreground">Custom Dataset v1.0</p>
            </div>
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">Vulnerability Scoring</p>
              <p className="text-2xl font-bold">MAE: 8.34</p>
              <p className="text-xs text-muted-foreground">CISA KEV • R² = 0.78</p>
            </div>
          </div>
          <Button 
            onClick={() => onViewChange?.('performance')}
            className="w-full md:w-auto"
          >
            <Activity className="w-4 h-4 mr-2" />
            Open Performance Dashboard
            <ArrowRight className="w-4 h-4 ml-2" />
          </Button>
        </CardContent>
      </Card>

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
    </div>
  );
}