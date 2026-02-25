import { ThreatPrediction } from '@/types/psoc';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  AlertTriangle, 
  Target, 
  Clock, 
  TrendingUp, 
  Shield, 
  Globe, 
  CheckCircle,
  XCircle,
  ChevronRight
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { cn } from '@/lib/utils';

interface PredictionModalProps {
  prediction: ThreatPrediction | null;
  isOpen: boolean;
  onClose: () => void;
  onConvertToIncident: (prediction: ThreatPrediction) => void;
}

export function PredictionModal({
  prediction,
  isOpen,
  onClose,
  onConvertToIncident
}: PredictionModalProps) {
  if (!prediction) return null;

  const severityConfig = {
    critical: { badge: 'critical' as const, color: 'text-destructive', bg: 'bg-destructive/10' },
    high: { badge: 'high' as const, color: 'text-severity-high', bg: 'bg-severity-high/10' },
    medium: { badge: 'medium' as const, color: 'text-warning', bg: 'bg-warning/10' },
    low: { badge: 'low' as const, color: 'text-success', bg: 'bg-success/10' },
  };

  // ✅ Normalize + fallback
  const normalizedSeverity =
    prediction?.severity?.toLowerCase?.() as keyof typeof severityConfig;

  const config =
    severityConfig[normalizedSeverity] ?? severityConfig.low;

  const affectedSystems = prediction.affectedSystems ?? [];
  const indicators = prediction.indicators ?? [];
  const osintCorrelations = prediction.osintCorrelations ?? [];
  const recommendedActions = prediction.recommendedActions ?? [];

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-hidden bg-card border-border">
        <DialogHeader className="border-b border-border pb-4">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Badge variant={config.badge} className="uppercase font-bold">
                  {normalizedSeverity ?? 'low'}
                </Badge>
                <span className="text-sm text-muted-foreground font-mono">
                  {prediction.id?.toUpperCase?.() ?? 'UNKNOWN'}
                </span>
              </div>
              <DialogTitle className="text-xl">
                {prediction.title ?? 'Untitled Prediction'}
              </DialogTitle>
              <p className="text-sm text-muted-foreground mt-1">
                Predicted{' '}
                {prediction.predictedAt
                  ? formatDistanceToNow(prediction.predictedAt, { addSuffix: true })
                  : 'recently'}
              </p>
            </div>
            <div className={cn("p-4 rounded-xl text-center", config.bg)}>
              <div className={cn("text-4xl font-bold", config.color)}>
                {prediction.probability ?? 0}%
              </div>
              <div className="text-xs text-muted-foreground">Probability</div>
            </div>
          </div>
        </DialogHeader>

        <Tabs defaultValue="overview" className="flex-1 overflow-hidden">
          <TabsList className="w-full justify-start bg-secondary/50 p-1">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="analysis">Analysis</TabsTrigger>
            <TabsTrigger value="actions">Recommended Actions</TabsTrigger>
          </TabsList>

          <div className="overflow-y-auto max-h-[50vh] mt-4">
            <TabsContent value="overview" className="space-y-4 mt-0">
              <div className="grid grid-cols-4 gap-3">
                <Metric icon={<TrendingUp className="w-4 h-4" />} label="Confidence" value={`${prediction.confidence ?? 0}%`} />
                <Metric icon={<Target className="w-4 h-4" />} label="Impact Score" value={`${prediction.impactScore ?? 0}/10`} />
                <Metric icon={<Clock className="w-4 h-4" />} label="Timeframe" value={prediction.timeframe ?? 'N/A'} />
                <Metric icon={<Shield className="w-4 h-4" />} label="Attack Vector" value={prediction.attackVector ?? 'Unknown'} />
              </div>

              <div className="p-4 rounded-lg bg-secondary/30 border border-border">
                <h4 className="font-semibold mb-2">Description</h4>
                <p className="text-sm text-muted-foreground">
                  {prediction.description ?? 'No description provided.'}
                </p>
              </div>

              <div>
                <h4 className="font-semibold mb-3">Affected Systems</h4>
                <div className="flex flex-wrap gap-2">
                  {affectedSystems.length > 0 ? (
                    affectedSystems.map((system, idx) => (
                      <span key={idx} className="px-3 py-1.5 text-sm bg-secondary rounded-lg border border-border">
                        {system}
                      </span>
                    ))
                  ) : (
                    <span className="text-sm text-muted-foreground">None listed</span>
                  )}
                </div>
              </div>

              <div>
                <h4 className="font-semibold mb-3">Threat Indicators</h4>
                <div className="space-y-2">
                  {indicators.length > 0 ? (
                    indicators.map((indicator, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-sm">
                        <AlertTriangle className="w-4 h-4 text-warning" />
                        {indicator}
                      </div>
                    ))
                  ) : (
                    <span className="text-sm text-muted-foreground">No indicators</span>
                  )}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="analysis" className="space-y-4 mt-0">
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Globe className="w-5 h-5 text-primary" />
                  <h4 className="font-semibold">OSINT Correlations</h4>
                </div>

                {osintCorrelations.length > 0 ? (
                  osintCorrelations.map((correlation, idx) => (
                    <div key={idx} className="p-4 rounded-lg bg-secondary/30 border border-border">
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-medium">{correlation.source}</span>
                            <Badge variant="info" className="text-xs capitalize">
                              {correlation.type}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground">{correlation.indicator}</p>
                        </div>
                        <div className="text-right">
                          <div className="text-xl font-bold text-primary">
                            {correlation.matchScore ?? 0}%
                          </div>
                          <div className="text-xs text-muted-foreground">Match Score</div>
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <span className="text-sm text-muted-foreground">No OSINT correlations</span>
                )}
              </div>
            </TabsContent>

            <TabsContent value="actions" className="space-y-4 mt-0">
              {recommendedActions.length > 0 ? (
                recommendedActions.map((action, idx) => (
                  <div key={idx} className="flex items-center gap-3 p-4 rounded-lg bg-secondary/30 border border-border">
                    <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary font-bold">
                      {idx + 1}
                    </div>
                    <span className="flex-1 text-sm">{action}</span>
                    <Button variant="ghost" size="sm">
                      <CheckCircle className="w-4 h-4 mr-1" />
                      Mark Done
                    </Button>
                  </div>
                ))
              ) : (
                <span className="text-sm text-muted-foreground">No recommended actions</span>
              )}
            </TabsContent>
          </div>
        </Tabs>

        <div className="flex items-center justify-between pt-4 border-t border-border">
          <Button variant="outline" onClick={onClose}>
            <XCircle className="w-4 h-4 mr-2" />
            Close
          </Button>
          <Button
            variant="cyber"
            onClick={() => {
              onConvertToIncident(prediction);
              onClose();
            }}
          >
            <AlertTriangle className="w-4 h-4 mr-2" />
            Convert to Incident
            <ChevronRight className="w-4 h-4 ml-1" />
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

/* Small helper for cleaner metric UI */
function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="p-4 rounded-lg bg-secondary/50 border border-border">
      <div className="flex items-center gap-2 text-muted-foreground mb-2">
        {icon}
        <span className="text-xs">{label}</span>
      </div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
  );
}