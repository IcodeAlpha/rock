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

export function PredictionModal({ prediction, isOpen, onClose, onConvertToIncident }: PredictionModalProps) {
  if (!prediction) return null;

  const severityConfig = {
    critical: { badge: 'critical' as const, color: 'text-destructive', bg: 'bg-destructive/10' },
    high: { badge: 'high' as const, color: 'text-severity-high', bg: 'bg-severity-high/10' },
    medium: { badge: 'medium' as const, color: 'text-warning', bg: 'bg-warning/10' },
    low: { badge: 'low' as const, color: 'text-success', bg: 'bg-success/10' },
  };

  const config = severityConfig[prediction.severity];

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-hidden bg-card border-border">
        <DialogHeader className="border-b border-border pb-4">
          <div className="flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Badge variant={config.badge} className="uppercase font-bold">
                  {prediction.severity}
                </Badge>
                <span className="text-sm text-muted-foreground font-mono">
                  {prediction.id.toUpperCase()}
                </span>
              </div>
              <DialogTitle className="text-xl">{prediction.title}</DialogTitle>
              <p className="text-sm text-muted-foreground mt-1">
                Predicted {formatDistanceToNow(prediction.predictedAt, { addSuffix: true })}
              </p>
            </div>
            <div className={cn("p-4 rounded-xl text-center", config.bg)}>
              <div className={cn("text-4xl font-bold", config.color)}>{prediction.probability}%</div>
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
              {/* Metrics Grid */}
              <div className="grid grid-cols-4 gap-3">
                <div className="p-4 rounded-lg bg-secondary/50 border border-border">
                  <div className="flex items-center gap-2 text-muted-foreground mb-2">
                    <TrendingUp className="w-4 h-4" />
                    <span className="text-xs">Confidence</span>
                  </div>
                  <div className="text-2xl font-bold">{prediction.confidence}%</div>
                </div>
                <div className="p-4 rounded-lg bg-secondary/50 border border-border">
                  <div className="flex items-center gap-2 text-muted-foreground mb-2">
                    <Target className="w-4 h-4" />
                    <span className="text-xs">Impact Score</span>
                  </div>
                  <div className="text-2xl font-bold">{prediction.impactScore}/10</div>
                </div>
                <div className="p-4 rounded-lg bg-secondary/50 border border-border">
                  <div className="flex items-center gap-2 text-muted-foreground mb-2">
                    <Clock className="w-4 h-4" />
                    <span className="text-xs">Timeframe</span>
                  </div>
                  <div className="text-2xl font-bold">{prediction.timeframe}</div>
                </div>
                <div className="p-4 rounded-lg bg-secondary/50 border border-border">
                  <div className="flex items-center gap-2 text-muted-foreground mb-2">
                    <Shield className="w-4 h-4" />
                    <span className="text-xs">Attack Vector</span>
                  </div>
                  <div className="text-sm font-medium leading-tight">{prediction.attackVector}</div>
                </div>
              </div>

              {/* Description */}
              <div className="p-4 rounded-lg bg-secondary/30 border border-border">
                <h4 className="font-semibold mb-2">Description</h4>
                <p className="text-sm text-muted-foreground">{prediction.description}</p>
              </div>

              {/* Affected Systems */}
              <div>
                <h4 className="font-semibold mb-3">Affected Systems</h4>
                <div className="flex flex-wrap gap-2">
                  {prediction.affectedSystems.map((system, idx) => (
                    <span key={idx} className="px-3 py-1.5 text-sm bg-secondary rounded-lg border border-border">
                      {system}
                    </span>
                  ))}
                </div>
              </div>

              {/* Indicators */}
              <div>
                <h4 className="font-semibold mb-3">Threat Indicators</h4>
                <div className="space-y-2">
                  {prediction.indicators.map((indicator, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-sm">
                      <AlertTriangle className="w-4 h-4 text-warning" />
                      {indicator}
                    </div>
                  ))}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="analysis" className="space-y-4 mt-0">
              {/* OSINT Correlations */}
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Globe className="w-5 h-5 text-primary" />
                  <h4 className="font-semibold">OSINT Correlations</h4>
                </div>
                <div className="space-y-3">
                  {prediction.osintCorrelations.map((correlation, idx) => (
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
                          <p className="text-xs text-muted-foreground mt-1">
                            Last seen: {formatDistanceToNow(correlation.lastSeen, { addSuffix: true })}
                          </p>
                        </div>
                        <div className="text-right">
                          <div className="text-xl font-bold text-primary">{correlation.matchScore}%</div>
                          <div className="text-xs text-muted-foreground">Match Score</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="actions" className="space-y-4 mt-0">
              <div className="space-y-3">
                {prediction.recommendedActions.map((action, idx) => (
                  <div 
                    key={idx} 
                    className="flex items-center gap-3 p-4 rounded-lg bg-secondary/30 border border-border"
                  >
                    <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary font-bold">
                      {idx + 1}
                    </div>
                    <span className="flex-1 text-sm">{action}</span>
                    <Button variant="ghost" size="sm">
                      <CheckCircle className="w-4 h-4 mr-1" />
                      Mark Done
                    </Button>
                  </div>
                ))}
              </div>
            </TabsContent>
          </div>
        </Tabs>

        {/* Footer Actions */}
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
