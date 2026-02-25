import { ThreatPrediction } from '@/types/psoc';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { Clock, Target, TrendingUp, AlertTriangle, ChevronRight } from 'lucide-react';

interface PredictionCardProps {
  prediction: ThreatPrediction;
  onViewDetails: (prediction: ThreatPrediction) => void;
  onConvertToIncident: (prediction: ThreatPrediction) => void;
}

export function PredictionCard({
  prediction,
  onViewDetails,
  onConvertToIncident
}: PredictionCardProps) {

  const severityConfig = {
    critical: { badge: 'critical' as const, glow: 'glow-destructive', border: 'border-destructive/30' },
    high: { badge: 'high' as const, glow: 'glow-warning', border: 'border-severity-high/30' },
    medium: { badge: 'medium' as const, glow: '', border: 'border-warning/30' },
    low: { badge: 'low' as const, glow: '', border: 'border-success/30' },
  };

  // 🔐 SAFE NORMALIZATION
  const normalizedSeverity =
    prediction?.severity?.toLowerCase?.() as keyof typeof severityConfig;

  const config =
    severityConfig[normalizedSeverity] ?? severityConfig.low;

  // 🔐 SAFE FALLBACKS
  const timeframeDays =
    prediction?.timeframe?.split?.(' ')?.[0] ?? '0';

  const affectedSystems =
    prediction?.affectedSystems ?? [];

  return (
    <div
      className={cn(
        "p-5 rounded-xl border bg-card/50 backdrop-blur-sm transition-all duration-300 hover:shadow-xl group",
        config.border,
        config.glow && normalizedSeverity === 'critical' && 'animate-pulse-glow'
      )}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            <Badge variant={config.badge} className="uppercase text-xs font-bold">
              {prediction?.severity ?? 'low'}
            </Badge>
            <span className="text-xs text-muted-foreground font-mono">
              {prediction?.id?.toUpperCase?.() ?? 'UNKNOWN'}
            </span>
          </div>
          <h4 className="font-semibold text-base leading-tight group-hover:text-primary transition-colors">
            {prediction?.title ?? 'Untitled Threat'}
          </h4>
        </div>
        <div className="flex flex-col items-end gap-1">
          <div className="text-2xl font-bold text-primary">
            {prediction?.probability ?? 0}%
          </div>
          <span className="text-xs text-muted-foreground">Probability</span>
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-3 gap-3 mb-4">
        <div className="p-3 rounded-lg bg-secondary/50 border border-border">
          <div className="flex items-center gap-1.5 text-muted-foreground mb-1">
            <TrendingUp className="w-3.5 h-3.5" />
            <span className="text-xs">Confidence</span>
          </div>
          <div className="text-lg font-bold">
            {prediction?.confidence ?? 0}%
          </div>
        </div>

        <div className="p-3 rounded-lg bg-secondary/50 border border-border">
          <div className="flex items-center gap-1.5 text-muted-foreground mb-1">
            <Target className="w-3.5 h-3.5" />
            <span className="text-xs">Impact</span>
          </div>
          <div className="text-lg font-bold">
            {prediction?.impactScore ?? 0}/10
          </div>
        </div>

        <div className="p-3 rounded-lg bg-secondary/50 border border-border">
          <div className="flex items-center gap-1.5 text-muted-foreground mb-1">
            <Clock className="w-3.5 h-3.5" />
            <span className="text-xs">Timeframe</span>
          </div>
          <div className="text-lg font-bold">
            {timeframeDays}d
          </div>
        </div>
      </div>

      {/* Affected Systems */}
      <div className="mb-4">
        <p className="text-xs text-muted-foreground mb-2">
          Affected Systems
        </p>
        <div className="flex flex-wrap gap-1.5">
          {affectedSystems.slice(0, 3).map((system, idx) => (
            <span
              key={idx}
              className="px-2 py-1 text-xs bg-secondary rounded-md border border-border"
            >
              {system}
            </span>
          ))}

          {affectedSystems.length > 3 && (
            <span className="px-2 py-1 text-xs bg-secondary rounded-md border border-border text-muted-foreground">
              +{affectedSystems.length - 3} more
            </span>
          )}
        </div>
      </div>

      {/* Actions */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-3 border-t border-border">
        <Button
          variant="glass"
          size="sm"
          className="flex-1 min-w-0"
          onClick={() => onViewDetails(prediction)}
        >
          <span className="truncate">View Details</span>
          <ChevronRight className="w-4 h-4 ml-1 flex-shrink-0" />
        </Button>

        <Button
          variant="cyber"
          size="sm"
          className="flex-1 min-w-0"
          onClick={() => onConvertToIncident(prediction)}
        >
          <AlertTriangle className="w-4 h-4 mr-1 flex-shrink-0" />
          <span className="truncate">Convert to Incident</span>
        </Button>
      </div>
    </div>
  );
}