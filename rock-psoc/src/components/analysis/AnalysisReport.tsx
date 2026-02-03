import { ThreatAnalysis, AnalysisFinding, ThreatPrediction } from '@/types/psoc';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { 
  FileText, 
  AlertTriangle, 
  Shield, 
  CheckCircle, 
  Info,
  ChevronRight,
  Download,
  Clock,
  Loader2
} from 'lucide-react';
import { format } from 'date-fns';
import { usePredictions } from '@/hooks/usePredictions';
import { useState } from 'react';
import { toast } from '@/hooks/use-toast';

interface AnalysisReportProps {
  analysis: ThreatAnalysis;
  onConvertToIncident?: (analysis: ThreatAnalysis) => void;
}

export function AnalysisReport({ analysis, onConvertToIncident }: AnalysisReportProps) {
  const { predictions, convertToIncident } = usePredictions();
  const [isConverting, setIsConverting] = useState(false);
  const severityConfig = {
    critical: { bg: 'bg-destructive/20', border: 'border-destructive/40', text: 'text-destructive' },
    high: { bg: 'bg-severity-high/20', border: 'border-severity-high/40', text: 'text-severity-high' },
    medium: { bg: 'bg-warning/20', border: 'border-warning/40', text: 'text-warning' },
    low: { bg: 'bg-success/20', border: 'border-success/40', text: 'text-success' },
  };

  const findingTypeConfig = {
    threat: { icon: AlertTriangle, color: 'text-destructive' },
    vulnerability: { icon: Shield, color: 'text-severity-high' },
    suspicious: { icon: Info, color: 'text-warning' },
    info: { icon: CheckCircle, color: 'text-muted-foreground' },
  };

  const config = severityConfig[analysis.overallSeverity];
  const threatCount = analysis.findings.filter(f => f.type === 'threat').length;
  const vulnCount = analysis.findings.filter(f => f.type === 'vulnerability').length;

  return (
    <div className={cn(
      "rounded-xl border overflow-hidden",
      config.border, config.bg
    )}>
      {/* Header */}
      <div className="p-4 border-b border-border bg-card/50">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className={cn(
              "w-10 h-10 rounded-lg flex items-center justify-center",
              config.bg
            )}>
              <FileText className={cn("w-5 h-5", config.text)} />
            </div>
            <div>
              <h3 className="font-semibold">{analysis.fileName}</h3>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Clock className="w-3 h-3" />
                <span>Analyzed {format(analysis.uploadedAt, 'MMM d, yyyy HH:mm')}</span>
              </div>
            </div>
          </div>
          <Badge variant={analysis.overallSeverity}>
            {analysis.overallSeverity.toUpperCase()} RISK
          </Badge>
        </div>
      </div>

      {/* Summary */}
      <div className="p-4 border-b border-border">
        <h4 className="text-sm font-medium mb-2">Executive Summary</h4>
        <p className="text-sm text-muted-foreground">{analysis.summary}</p>
        
        <div className="flex gap-4 mt-3">
          <div className="flex items-center gap-2 text-sm">
            <AlertTriangle className="w-4 h-4 text-destructive" />
            <span>{threatCount} Threats</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <Shield className="w-4 h-4 text-severity-high" />
            <span>{vulnCount} Vulnerabilities</span>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <Info className="w-4 h-4 text-muted-foreground" />
            <span>{analysis.findings.length} Total Findings</span>
          </div>
        </div>
      </div>

      {/* Findings */}
      <div className="p-4 border-b border-border">
        <h4 className="text-sm font-medium mb-3">Detailed Findings</h4>
        <div className="space-y-2">
          {analysis.findings.map((finding) => {
            const typeConfig = findingTypeConfig[finding.type];
            const Icon = typeConfig.icon;
            
            return (
              <div 
                key={finding.id}
                className="p-3 rounded-lg bg-secondary/30 border border-border"
              >
                <div className="flex items-start gap-3">
                  <Icon className={cn("w-4 h-4 mt-0.5", typeConfig.color)} />
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-sm">{finding.title}</span>
                      <Badge variant={finding.severity} className="text-xs">
                        {finding.severity}
                      </Badge>
                      <span className="text-xs text-muted-foreground ml-auto">
                        {finding.confidence}% confidence
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">{finding.description}</p>
                    {finding.location && (
                      <p className="text-xs text-primary mt-1">📍 {finding.location}</p>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recommendations */}
      <div className="p-4 border-b border-border">
        <h4 className="text-sm font-medium mb-3">AI Recommendations</h4>
        <ul className="space-y-2">
          {analysis.recommendations.map((rec, i) => (
            <li key={i} className="flex items-start gap-2 text-sm">
              <ChevronRight className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
              <span className="text-muted-foreground">{rec}</span>
            </li>
          ))}
        </ul>
      </div>

      {/* Actions */}
      <div className="p-4 flex gap-3">
        <Button 
          variant="cyber" 
          className="flex-1"
          disabled={isConverting}
          onClick={async () => {
            setIsConverting(true);
            try {
              // Find the corresponding prediction saved for this analysis
              const matchingPrediction = predictions.find(
                p => p.title === `File Analysis: ${analysis.fileName}`
              );
              
              if (matchingPrediction) {
                await convertToIncident.mutateAsync(matchingPrediction);
              } else {
                toast({
                  title: 'Prediction Not Found',
                  description: 'Could not find the saved prediction for this analysis. It may have already been converted.',
                  variant: 'destructive',
                });
              }
              onConvertToIncident?.(analysis);
            } finally {
              setIsConverting(false);
            }
          }}
        >
          {isConverting ? (
            <>
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              Converting...
            </>
          ) : (
            'Convert to Incident'
          )}
        </Button>
        <Button variant="glass">
          <Download className="w-4 h-4 mr-2" />
          Export Report
        </Button>
      </div>
    </div>
  );
}
